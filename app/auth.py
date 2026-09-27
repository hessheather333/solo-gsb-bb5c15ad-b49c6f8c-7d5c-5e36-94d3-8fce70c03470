"""管理写接口的 HMAC-SHA256 防重放认证。

仅保护管理类写接口：
  PUT    /policies
  POST   /policies/rollback
  POST   /policy-changes
  DELETE /policy-changes/{change_id}

所有 GET、裁决（POST /decide、POST /decide-batches）与撤销（.../revoke）不经过本模块，保持匿名可用。

客户端必须携带四个请求头：X-Key-Id、X-Timestamp（Unix 秒）、X-Nonce、
X-Signature。签名原文为（恰好 4 个 ``\\n`` 分隔的 5 段）：

    <方法>\\n<原始路径及查询串>\\n<请求体 SHA-256 小写十六进制>\\n<时间戳>\\n<nonce>

签名值 = HMAC-SHA256(secret, 签名原文) 的小写十六进制；无请求体（如 DELETE）
时请求体 SHA-256 取空串的摘要。

约定：
- 时间戳偏离服务器当前时间超过 TIMESTAMP_WINDOW_SEC（300 秒）-> 401；
- key id 不匹配 / 缺头 / 签名无效 -> 401（key id 与签名均常量时间比较）；
- nonce 与 key id 联合唯一，在 NONCE_TTL_SEC（300 秒）内同一 key 重用 -> 409；
- nonce 登记（reserve_nonce）必须与业务写入处在同一个 BEGIN IMMEDIATE
  事务中：业务抛错回滚时 nonce 一并回滚，不会被占用。
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import sqlite3
import time
from dataclasses import dataclass

from fastapi import HTTPException, Request

from .quota import iso, now_utc

# 时间戳允许偏离服务器时钟的秒数；同时也是 nonce 的保留时长
TIMESTAMP_WINDOW_SEC = 300
NONCE_TTL_SEC = 300

# 头长度上限，仅用于拒绝明显的滥用输入
MAX_KEY_ID_LEN = 128
MAX_NONCE_LEN = 256

_TS_RE = re.compile(r"\d{1,11}")
_SIGNATURE_RE = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class AdminPrincipal:
    """认证通过后的调用方身份（key_id 与其本次 nonce）。"""

    key_id: str
    nonce: str


def admin_config() -> tuple[str, str]:
    """读取服务端管理凭据；未配置时管理接口以 503 显式失败（fail-closed）。"""
    key_id = os.environ.get("ADMIN_KEY_ID", "")
    secret = os.environ.get("ADMIN_HMAC_SECRET", "")
    if not key_id or not secret:
        raise HTTPException(
            503,
            "管理写接口未就绪：服务端缺少 ADMIN_KEY_ID / ADMIN_HMAC_SECRET 配置",
        )
    return key_id, secret


async def require_admin(request: Request) -> AdminPrincipal:
    """FastAPI 依赖：校验管理写请求的时间戳与 HMAC-SHA256 签名。

    校验顺序：头完整性 -> 时间戳格式与时间窗 -> key id -> 签名。
    任何不满足都返回 401；凭据未配置返回 503。
    """
    key_id = request.headers.get("x-key-id", "")
    ts_raw = request.headers.get("x-timestamp", "")
    nonce = request.headers.get("x-nonce", "")
    signature = request.headers.get("x-signature", "")

    configured_key_id, secret = admin_config()

    # 1) 头必须齐全；长度封顶，拒绝异常输入
    if (
        not key_id
        or not ts_raw
        or not nonce
        or not signature
        or len(key_id) > MAX_KEY_ID_LEN
        or len(nonce) > MAX_NONCE_LEN
    ):
        raise HTTPException(401, "缺少 X-Key-Id/X-Timestamp/X-Nonce/X-Signature 签名头")

    # 2) 时间戳必须是 Unix 秒整数，且落在 ±300 秒窗口内
    if not _TS_RE.fullmatch(ts_raw):
        raise HTTPException(401, "X-Timestamp 必须是 Unix 秒整数")
    if abs(time.time() - int(ts_raw)) > TIMESTAMP_WINDOW_SEC:
        raise HTTPException(401, "请求时间戳偏离服务器时间超过 300 秒")

    # 3) key id 必须与服务端配置一致（字节级常量时间比较，兼容非 ASCII 头值）
    if not hmac.compare_digest(
        key_id.encode("utf-8"), configured_key_id.encode("utf-8")
    ):
        raise HTTPException(401, "X-Key-Id 与服务端配置不符")

    # 签名值规格：恰好 64 位小写十六进制（大写或非法字符直接判无效，
    # 同时避免 compare_digest 对非 ASCII str 抛 TypeError）
    if not _SIGNATURE_RE.fullmatch(signature):
        raise HTTPException(401, "X-Signature 必须是 64 位小写十六进制 HMAC-SHA256")

    # 4) 重算签名：方法\n原始路径及查询串\n请求体 SHA-256 小写hex\n时间戳\nnonce
    body = await request.body()
    body_hash = hashlib.sha256(body).hexdigest()

    # ASGI raw_path/query_string 是未解码的原始字节；缺失时回退到 URL 解析值
    raw_path = request.scope.get("raw_path")
    if isinstance(raw_path, str):
        raw_path = raw_path.encode("latin-1")
    if not raw_path:
        raw_path = request.url.path.encode("latin-1")
    query_string = request.scope.get("query_string", b"")
    if isinstance(query_string, str):
        query_string = query_string.encode("latin-1")
    target = raw_path + (b"?" + query_string if query_string else b"")

    signing_bytes = b"\n".join(
        [
            request.method.encode("ascii"),
            target,
            body_hash.encode("ascii"),
            ts_raw.encode("ascii"),
            nonce.encode("utf-8"),
        ]
    )
    expected = hmac.new(
        secret.encode("utf-8"), signing_bytes, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(401, "签名无效（方法/路径/请求体摘要/时间戳/nonce 任一不符）")

    return AdminPrincipal(key_id=key_id, nonce=nonce)


def reserve_nonce(
    conn: sqlite3.Connection,
    key_id: str,
    nonce: str,
    *,
    now: float | None = None,
    ttl: int = NONCE_TTL_SEC,
) -> None:
    """在当前写事务内登记本次请求的 nonce。

    必须在业务写入之前、且与业务写入处于同一个 BEGIN IMMEDIATE 事务中调用：
    随后业务失败（4xx 等）触发事务回滚，nonce 行随之撤销，不会误占；
    只有随业务一起 COMMIT 成功的 nonce 才在 ``ttl`` 秒内对同一 key 防重放。

    先清理全表已过期记录（保留窗口 300 秒），再查重（同 key 重用 -> 409），
    最后插入；插入遇唯一约束冲突（并发抢占）同样返回 409。
    """
    now_ts = int(time.time() if now is None else now)

    # 过期 nonce 物理删除：保留时长即时间窗 300 秒
    conn.execute("DELETE FROM admin_nonces WHERE expires_at <= ?", (now_ts,))

    duplicate = conn.execute(
        "SELECT 1 FROM admin_nonces WHERE key_id=? AND nonce=?",
        (key_id, nonce),
    ).fetchone()
    if duplicate is not None:
        raise HTTPException(
            409, f"同一 X-Key-Id 在 {NONCE_TTL_SEC} 秒内重用 nonce，拒绝重放"
        )

    try:
        conn.execute(
            """
            INSERT INTO admin_nonces (key_id, nonce, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (key_id, nonce, iso(now_utc()), now_ts + ttl),
        )
    except sqlite3.IntegrityError:
        # BEGIN IMMEDIATE 已串行化写事务，这里仅作并发兜底
        raise HTTPException(409, "nonce 已被使用，拒绝重放")
