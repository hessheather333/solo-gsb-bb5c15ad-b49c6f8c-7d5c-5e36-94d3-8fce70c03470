"""配额裁决核心逻辑：多级令牌桶、幂等存档与撤销。

所有公共写操作都必须在 database.write_tx（BEGIN IMMEDIATE）事务中调用，
保证「补充 -> 判足 -> 扣减」这一读-改-写序列的原子性与隔离性。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import HTTPException

# 各策略层的空标识统一用空串存储（SQLite STRICT 主键列不允许 NULL 参与唯一比较）
EMPTY = ""


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    """统一的 ISO 8601 UTC 文本，例如 2026-09-17T12:00:00.123456Z。"""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso(text: str) -> datetime:
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def payload_hash(payload: dict[str, Any]) -> str:
    """对除 request_id 外的裁决载荷做规范序列化后取 SHA-256。"""
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- 策略管理


def _normalize_scope(
    scope: str,
    tenant_id: Optional[str],
    route_id: Optional[str],
) -> tuple[str, str]:
    """把 (scope, tenant_id, route_id) 规范化成存储用的 (tenant, route)。

    非法组合直接抛 422；各层空标识统一用空串。
    """
    tenant = tenant_id or EMPTY
    route = route_id or EMPTY
    if scope == "global":
        return EMPTY, EMPTY
    if scope == "tenant":
        if not tenant:
            raise HTTPException(422, "tenant 作用域必须提供 tenant_id")
        return tenant, EMPTY
    if scope == "route":
        if not tenant or not route:
            raise HTTPException(422, "route 作用域必须同时提供 tenant_id 与 route_id")
        return tenant, route
    raise HTTPException(422, f"非法 scope: {scope!r}")


def _validate_policy_values(
    capacity: float,
    refill_rate: float,
    low_balance_threshold: Optional[float],
) -> None:
    if capacity < 0 or refill_rate < 0:
        raise HTTPException(422, "capacity 与 refill_rate 必须非负")
    if low_balance_threshold is not None and not (
        0.0 <= low_balance_threshold <= capacity
    ):
        raise HTTPException(
            422, "low_balance_threshold 必须为 null（关闭）或在 0 到 capacity 之间"
        )


def list_policies(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT scope, tenant_id, route_id, capacity, refill_rate, "
        "low_balance_threshold, updated_at "
        "FROM policies ORDER BY scope, tenant_id, route_id"
    ).fetchall()
    return [_policy_out(r) for r in rows]


def _pending_change(
    conn: sqlite3.Connection, scope: str, tenant: str, route: str
) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT change_id, effective_at FROM policy_changes "
        "WHERE scope=? AND tenant_id=? AND route_id=? AND status='pending'",
        (scope, tenant, route),
    ).fetchone()


def upsert_policy(
    conn: sqlite3.Connection,
    *,
    scope: str,
    tenant_id: Optional[str],
    route_id: Optional[str],
    capacity: float,
    refill_rate: float,
    low_balance_threshold: Optional[float] = None,
) -> dict[str, Any]:
    """创建或更新一层策略。

    更新容量时，已存在的桶先按旧策略补充到当前时刻，再截断到新容量，
    保证余额永远不超过当前容量。
    low_balance_threshold 为 None 时关闭该层的低余额事件；否则须在
    [0, capacity] 内。PUT 为全量替换：不传即视为关闭。

    该策略存在待生效（pending）的定时变更时拒绝直接更新，返回 409：
    两条更新路径并发交错会破坏变更应用时的「旧策略 -> 新策略」余额换算，
    请先取消变更或等其生效后再更新。
    """
    tenant, route = _normalize_scope(scope, tenant_id, route_id)
    _validate_policy_values(capacity, refill_rate, low_balance_threshold)

    pending = _pending_change(conn, scope, tenant, route)
    if pending is not None:
        raise HTTPException(
            409,
            f"该策略存在待生效的定时变更 change_id={pending['change_id']!r}"
            f"（effective_at={pending['effective_at']}），请先取消或等其生效后再更新",
        )

    ts = now_utc()
    # 所有余额写操作先在同一事务内把到期 pending 预占转为 expired 并返还原桶，
    # 返还的令牌随后与桶上已有余额一起按新容量截断
    _expire_due_reservations(conn, ts)

    old = conn.execute(
        "SELECT capacity, refill_rate FROM policies "
        "WHERE scope=? AND tenant_id=? AND route_id=?",
        (scope, tenant, route),
    ).fetchone()

    bucket = conn.execute(
        "SELECT balance, updated_at FROM buckets "
        "WHERE scope=? AND tenant_id=? AND route_id=?",
        (scope, tenant, route),
    ).fetchone()
    if bucket is not None:
        # 用旧策略（若存在）先把应补充的令牌补上，再按新容量截断
        cap_old = old["capacity"] if old else capacity
        rate_old = old["refill_rate"] if old else refill_rate
        balance = _refill(bucket["balance"], bucket["updated_at"], cap_old, rate_old, ts)
        balance = min(balance, capacity)
        conn.execute(
            "UPDATE buckets SET balance=?, updated_at=? "
            "WHERE scope=? AND tenant_id=? AND route_id=?",
            (balance, iso(ts), scope, tenant, route),
        )

    conn.execute(
        """
        INSERT INTO policies
            (scope, tenant_id, route_id, capacity, refill_rate,
             low_balance_threshold, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (scope, tenant_id, route_id) DO UPDATE SET
            capacity=excluded.capacity,
            refill_rate=excluded.refill_rate,
            low_balance_threshold=excluded.low_balance_threshold,
            updated_at=excluded.updated_at
        """,
        (
            scope, tenant, route, float(capacity), float(refill_rate),
            None if low_balance_threshold is None else float(low_balance_threshold),
            iso(ts),
        ),
    )
    # 每次 PUT 成功都在同一事务追加一条不可变版本（source=put）
    _append_policy_version(
        conn,
        scope=scope, tenant=tenant, route=route,
        capacity=capacity, refill_rate=refill_rate,
        low_balance_threshold=low_balance_threshold,
        source="put", created_at=iso(ts),
    )
    row = conn.execute(
        "SELECT scope, tenant_id, route_id, capacity, refill_rate, "
        "low_balance_threshold, updated_at "
        "FROM policies WHERE scope=? AND tenant_id=? AND route_id=?",
        (scope, tenant, route),
    ).fetchone()
    return _policy_out(row)


# ------------------------------------------------------------ 策略版本审计


_VERSION_COLS = (
    "version, scope, tenant_id, route_id, capacity, refill_rate, "
    "low_balance_threshold, source, change_id, restored_from_version, created_at"
)


def _version_out(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "version": row["version"],
        "scope": row["scope"],
        "tenant_id": row["tenant_id"] or None,
        "route_id": row["route_id"] or None,
        "capacity": row["capacity"],
        "refill_rate": row["refill_rate"],
        "low_balance_threshold": row["low_balance_threshold"],
        "source": row["source"],
        "change_id": row["change_id"],
        "restored_from_version": row["restored_from_version"],
        "created_at": row["created_at"],
    }


def _next_version(
    conn: sqlite3.Connection, scope: str, tenant: str, route: str
) -> int:
    """在写事务内分配该策略的下一个版本号（max(version)+1，首个为 1）。

    所有调用方都在 BEGIN IMMEDIATE 事务内，写锁已排他持有，
    max 读与随后的插入之间不会有其他写者插入。
    """
    row = conn.execute(
        "SELECT COALESCE(MAX(version), 0) AS v FROM policy_versions "
        "WHERE scope=? AND tenant_id=? AND route_id=?",
        (scope, tenant, route),
    ).fetchone()
    return int(row["v"]) + 1


def _append_policy_version(
    conn: sqlite3.Connection,
    *,
    scope: str,
    tenant: str,
    route: str,
    capacity: float,
    refill_rate: float,
    low_balance_threshold: Optional[float],
    source: str,
    created_at: str,
    change_id: Optional[str] = None,
    restored_from_version: Optional[int] = None,
) -> dict[str, Any]:
    """在当前写事务内追加一条不可变版本记录并返回它。

    与触发变更（PUT 成功 / 定时切换生效 / 回滚成功）在同一事务内提交，
    保证「策略参数已变」与「版本已落账」要么同时可见要么都不可见。
    """
    version = _next_version(conn, scope, tenant, route)
    conn.execute(
        """
        INSERT INTO policy_versions
            (scope, tenant_id, route_id, version, capacity, refill_rate,
             low_balance_threshold, source, change_id, restored_from_version,
             created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scope, tenant, route, version, float(capacity), float(refill_rate),
            None if low_balance_threshold is None else float(low_balance_threshold),
            source, change_id, restored_from_version, created_at,
        ),
    )
    row = conn.execute(
        f"SELECT {_VERSION_COLS} FROM policy_versions "
        "WHERE scope=? AND tenant_id=? AND route_id=? AND version=?",
        (scope, tenant, route, version),
    ).fetchone()
    return _version_out(row)


def list_policy_versions(
    conn: sqlite3.Connection,
    *,
    scope: str,
    tenant_id: Optional[str] = None,
    route_id: Optional[str] = None,
) -> list[dict[str, Any]]:
    """按策略键返回版本历史，新版本在前（version 降序）。只读。"""
    tenant, route = _normalize_scope(scope, tenant_id, route_id)
    rows = conn.execute(
        f"SELECT {_VERSION_COLS} FROM policy_versions "
        "WHERE scope=? AND tenant_id=? AND route_id=? "
        "ORDER BY version DESC, id DESC",
        (scope, tenant, route),
    ).fetchall()
    return [_version_out(r) for r in rows]


def rollback_policy(
    conn: sqlite3.Connection,
    *,
    scope: str,
    tenant_id: Optional[str],
    route_id: Optional[str],
    version: int,
) -> dict[str, Any]:
    """在同一写事务内把策略恢复到指定历史版本，并追加一条 source=rollback 版本。

    约束：目标策略不存在 -> 404；目标版本不属于该策略 -> 404；
    该策略存在 pending 定时变更 -> 409（避免与到期应用交错）。
    桶按 PUT 相同规则处理：先按当前策略补充到事务时刻，再按目标容量截断。
    """
    tenant, route = _normalize_scope(scope, tenant_id, route_id)

    pending = _pending_change(conn, scope, tenant, route)
    if pending is not None:
        raise HTTPException(
            409,
            f"该策略存在待生效的定时变更 change_id={pending['change_id']!r}"
            f"（effective_at={pending['effective_at']}），请先取消或等其生效后再回滚",
        )

    current = conn.execute(
        "SELECT capacity, refill_rate, low_balance_threshold FROM policies "
        "WHERE scope=? AND tenant_id=? AND route_id=?",
        (scope, tenant, route),
    ).fetchone()
    if current is None:
        raise HTTPException(404, "目标策略不存在，请先用 PUT /policies 创建")

    target = conn.execute(
        f"SELECT {_VERSION_COLS} FROM policy_versions "
        "WHERE scope=? AND tenant_id=? AND route_id=? AND version=?",
        (scope, tenant, route, version),
    ).fetchone()
    if target is None:
        raise HTTPException(
            404, f"版本 version={version} 不属于该策略，无法回滚"
        )

    cap = float(target["capacity"])
    rate = float(target["refill_rate"])
    threshold = target["low_balance_threshold"]

    ts = now_utc()
    # 余额写操作：先在同一事务内把到期 pending 预占转为 expired 并返还，
    # 随后桶按当前策略补充时即可计入返还的令牌，再按目标容量截断
    _expire_due_reservations(conn, ts)
    # 已有桶：先按当前策略补充到事务时刻，再截断到目标版本容量
    bucket = conn.execute(
        "SELECT balance, updated_at FROM buckets "
        "WHERE scope=? AND tenant_id=? AND route_id=?",
        (scope, tenant, route),
    ).fetchone()
    if bucket is not None:
        balance = _refill(
            bucket["balance"], bucket["updated_at"],
            current["capacity"], current["refill_rate"], ts,
        )
        balance = min(balance, cap)
        conn.execute(
            "UPDATE buckets SET balance=?, updated_at=? "
            "WHERE scope=? AND tenant_id=? AND route_id=?",
            (balance, iso(ts), scope, tenant, route),
        )

    conn.execute(
        """
        UPDATE policies
        SET capacity=?, refill_rate=?, low_balance_threshold=?, updated_at=?
        WHERE scope=? AND tenant_id=? AND route_id=?
        """,
        (cap, rate, threshold, iso(ts), scope, tenant, route),
    )
    return _append_policy_version(
        conn,
        scope=scope, tenant=tenant, route=route,
        capacity=cap, refill_rate=rate, low_balance_threshold=threshold,
        source="rollback", created_at=iso(ts),
        restored_from_version=version,
    )


def _policy_out(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "scope": row["scope"],
        "tenant_id": row["tenant_id"] or None,
        "route_id": row["route_id"] or None,
        "capacity": row["capacity"],
        "refill_rate": row["refill_rate"],
        "low_balance_threshold": row["low_balance_threshold"],
        "updated_at": row["updated_at"],
    }


# ------------------------------------------------------------ 策略定时切换


def _change_out(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "change_id": row["change_id"],
        "scope": row["scope"],
        "tenant_id": row["tenant_id"] or None,
        "route_id": row["route_id"] or None,
        "capacity": row["new_capacity"],
        "refill_rate": row["new_refill_rate"],
        "low_balance_threshold": row["new_low_balance_threshold"],
        "effective_at": row["effective_at"],
        "status": row["status"],
        "created_at": row["created_at"],
        "applied_at": row["applied_at"],
        "cancelled_at": row["cancelled_at"],
    }


_CHANGE_COLS = (
    "change_id, scope, tenant_id, route_id, new_capacity, new_refill_rate, "
    "new_low_balance_threshold, effective_at, status, created_at, "
    "applied_at, cancelled_at"
)


def create_policy_change(
    conn: sqlite3.Connection,
    *,
    change_id: str,
    scope: str,
    tenant_id: Optional[str],
    route_id: Optional[str],
    capacity: float,
    refill_rate: float,
    low_balance_threshold: Optional[float],
    effective_at: datetime,
) -> dict[str, Any]:
    """为已存在的策略登记一条未来生效的容量/速率/阈值变更。

    约束：目标策略必须已存在（404）；effective_at 必须是未来 UTC 时刻（422）；
    同一策略至多一条 pending 变更（409）；change_id 全局唯一（409）。
    """
    tenant, route = _normalize_scope(scope, tenant_id, route_id)
    _validate_policy_values(capacity, refill_rate, low_balance_threshold)
    if effective_at.tzinfo is None:
        raise HTTPException(422, "effective_at 必须显式带时区（UTC）")
    effective_at = effective_at.astimezone(timezone.utc)

    ts = now_utc()
    if not effective_at > ts:
        raise HTTPException(422, "effective_at 必须是晚于当前时间的未来 UTC 时刻")

    policy = conn.execute(
        "SELECT 1 FROM policies WHERE scope=? AND tenant_id=? AND route_id=?",
        (scope, tenant, route),
    ).fetchone()
    if policy is None:
        raise HTTPException(404, "目标策略不存在，请先用 PUT /policies 创建")

    dup = conn.execute(
        f"SELECT {_CHANGE_COLS} FROM policy_changes WHERE change_id=?",
        (change_id,),
    ).fetchone()
    if dup is not None:
        raise HTTPException(409, f"change_id={change_id!r} 已存在")
    if _pending_change(conn, scope, tenant, route) is not None:
        raise HTTPException(409, "同一策略已存在待生效变更，取消或等其生效后才能提交新的")

    conn.execute(
        """
        INSERT INTO policy_changes
            (change_id, scope, tenant_id, route_id, new_capacity, new_refill_rate,
             new_low_balance_threshold, effective_at, status, created_at,
             applied_at, cancelled_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, NULL, NULL)
        """,
        (
            change_id, scope, tenant, route, float(capacity), float(refill_rate),
            None if low_balance_threshold is None else float(low_balance_threshold),
            iso(effective_at), iso(ts),
        ),
    )
    row = conn.execute(
        f"SELECT {_CHANGE_COLS} FROM policy_changes WHERE change_id=?",
        (change_id,),
    ).fetchone()
    return _change_out(row)


def list_policy_changes(
    conn: sqlite3.Connection,
    *,
    status: Optional[str] = None,
    scope: Optional[str] = None,
    tenant_id: Optional[str] = None,
    route_id: Optional[str] = None,
) -> list[dict[str, Any]]:
    """列出定时变更，可按 status 与策略键过滤；按提交顺序稳定返回。"""
    sql = f"SELECT {_CHANGE_COLS} FROM policy_changes"
    where: list[str] = []
    params: list[Any] = []
    if status is not None:
        where.append("status=?")
        params.append(status)
    if scope is not None:
        where.append("scope=?")
        params.append(scope)
    if tenant_id is not None:
        where.append("tenant_id=?")
        params.append(tenant_id or EMPTY)
    if route_id is not None:
        where.append("route_id=?")
        params.append(route_id or EMPTY)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id"
    return [_change_out(r) for r in conn.execute(sql, params).fetchall()]


def get_policy_change(conn: sqlite3.Connection, change_id: str) -> dict[str, Any]:
    row = conn.execute(
        f"SELECT {_CHANGE_COLS} FROM policy_changes WHERE change_id=?",
        (change_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(404, f"change_id={change_id!r} 不存在")
    return _change_out(row)


def cancel_policy_change(conn: sqlite3.Connection, change_id: str) -> dict[str, Any]:
    """取消一条尚未生效的 pending 变更（重复取消幂等）。

    不存在 -> 404；已生效或已到生效时刻 -> 409；
    已取消 -> 原样返回该 cancelled 记录。
    """
    row = conn.execute(
        f"SELECT {_CHANGE_COLS} FROM policy_changes WHERE change_id=?",
        (change_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(404, f"change_id={change_id!r} 不存在")
    if row["status"] == "applied":
        raise HTTPException(
            409, f"change_id={change_id!r} 已生效，无法取消"
        )
    if row["status"] == "cancelled":
        return _change_out(row)

    ts = now_utc()
    # 双保险：effective_at 已到期的变更可能正被/已被裁决事务应用，
    # 只取消仍为 pending 且生效时刻仍在未来的行
    cur = conn.execute(
        "UPDATE policy_changes SET status='cancelled', cancelled_at=? "
        "WHERE change_id=? AND status='pending' AND effective_at > ?",
        (iso(ts), change_id, iso(ts)),
    )
    if cur.rowcount == 0:
        raise HTTPException(409, f"change_id={change_id!r} 已到生效时刻，无法取消")
    row = conn.execute(
        f"SELECT {_CHANGE_COLS} FROM policy_changes WHERE change_id=?",
        (change_id,),
    ).fetchone()
    return _change_out(row)


# ---------------------------------------------------------------- 令牌桶


def _refill(
    balance: float,
    updated_at: str,
    capacity: float,
    refill_rate: float,
    now: datetime,
) -> float:
    elapsed = max(0.0, (now - parse_iso(updated_at)).total_seconds())
    return min(float(capacity), float(balance) + elapsed * float(refill_rate))


def _bucket_out(
    scope: str,
    tenant: str,
    route: str,
    capacity: float,
    refill_rate: float,
    balance: float,
) -> dict[str, Any]:
    return {
        "scope": scope,
        "tenant_id": tenant or None,
        "route_id": route or None,
        "capacity": float(capacity),
        "refill_rate": float(refill_rate),
        "balance": float(balance),
    }


def list_buckets(conn: sqlite3.Connection, *, live: bool = True) -> list[dict[str, Any]]:
    """列出所有已创建的桶；live=True 时展示补充到当前时刻的余额（不落库）。"""
    rows = conn.execute(
        """
        SELECT b.scope, b.tenant_id, b.route_id, b.balance, b.updated_at,
               p.capacity, p.refill_rate
        FROM buckets b JOIN policies p
          ON p.scope=b.scope AND p.tenant_id=b.tenant_id AND p.route_id=b.route_id
        ORDER BY b.scope, b.tenant_id, b.route_id
        """
    ).fetchall()
    now = now_utc()
    out: list[dict[str, Any]] = []
    for r in rows:
        balance = (
            _refill(r["balance"], r["updated_at"], r["capacity"], r["refill_rate"], now)
            if live
            else r["balance"]
        )
        out.append(
            _bucket_out(
                r["scope"], r["tenant_id"], r["route_id"],
                r["capacity"], r["refill_rate"], balance,
            )
        )
    return out


# ---------------------------------------------------------------- 裁决


def _hit_keys(
    tenant_id: Optional[str], route_id: Optional[str]
) -> list[tuple[str, str, str]]:
    """一次裁决按 全局 -> 租户 -> 路由 顺序命中的策略键。"""
    keys: list[tuple[str, str, str]] = [("global", EMPTY, EMPTY)]
    if tenant_id:
        keys.append(("tenant", tenant_id, EMPTY))
        if route_id:
            keys.append(("route", tenant_id, route_id))
    return keys


def _apply_due_changes(
    conn: sqlite3.Connection,
    keys: list[tuple[str, str, str]],
    now: datetime,
) -> None:
    """在裁决事务内、裁决之前，应用所有命中且已到期（effective_at <= now）的变更。

    逐条串行应用：每条都在同一事务内完成「余额换算 -> 覆盖策略 -> 标记 applied」，
    因此并发请求只能观察到完整的旧状态或完整的新状态，不会看到半成品。
    """
    now_iso = iso(now)
    for scope, tenant, route in keys:
        rows = conn.execute(
            """
            SELECT change_id, scope, tenant_id, route_id, new_capacity,
                   new_refill_rate, new_low_balance_threshold, effective_at
            FROM policy_changes
            WHERE scope=? AND tenant_id=? AND route_id=?
              AND status='pending' AND effective_at <= ?
            ORDER BY effective_at, id
            """,
            (scope, tenant, route, now_iso),
        ).fetchall()
        for ch in rows:
            _apply_policy_change(conn, ch, now)


def _apply_policy_change(
    conn: sqlite3.Connection, ch: sqlite3.Row, now: datetime
) -> None:
    """应用单条变更：旧策略补充到 effective_at -> 按比例缩放余额 ->
    覆盖为新策略 -> 按新速率从 effective_at 补充至 now（由随后的裁决补充完成）。

    余额换算（余额为「剩余比例」语义）：
      1. 先按旧容量/旧速率把余额补充到 effective_at（上限旧容量）；
      2. 旧容量为 0 时余额直接置 0，否则
         balance = 旧余额 / 旧容量 × 新容量（不超过新容量）；
      3. 桶的 updated_at 置为 effective_at，之后统一按新速率继续补充。
    """
    scope, tenant, route = ch["scope"], ch["tenant_id"], ch["route_id"]
    effective_at = parse_iso(ch["effective_at"])
    eff_iso = ch["effective_at"]
    new_cap = float(ch["new_capacity"])
    new_rate = float(ch["new_refill_rate"])
    new_threshold = ch["new_low_balance_threshold"]

    old = conn.execute(
        "SELECT capacity, refill_rate FROM policies "
        "WHERE scope=? AND tenant_id=? AND route_id=?",
        (scope, tenant, route),
    ).fetchone()
    if old is None:
        # 策略行已不存在（当前版本不支持删除，仅作防御）：放弃本条
        return
    old_cap, old_rate = float(old["capacity"]), float(old["refill_rate"])

    bucket = conn.execute(
        "SELECT balance, updated_at FROM buckets "
        "WHERE scope=? AND tenant_id=? AND route_id=?",
        (scope, tenant, route),
    ).fetchone()
    if bucket is None:
        # 桶尚未惰性创建：没有需要换算的余额，新策略生效后按新容量满额创建
        pass
    else:
        # 1) 旧策略补充到生效时刻
        at_eff = _refill(
            bucket["balance"], bucket["updated_at"], old_cap, old_rate, effective_at
        )
        # 2) 按剩余比例缩放到新容量（旧容量为 0 -> 余额 0）
        if old_cap <= 0.0:
            balance = 0.0
        else:
            balance = min(new_cap, at_eff / old_cap * new_cap)
        # 3) 时间锚点移到 effective_at，后续补充统一走新速率
        conn.execute(
            "UPDATE buckets SET balance=?, updated_at=? "
            "WHERE scope=? AND tenant_id=? AND route_id=?",
            (balance, eff_iso, scope, tenant, route),
        )

    conn.execute(
        """
        UPDATE policies
        SET capacity=?, refill_rate=?, low_balance_threshold=?, updated_at=?
        WHERE scope=? AND tenant_id=? AND route_id=?
        """,
        (
            new_cap, new_rate, new_threshold, eff_iso,
            scope, tenant, route,
        ),
    )
    cur = conn.execute(
        "UPDATE policy_changes SET status='applied', applied_at=? "
        "WHERE change_id=? AND status='pending'",
        (iso(now), ch["change_id"]),
    )
    if cur.rowcount > 0:
        # 定时切换实际生效（由本次裁决/撤销事务抢到 pending -> applied）时，
        # 在同一事务追加不可变版本（source=scheduled）
        _append_policy_version(
            conn,
            scope=scope, tenant=tenant, route=route,
            capacity=new_cap, refill_rate=new_rate,
            low_balance_threshold=new_threshold,
            source="scheduled", created_at=iso(now),
            change_id=ch["change_id"],
        )


def _maybe_emit_low_balance(
    conn: sqlite3.Connection,
    state: dict[str, Any],
    *,
    before: float,
    after: float,
    request_id: str,
    now: datetime,
) -> None:
    """获准扣减令桶「从阈值之上降至不高于阈值」时，在扣减事务内写入唯一事件。

    阈值关闭（None）或本次未越线时不写。余额已在阈值之下的继续扣减不算
    越线；只有当补充/撤销/策略更新把余额重新抬到阈值之上后，再次越线才
    会产生新事件。
    """
    threshold = state["low_balance_threshold"]
    if threshold is None:
        return
    # after 是浮点减法结果，给「不高于阈值」一点容差，避免恰好等于阈值时漏报
    if before > threshold and after <= threshold + 1e-12:
        conn.execute(
            """
            INSERT INTO low_balance_events
                (scope, tenant_id, route_id, balance_before, balance_after,
                 threshold, request_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                state["scope"], state["tenant"], state["route"],
                float(before), float(after), float(threshold),
                request_id, iso(now),
            ),
        )


def _pending_change_map(
    conn: sqlite3.Connection, keys: list[tuple[str, str, str]]
) -> dict[tuple[str, str, str], tuple[datetime, float, float]]:
    """各命中策略键的待生效（pending）变更：键 -> (effective_at, 新容量, 新速率)。

    到期变更已在本次裁决事务开始时由 _apply_due_changes 应用，剩下的
    pending 变更 effective_at 必在未来；同一策略至多一条 pending
    （唯一索引 idx_policy_changes_one_pending 保证）。
    """
    out: dict[tuple[str, str, str], tuple[datetime, float, float]] = {}
    for scope, tenant, route in keys:
        row = conn.execute(
            "SELECT effective_at, new_capacity, new_refill_rate "
            "FROM policy_changes "
            "WHERE scope=? AND tenant_id=? AND route_id=? AND status='pending'",
            (scope, tenant, route),
        ).fetchone()
        if row is not None:
            out[(scope, tenant, route)] = (
                parse_iso(row["effective_at"]),
                float(row["new_capacity"]),
                float(row["new_refill_rate"]),
            )
    return out


def _segment_ready_at(
    bal: float,
    cap: float,
    rate: float,
    cost: float,
    start: float,
    end: Optional[float],
) -> Optional[float]:
    """余额在 [start, end)（end=None 表示无界）内按 min(cap, bal+(t-start)*rate)
    变化时，首次达到 cost 的时刻；本段内不可达返回 None。

    边界点 end 属于下一段（切换在 effective_at 时刻先按比例换算余额），
    故本段的就绪时刻必须严格小于 end。
    """
    if bal + 1e-12 >= cost:
        return start
    if rate <= 0.0 or cost > cap + 1e-12:
        return None
    t = start + (cost - bal) / rate
    if end is not None and t >= end:
        return None
    return t


def _first_sufficient_wait(
    states: list[dict[str, Any]],
    changes: dict[tuple[str, str, str], tuple[datetime, float, float]],
    cost: float,
    now: datetime,
) -> Optional[float]:
    """从裁决时刻 now 起，预测全部命中桶首次同时 >= cost 的等待秒数；不可能为 None。

    纯演算（不读写库、不提前应用切换）：各桶先按当前策略补充；有待生效
    变更的桶到 effective_at 按「旧余额 / 旧容量 × 新容量」的剩余比例规则
    换算（旧容量为 0 则余额归零），此后按新速率补充。切换时刻余额可能
    跳变（放大或缩小），因此以各切换时刻为界逐段考察：段内各桶余额单调
    不减，全部就绪即取各就绪时刻的最大值；第一段产生可行解即为答案，
    最终段仍有桶不可达则永不可重试。
    """
    # 每桶当前段的 (段起点余额, 容量, 速率) 与切换点（距 now 的秒数）
    tracks: list[dict[str, Any]] = []
    for s in states:
        switch = None
        ch = changes.get((s["scope"], s["tenant"], s["route"]))
        if ch is not None:
            eff, new_cap, new_rate = ch
            switch = (max(0.0, (eff - now).total_seconds()), new_cap, new_rate)
        tracks.append(
            {
                "bal": float(s["balance"]),
                "cap": float(s["capacity"]),
                "rate": float(s["refill_rate"]),
                "switch": switch,
            }
        )

    events = sorted({t["switch"][0] for t in tracks if t["switch"] is not None})
    start = 0.0
    for end in [*events, None]:  # None 收尾：最终段 [start, +∞)
        ready_max = start
        for t in tracks:
            ready = _segment_ready_at(
                t["bal"], t["cap"], t["rate"], cost, start, end
            )
            if ready is None:
                break
            ready_max = max(ready_max, ready)
        else:
            return ready_max
        if end is None:
            return None
        # 推进到 end：各桶先按段内速率补充到该时刻，到点切换的桶再按
        # 剩余比例换算容量（与 _apply_policy_change 同一套规则）
        for t in tracks:
            bal = min(t["cap"], t["bal"] + (end - start) * t["rate"])
            if t["switch"] is not None and t["switch"][0] == end:
                _, new_cap, new_rate = t["switch"]
                bal = (
                    0.0
                    if t["cap"] <= 0.0
                    else min(new_cap, bal / t["cap"] * new_cap)
                )
                t["cap"], t["rate"] = new_cap, new_rate
                t["switch"] = None  # 同一策略至多一条 pending
            t["bal"] = bal
        start = end
    return None  # pragma: no cover - 不可达：最终段必然 return


def decide(
    conn: sqlite3.Connection,
    *,
    request_id: str,
    tenant_id: Optional[str],
    route_id: Optional[str],
    cost: float,
) -> tuple[dict[str, Any], bool]:
    """对一次请求做多级裁决，返回 (结果, 是否为重放)。

    命中的每个桶在同一事务、同一时刻 now 下：
      1. 按距上次更新经过的时间补充令牌（不超过容量）；
      2. 全部桶余额都足够才统一扣减；任一不足则一个都不扣。
    拒绝时的重试时间把命中桶待生效的定时切换纳入预测（见
    _first_sufficient_wait），但只演算不落库，切换不会提前应用。
    """
    if cost <= 0:
        raise HTTPException(422, "cost 必须为正数")
    if route_id and not tenant_id:
        raise HTTPException(422, "提供 route_id 时必须同时提供 tenant_id")

    now = now_utc()

    # 0) 在同一裁决事务内先应用所有命中且到期的定时策略变更（无后台任务，
    #    惰性驱动），随后的读策略/读桶看到的必是切换后的完整新状态
    _apply_due_changes(conn, _hit_keys(tenant_id, route_id), now)
    # 所有余额写操作：先把到期 pending 预占在同一事务内转为 expired 并返还原桶，
    # 随后的补充/判足/扣减看到的必是返还后的余额
    _expire_due_reservations(conn, now)

    # 1) 幂等：request_id 已存在时，载荷一致则重放，冲突则 409
    existing = conn.execute(
        "SELECT payload_hash, result_json FROM decisions WHERE request_id=?",
        (request_id,),
    ).fetchone()
    payload = {"tenant_id": tenant_id or None, "route_id": route_id or None, "cost": cost}
    digest = payload_hash(payload)
    payload_json = json.dumps(payload, ensure_ascii=False)
    if existing is not None:
        if existing["payload_hash"] != digest:
            raise HTTPException(
                409,
                f"request_id={request_id!r} 已存在但裁决载荷不一致，拒绝重放",
            )
        result = json.loads(existing["result_json"])
        result["replayed"] = True
        return result, True

    # 2) 解析本次请求命中的策略层（全局 -> 租户 -> 路由），缺省层不做限制
    levels: list[tuple[str, str, str, sqlite3.Row]] = []
    g = conn.execute(
        "SELECT capacity, refill_rate, low_balance_threshold FROM policies "
        "WHERE scope='global' AND tenant_id='' AND route_id=''"
    ).fetchone()
    if g is not None:
        levels.append(("global", EMPTY, EMPTY, g))
    if tenant_id:
        t = conn.execute(
            "SELECT capacity, refill_rate, low_balance_threshold FROM policies "
            "WHERE scope='tenant' AND tenant_id=? AND route_id=''",
            (tenant_id,),
        ).fetchone()
        if t is not None:
            levels.append(("tenant", tenant_id, EMPTY, t))
        if route_id:
            r = conn.execute(
                "SELECT capacity, refill_rate, low_balance_threshold FROM policies "
                "WHERE scope='route' AND tenant_id=? AND route_id=?",
                (tenant_id, route_id),
            ).fetchone()
            if r is not None:
                levels.append(("route", tenant_id, route_id, r))

    if not levels:
        raise HTTPException(404, "没有任何命中的配额策略（请先配置至少一层策略）")

    # 3) 取桶（惰性创建，新桶满额），并在同一 now 下补充
    states: list[dict[str, Any]] = []
    for scope, tenant, route, pol in levels:
        row = conn.execute(
            "SELECT balance, updated_at FROM buckets "
            "WHERE scope=? AND tenant_id=? AND route_id=?",
            (scope, tenant, route),
        ).fetchone()
        if row is None:
            balance = float(pol["capacity"])
            conn.execute(
                "INSERT INTO buckets (scope, tenant_id, route_id, balance, updated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (scope, tenant, route, balance, iso(now)),
            )
        else:
            balance = _refill(
                row["balance"], row["updated_at"],
                pol["capacity"], pol["refill_rate"], now,
            )
        states.append(
            {
                "scope": scope, "tenant": tenant, "route": route,
                "capacity": float(pol["capacity"]),
                "refill_rate": float(pol["refill_rate"]),
                "low_balance_threshold": pol["low_balance_threshold"],
                "balance": balance,
            }
        )

    allowed = all(s["balance"] + 1e-12 >= cost for s in states)

    # 4) 不足：整组一个都不扣（补充本身会落库，这是时间应得的令牌）；
    #    充足：所有命中桶在同一事务中一起扣减
    if allowed:
        for s in states:
            before = s["balance"]
            after = before - float(cost)
            s["balance"] = after
            conn.execute(
                "UPDATE buckets SET balance=?, updated_at=? "
                "WHERE scope=? AND tenant_id=? AND route_id=?",
                (after, iso(now), s["scope"], s["tenant"], s["route"]),
            )
            _maybe_emit_low_balance(
                conn, s, before=before, after=after,
                request_id=request_id, now=now,
            )
        retry_at, retry_after, retry_possible = None, None, True
    else:
        # 整组最早可重试时刻：以裁决时刻为起点纯演算——各命中桶先按当前
        # 策略补充；命中层若有待生效（pending）的定时切换，到 effective_at
        # 按剩余比例换算容量、此后按新速率补充；跨全部命中层取首次同时
        # 足额的时刻。演算不改动任何落库状态（切换不会提前应用）。
        changes = _pending_change_map(
            conn, [(s["scope"], s["tenant"], s["route"]) for s in states]
        )
        wait = _first_sufficient_wait(states, changes, float(cost), now)
        if wait is None:
            retry_possible = False
            retry_at, retry_after = None, None
        else:
            retry_possible = True
            retry_dt = now + timedelta(seconds=wait)
            retry_at, retry_after = iso(retry_dt), max(0.0, wait)
        # 拒绝不扣减，但补充后的余额（时间应得的令牌）一律落库
        for s in states:
            conn.execute(
                "UPDATE buckets SET balance=?, updated_at=? "
                "WHERE scope=? AND tenant_id=? AND route_id=?",
                (s["balance"], iso(now), s["scope"], s["tenant"], s["route"]),
            )

    result = {
        "request_id": request_id,
        "allowed": allowed,
        "cost": float(cost),
        "tenant_id": tenant_id or None,
        "route_id": route_id or None,
        "decided_at": iso(now),
        "retry_at": retry_at,
        "retry_after_seconds": retry_after,
        "retry_possible": retry_possible,
        "replayed": False,
        "revoked": False,
        "buckets": [
            _bucket_out(
                s["scope"], s["tenant"], s["route"],
                s["capacity"], s["refill_rate"], s["balance"],
            )
            for s in states
        ],
    }

    # 5) 存档（通过与拒绝都存），保证 request_id 可重放
    conn.execute(
        """
        INSERT INTO decisions
            (request_id, payload_hash, payload_json, allowed, cost, decided_at,
             retry_at, retry_after_secs, result_json, revoked, revoked_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)
        """,
        (
            request_id, digest, payload_json, int(allowed), float(cost), iso(now),
            retry_at, retry_after, json.dumps(result, ensure_ascii=False),
        ),
    )
    return result, False


# ------------------------------------------------------------ 批量裁决


class BatchRejected(Exception):
    """批量演算在某条目处整批失败（不足或 request_id 已存在）。

    不是 4xx HTTP 错误：调用方回滚业务事务后，仍需把批次失败结果落档。
    """

    def __init__(self, index: int, reason: str, failure: dict[str, Any]):
        super().__init__(f"batch failed at index={index}: {reason}")
        self.index = index
        self.reason = reason
        self.failure = failure


def _load_policy_levels_batch(
    conn: sqlite3.Connection,
    tenant_id: Optional[str],
    route_id: Optional[str],
) -> list[tuple[str, str, str, sqlite3.Row]]:
    """解析一次裁决命中的已配置策略层（全局 -> 租户 -> 路由），缺省层不限制。"""
    levels: list[tuple[str, str, str, sqlite3.Row]] = []
    g = conn.execute(
        "SELECT capacity, refill_rate, low_balance_threshold FROM policies "
        "WHERE scope='global' AND tenant_id='' AND route_id=''"
    ).fetchone()
    if g is not None:
        levels.append(("global", EMPTY, EMPTY, g))
    if tenant_id:
        t = conn.execute(
            "SELECT capacity, refill_rate, low_balance_threshold FROM policies "
            "WHERE scope='tenant' AND tenant_id=? AND route_id=''",
            (tenant_id,),
        ).fetchone()
        if t is not None:
            levels.append(("tenant", tenant_id, EMPTY, t))
        if route_id:
            r = conn.execute(
                "SELECT capacity, refill_rate, low_balance_threshold FROM policies "
                "WHERE scope='route' AND tenant_id=? AND route_id=?",
                (tenant_id, route_id),
            ).fetchone()
            if r is not None:
                levels.append(("route", tenant_id, route_id, r))
    return levels


def _batch_payload(items: list[dict[str, Any]]) -> dict[str, Any]:
    """批次的规范载荷（不含 batch_id 也无所谓：hash 按行存储时 batch_id 已做主键，
    这里把整批条目按数组顺序纳入摘要，任何字段或顺序变化都视为异载荷）。"""
    return {"requests": items}


def decide_batch(
    conn: sqlite3.Connection,
    *,
    batch_id: str,
    items: list[dict[str, Any]],
) -> dict[str, Any]:
    """在一个写事务内完成整批裁决，返回可直接响应的结果字典。

    事务内顺序：① 以同一时刻 now 应用所有条目命中、且已到期的定时策略切换
    （仅一次）；② 按数组顺序在共享的多级桶上演算——前项模拟扣减后的余额
    供后项使用；③ 仅当全部条目获准时，才一次性写入桶余额、普通裁决与
    低余额事件，以及批次档案。

    任一条目不足或 request_id 已存在（含批内重复）时抛出 BatchRejected，
    调用方必须 ROLLBACK 当前事务，再调用 record_failed_batch 单独存档。

    batch_id 幂等：已存在且完整载荷一致 -> 返回原结果（replayed=True）；
    同键异载荷 -> 409。
    """
    for it in items:
        if it["cost"] <= 0:
            raise HTTPException(422, "cost 必须为正数")
        if it.get("route_id") and not it.get("tenant_id"):
            raise HTTPException(422, "提供 route_id 时必须同时提供 tenant_id")

    canonical = _batch_payload(
        [
            {
                "request_id": it["request_id"],
                "tenant_id": it.get("tenant_id") or None,
                "route_id": it.get("route_id") or None,
                "cost": float(it["cost"]),
            }
            for it in items
        ]
    )
    digest = payload_hash(canonical)
    payload_json = json.dumps(canonical, ensure_ascii=False)

    existing = conn.execute(
        "SELECT payload_hash, result_json FROM decide_batches WHERE batch_id=?",
        (batch_id,),
    ).fetchone()
    if existing is not None:
        if existing["payload_hash"] != digest:
            raise HTTPException(
                409,
                f"batch_id={batch_id!r} 已存在但批次载荷不一致，拒绝重放",
            )
        result = json.loads(existing["result_json"])
        result["replayed"] = True
        return result

    now = now_utc()
    now_iso = iso(now)

    # 1) 同一时刻、同一事务内，先应用所有条目命中且到期的定时切换（并集去重）
    hit_keys: list[tuple[str, str, str]] = []
    for it in items:
        for key in _hit_keys(it.get("tenant_id"), it.get("route_id")):
            if key not in hit_keys:
                hit_keys.append(key)
    _apply_due_changes(conn, hit_keys, now)
    # 余额写操作：同刻先把到期 pending 预占转为 expired 并返还；整批随后失败时
    # 本事务整体回滚（到期转换也一并回滚），与到期切换保持 pending 同一规则
    _expire_due_reservations(conn, now)

    # 共享桶状态缓存：同一桶被多个条目命中时，余额沿数组顺序传递
    states: dict[tuple[str, str, str], dict[str, Any]] = {}

    def state_for(
        scope: str, tenant: str, route: str, pol: sqlite3.Row
    ) -> dict[str, Any]:
        key = (scope, tenant, route)
        st = states.get(key)
        if st is not None:
            return st
        row = conn.execute(
            "SELECT balance, updated_at FROM buckets "
            "WHERE scope=? AND tenant_id=? AND route_id=?",
            (scope, tenant, route),
        ).fetchone()
        if row is None:
            # 桶尚未惰性创建：以满额参与演算，实际 INSERT 推迟到整批提交
            balance = float(pol["capacity"])
        else:
            # 到期切换可能刚改写过该桶的余额与时间锚点；整批共用同一 now，
            # 时间补充只在首次载入时计算一次
            balance = _refill(
                row["balance"], row["updated_at"],
                pol["capacity"], pol["refill_rate"], now,
            )
        st = {
            "scope": scope, "tenant": tenant, "route": route,
            "capacity": float(pol["capacity"]),
            "refill_rate": float(pol["refill_rate"]),
            "low_balance_threshold": pol["low_balance_threshold"],
            "balance": balance,
            # 桶是否为本次演算中新引入（提交时才 INSERT）：失败回滚后
            # 不应凭空多出余额为满额的桶行
            "new_bucket": row is None,
        }
        states[key] = st
        return st

    seen_request_ids: set[str] = set()
    item_results: list[dict[str, Any]] = []
    # 每项命中桶的 (state, 扣减前, 扣减后)，低余额事件据此判定：
    # 同一桶被多个条目命中时，各次越线必须按演算顺序逐个识别
    item_deductions: list[list[tuple[dict[str, Any], float, float]]] = []

    # 2) 按数组顺序演算：仅在全部获准后才真正落库
    for idx, it in enumerate(items):
        request_id = it["request_id"]
        tenant_id = it.get("tenant_id")
        route_id = it.get("route_id")
        cost = float(it["cost"])

        levels = _load_policy_levels_batch(conn, tenant_id, route_id)
        if not levels:
            raise HTTPException(404, "没有任何命中的配额策略（请先配置至少一层策略）")
        item_states = [state_for(scope, tenant, route, pol)
                       for scope, tenant, route, pol in levels]

        # request_id 冲突（批内重复，或普通裁决/先前批次已存档）先于不足判定
        if request_id in seen_request_ids:
            raise BatchRejected(idx, "request_id_exists", _batch_failure(
                idx, request_id, cost, tenant_id, route_id, item_states,
                "request_id_exists"))
        dup = conn.execute(
            "SELECT 1 FROM decisions WHERE request_id=?", (request_id,)
        ).fetchone()
        if dup is not None:
            raise BatchRejected(idx, "request_id_exists", _batch_failure(
                idx, request_id, cost, tenant_id, route_id, item_states,
                "request_id_exists"))
        seen_request_ids.add(request_id)

        if not all(s["balance"] + 1e-12 >= cost for s in item_states):
            raise BatchRejected(idx, "insufficient_balance", _batch_failure(
                idx, request_id, cost, tenant_id, route_id, item_states,
                "insufficient_balance"))

        # 模拟扣减：只改共享缓存中的余额，循环结束且整批获准时统一持久化
        deductions: list[tuple[dict[str, Any], float, float]] = []
        for s in item_states:
            before = s["balance"]
            after = before - cost
            s["balance"] = after
            deductions.append((s, before, after))
        item_deductions.append(deductions)

        item_results.append(
            {
                "index": idx,
                "request_id": request_id,
                "allowed": True,
                "cost": cost,
                "tenant_id": tenant_id or None,
                "route_id": route_id or None,
                "decided_at": now_iso,
                "buckets": [
                    _bucket_out(
                        s["scope"], s["tenant"], s["route"],
                        s["capacity"], s["refill_rate"], s["balance"],
                    )
                    for s in item_states
                ],
            }
        )

    # 3) 全部获准：同一事务内写入桶余额、低余额事件、单笔裁决与批次档案。
    #    低余额事件按演算顺序依据每项扣减前后的余额判定，request_id 归属
    #    对应条目；同一批次中多个条目或多个桶越线各写一条。
    for r, deductions in zip(item_results, item_deductions):
        for s, before, after in deductions:
            _maybe_emit_low_balance(
                conn, s, before=before, after=after,
                request_id=r["request_id"], now=now,
            )
    for s in states.values():
        if s["new_bucket"]:
            conn.execute(
                "INSERT INTO buckets (scope, tenant_id, route_id, balance, updated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (s["scope"], s["tenant"], s["route"], s["balance"], now_iso),
            )
        else:
            conn.execute(
                "UPDATE buckets SET balance=?, updated_at=? "
                "WHERE scope=? AND tenant_id=? AND route_id=?",
                (s["balance"], now_iso, s["scope"], s["tenant"], s["route"]),
            )

    for r in item_results:
        payload = {
            "tenant_id": r["tenant_id"],
            "route_id": r["route_id"],
            "cost": r["cost"],
        }
        decision = {
            "request_id": r["request_id"],
            "allowed": True,
            "cost": r["cost"],
            "tenant_id": r["tenant_id"],
            "route_id": r["route_id"],
            "decided_at": now_iso,
            "retry_at": None,
            "retry_after_seconds": None,
            "retry_possible": True,
            "replayed": False,
            "revoked": False,
            "buckets": r["buckets"],
        }
        conn.execute(
            """
            INSERT INTO decisions
                (request_id, payload_hash, payload_json, allowed, cost, decided_at,
                 retry_at, retry_after_secs, result_json, revoked, revoked_at)
            VALUES (?, ?, ?, 1, ?, ?, NULL, NULL, ?, 0, NULL)
            """,
            (
                r["request_id"], payload_hash(payload),
                json.dumps(payload, ensure_ascii=False), r["cost"], now_iso,
                json.dumps(decision, ensure_ascii=False),
            ),
        )

    result = {
        "batch_id": batch_id,
        "committed": True,
        "replayed": False,
        "decided_at": now_iso,
        "results": item_results,
        "failed_index": None,
        "failure": None,
    }
    conn.execute(
        """
        INSERT INTO decide_batches
            (batch_id, payload_hash, payload_json, committed, failed_index,
             result_json, decided_at)
        VALUES (?, ?, ?, 1, NULL, ?, ?)
        """,
        (batch_id, digest, payload_json,
         json.dumps(result, ensure_ascii=False), now_iso),
    )
    return result


def _batch_failure(
    index: int,
    request_id: str,
    cost: float,
    tenant_id: Optional[str],
    route_id: Optional[str],
    item_states: list[dict[str, Any]],
    reason: str,
) -> dict[str, Any]:
    """构造失败条目快照（前序条目模拟扣减后的桶余额，尚未持久化）。"""
    return {
        "index": index,
        "request_id": request_id,
        "reason": reason,
        "cost": float(cost),
        "tenant_id": tenant_id or None,
        "route_id": route_id or None,
        "buckets": [
            _bucket_out(
                s["scope"], s["tenant"], s["route"],
                s["capacity"], s["refill_rate"], s["balance"],
            )
            for s in item_states
        ],
    }


def record_failed_batch(
    conn: sqlite3.Connection,
    *,
    batch_id: str,
    items: list[dict[str, Any]],
    failure: dict[str, Any],
) -> dict[str, Any]:
    """业务事务回滚后，在独立事务中保存失败批次的档案（无论成败均保存）。

    返回可直接响应的结果。若并发下该 batch_id 已被另一事务存档：载荷一致
    则重放原结果，异载荷则抛 409（与 decide_batch 内的幂等判定保持一致）。
    """
    canonical = _batch_payload(
        [
            {
                "request_id": it["request_id"],
                "tenant_id": it.get("tenant_id") or None,
                "route_id": it.get("route_id") or None,
                "cost": float(it["cost"]),
            }
            for it in items
        ]
    )
    digest = payload_hash(canonical)
    payload_json = json.dumps(canonical, ensure_ascii=False)
    now_iso = iso(now_utc())
    idx = failure["index"]
    result = {
        "batch_id": batch_id,
        "committed": False,
        "replayed": False,
        "decided_at": now_iso,
        "results": None,
        "failed_index": idx,
        "failure": {
            "index": idx,
            "request_id": failure["request_id"],
            "reason": failure["reason"],
            "cost": float(failure["cost"]),
            "tenant_id": failure.get("tenant_id") or None,
            "route_id": failure.get("route_id") or None,
            "buckets": failure["buckets"],
        },
    }
    try:
        conn.execute(
            """
            INSERT INTO decide_batches
                (batch_id, payload_hash, payload_json, committed, failed_index,
                 result_json, decided_at)
            VALUES (?, ?, ?, 0, ?, ?, ?)
            """,
            (batch_id, digest, payload_json, idx,
             json.dumps(result, ensure_ascii=False), now_iso),
        )
    except sqlite3.IntegrityError:
        row = conn.execute(
            "SELECT payload_hash, result_json FROM decide_batches WHERE batch_id=?",
            (batch_id,),
        ).fetchone()
        if row is not None and row["payload_hash"] != digest:
            raise HTTPException(
                409,
                f"batch_id={batch_id!r} 已存在但批次载荷不一致，拒绝重放",
            )
        result = json.loads(row["result_json"])
        result["replayed"] = True
    return result


# ------------------------------------------------------------ 策略影响预演


def impact_preview(
    conn: sqlite3.Connection,
    *,
    scope: str,
    tenant_id: Optional[str],
    route_id: Optional[str],
    capacity: float,
    refill_rate: float,
    items: list[dict[str, Any]],
) -> dict[str, Any]:
    """对「把某已存在策略替换为候选容量/速率」做纯内存影响预演，返回双侧逐条结果。

    调用方必须在 database.read_tx 只读快照事务内调用；全程不改动策略、桶、
    裁决与事件数据。流程：

      1. 目标策略必须已存在（404）；目标策略或任一请求命中的策略存在待生效
         （pending）定时变更 -> 409（预演假设窗口内策略保持不变）；
      2. 以同一时刻 now 为预演起点（at_seconds=0），把所有涉及桶按现行策略
         补充到起点（同一只读快照）；
      3. 构建现行/候选两套独立内存状态：候选侧仅替换目标策略的容量与速率，
         并把该桶的起点余额截断到候选容量，其余桶两侧完全一致；
      4. 两侧各自按 at_seconds（非递减）逐条「补充 -> 判足 -> 扣减」：
         前项余额影响后项，拒绝项不扣减（补充照样计入）；
      5. 返回逐条两侧的准入结果、命中桶余额与差异（allowed 是否翻转、
         各桶余额差），以及汇总计数。

    未命中任何已配置策略层的请求两侧均准入、buckets 为空（无配额层可限制）。
    """
    tenant, route = _normalize_scope(scope, tenant_id, route_id)
    if capacity < 0 or refill_rate < 0:
        raise HTTPException(422, "capacity 与 refill_rate 必须非负")

    last_at = 0.0
    for it in items:
        if it["cost"] <= 0:
            raise HTTPException(422, "cost 必须为正数")
        if it.get("route_id") and not it.get("tenant_id"):
            raise HTTPException(422, "提供 route_id 时必须同时提供 tenant_id")
        at = float(it["at_seconds"])
        if not 0.0 <= at <= 3600.0:
            raise HTTPException(422, "at_seconds 必须在 0 到 3600 秒之间")
        if at < last_at:
            raise HTTPException(422, "requests 必须按 at_seconds 非递减顺序提交")
        last_at = at

    target_key = (scope, tenant, route)
    policy = conn.execute(
        "SELECT capacity, refill_rate FROM policies "
        "WHERE scope=? AND tenant_id=? AND route_id=?",
        target_key,
    ).fetchone()
    if policy is None:
        raise HTTPException(404, "目标策略不存在，请先用 PUT /policies 创建")

    # 预演涉及的策略键：目标策略 + 各请求按 全局 -> 租户 -> 路由 命中的层级
    involved: list[tuple[str, str, str]] = []

    def _add(key: tuple[str, str, str]) -> None:
        if key not in involved:
            involved.append(key)

    _add(target_key)
    item_keys: list[list[tuple[str, str, str]]] = []
    for it in items:
        keys = _hit_keys(it.get("tenant_id"), it.get("route_id"))
        item_keys.append(keys)
        for key in keys:
            _add(key)

    # 任一涉及策略存在待生效定时变更 -> 409：变更会在窗口内某时刻改写策略，
    # 预演的「策略不变」假设不再成立
    for key in involved:
        pending = _pending_change(conn, *key)
        if pending is not None:
            raise HTTPException(
                409,
                f"策略 scope={key[0]!r} tenant_id={key[1] or None!r} "
                f"route_id={key[2] or None!r} 存在待生效的定时变更 "
                f"change_id={pending['change_id']!r}"
                f"（effective_at={pending['effective_at']}），"
                "请先取消或等其生效后再预演",
            )

    # 同一只读快照：预演起点 now，各涉及策略与其桶一次读入
    start = now_utc()
    policies: dict[tuple[str, str, str], tuple[float, float]] = {}
    bucket_rows: dict[tuple[str, str, str], Optional[sqlite3.Row]] = {}
    for key in involved:
        pol = conn.execute(
            "SELECT capacity, refill_rate FROM policies "
            "WHERE scope=? AND tenant_id=? AND route_id=?",
            key,
        ).fetchone()
        if pol is None:
            continue  # 未配置的层不参与裁决
        policies[key] = (float(pol["capacity"]), float(pol["refill_rate"]))
        bucket_rows[key] = conn.execute(
            "SELECT balance, updated_at FROM buckets "
            "WHERE scope=? AND tenant_id=? AND route_id=?",
            key,
        ).fetchone()

    def _initial_states(candidate: bool) -> dict[tuple[str, str, str], dict[str, Any]]:
        """按现行策略把桶补充到起点，构建一套内存状态（candidate=True 时替换目标策略）。"""
        states: dict[tuple[str, str, str], dict[str, Any]] = {}
        for key, (cap, rate) in policies.items():
            b = bucket_rows[key]
            if b is None:
                balance = cap  # 桶尚未惰性创建：按现行容量满额
            else:
                balance = _refill(b["balance"], b["updated_at"], cap, rate, start)
            if candidate and key == target_key:
                cap, rate = float(capacity), float(refill_rate)
                balance = min(balance, cap)  # 起点余额截断到候选容量
            states[key] = {
                "scope": key[0], "tenant": key[1], "route": key[2],
                "capacity": cap, "refill_rate": rate,
                "balance": balance, "t": 0.0,
            }
        return states

    def _run(states: dict[tuple[str, str, str], dict[str, Any]]) -> list[dict[str, Any]]:
        """在一套内存状态上按时间顺序逐条补充、判足、扣减。"""
        out: list[dict[str, Any]] = []
        for it, keys in zip(items, item_keys):
            hit = [k for k in keys if k in states]
            at = float(it["at_seconds"])
            cost = float(it["cost"])
            for k in hit:
                st = states[k]
                st["balance"] = min(
                    st["capacity"],
                    st["balance"] + (at - st["t"]) * st["refill_rate"],
                )
                st["t"] = at
            allowed = all(states[k]["balance"] + 1e-12 >= cost for k in hit)
            if allowed:
                for k in hit:
                    states[k]["balance"] -= cost
            out.append(
                {
                    "allowed": allowed,
                    "buckets": [
                        _bucket_out(
                            states[k]["scope"], states[k]["tenant"], states[k]["route"],
                            states[k]["capacity"], states[k]["refill_rate"],
                            states[k]["balance"],
                        )
                        for k in hit
                    ],
                }
            )
        return out

    current_items = _run(_initial_states(candidate=False))
    candidate_items = _run(_initial_states(candidate=True))

    result_items: list[dict[str, Any]] = []
    current_allowed = candidate_allowed = allowed_changed_items = 0
    for idx, it in enumerate(items):
        cur, cand = current_items[idx], candidate_items[idx]
        current_allowed += int(cur["allowed"])
        candidate_allowed += int(cand["allowed"])
        changed = cur["allowed"] != cand["allowed"]
        allowed_changed_items += int(changed)
        diffs = [
            {
                "scope": cb["scope"],
                "tenant_id": cb["tenant_id"],
                "route_id": cb["route_id"],
                "current_balance": cb["balance"],
                "candidate_balance": kb["balance"],
                "balance_delta": kb["balance"] - cb["balance"],
            }
            for cb, kb in zip(cur["buckets"], cand["buckets"])
        ]
        result_items.append(
            {
                "index": idx,
                "at_seconds": float(it["at_seconds"]),
                "tenant_id": it.get("tenant_id") or None,
                "route_id": it.get("route_id") or None,
                "cost": float(it["cost"]),
                "current": cur,
                "candidate": cand,
                "allowed_changed": changed,
                "bucket_diffs": diffs,
            }
        )

    return {
        "scope": scope,
        "tenant_id": tenant or None,
        "route_id": route or None,
        "current_capacity": float(policy["capacity"]),
        "current_refill_rate": float(policy["refill_rate"]),
        "candidate_capacity": float(capacity),
        "candidate_refill_rate": float(refill_rate),
        "started_at": iso(start),
        "items": result_items,
        "summary": {
            "total_items": len(items),
            "current_allowed": current_allowed,
            "candidate_allowed": candidate_allowed,
            "allowed_changed_items": allowed_changed_items,
        },
    }


# ---------------------------------------------------------------- 撤销


def revoke(conn: sqlite3.Connection, request_id: str) -> tuple[dict[str, Any], bool]:
    """撤销一次已通过的裁决并补回令牌，返回 (结果, 是否为重复撤销)。

    重复撤销幂等；被拒绝/不存在的 request_id 分别返回 409 / 404。
    每个桶先按经过时间补充，再加回 cost，最后截断到容量。
    """
    row = conn.execute(
        "SELECT allowed, cost, payload_json, result_json, revoked FROM decisions "
        "WHERE request_id=?",
        (request_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(404, f"request_id={request_id!r} 不存在")
    if not row["allowed"]:
        raise HTTPException(409, f"request_id={request_id!r} 是被拒绝的裁决，无需撤销")
    if row["revoked"]:
        result = json.loads(row["result_json"])
        result["replayed"] = True
        return result, True

    payload = json.loads(row["payload_json"])
    cost = float(row["cost"])
    now = now_utc()

    # 用原裁决载荷定位当时命中的桶；桶行在裁决通过时必然已创建
    keys = _hit_keys(payload.get("tenant_id"), payload.get("route_id"))

    # 与裁决相同：先在本事务内应用命中且到期的定时变更，再补回令牌，
    # 避免撤销用旧策略把桶时间锚点推过 effective_at 而重复计息
    _apply_due_changes(conn, keys, now)
    # 余额写操作：先把到期 pending 预占转为 expired 并返还原桶，再补回本裁决
    _expire_due_reservations(conn, now)

    refunded_buckets: list[dict[str, Any]] = []
    for scope, tenant, route in keys:
        pol = conn.execute(
            "SELECT capacity, refill_rate FROM policies "
            "WHERE scope=? AND tenant_id=? AND route_id=?",
            (scope, tenant, route),
        ).fetchone()
        if pol is None:
            continue  # 策略已被移除（当前版本不支持删除，仅作防御）
        b = conn.execute(
            "SELECT balance, updated_at FROM buckets "
            "WHERE scope=? AND tenant_id=? AND route_id=?",
            (scope, tenant, route),
        ).fetchone()
        if b is None:
            continue
        # 先补充时间应得的令牌，再补回本次扣减，并以容量为上限
        balance = _refill(
            b["balance"], b["updated_at"],
            pol["capacity"], pol["refill_rate"], now,
        )
        balance = min(float(pol["capacity"]), balance + cost)
        conn.execute(
            "UPDATE buckets SET balance=?, updated_at=? "
            "WHERE scope=? AND tenant_id=? AND route_id=?",
            (balance, iso(now), scope, tenant, route),
        )
        refunded_buckets.append(
            _bucket_out(
                scope, tenant, route,
                pol["capacity"], pol["refill_rate"], balance,
            )
        )

    revoked_at = iso(now)
    result = json.loads(row["result_json"])
    result["revoked"] = True
    result["revoked_at"] = revoked_at
    result["replayed"] = False
    result["buckets"] = refunded_buckets

    conn.execute(
        "UPDATE decisions SET revoked=1, revoked_at=?, result_json=? WHERE request_id=?",
        (revoked_at, json.dumps(result, ensure_ascii=False), request_id),
    )
    return result, False


# ---------------------------------------------------------------- 事件


def list_events(
    conn: sqlite3.Connection, *, after_id: int = 0, limit: int = 100
) -> list[dict[str, Any]]:
    """按 id 递增返回低余额事件；after_id 为游标（不含），limit 为页大小。"""
    rows = conn.execute(
        "SELECT id, scope, tenant_id, route_id, balance_before, balance_after, "
        "threshold, request_id, created_at "
        "FROM low_balance_events WHERE id > ? ORDER BY id LIMIT ?",
        (after_id, limit),
    ).fetchall()
    return [
        {
            "id": r["id"],
            "scope": r["scope"],
            "tenant_id": r["tenant_id"] or None,
            "route_id": r["route_id"] or None,
            "balance_before": r["balance_before"],
            "balance_after": r["balance_after"],
            "threshold": r["threshold"],
            "request_id": r["request_id"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]


# ------------------------------------------------------------ 配额预占（reservation）


_RESERVATION_COLS = (
    "reservation_id, payload_hash, status, tenant_id, route_id, cost, "
    "ttl_seconds, created_at, expire_at, confirmed_at, cancelled_at, "
    "expired_at, buckets_json"
)


def _reservation_bucket_keys(row: sqlite3.Row) -> list[tuple[str, str, str]]:
    """读取创建预占时保存的原命中桶键快照（全局 -> 租户 -> 路由顺序）。"""
    return [
        (scope, tenant, route)
        for scope, tenant, route in json.loads(row["buckets_json"])
    ]


def _live_bucket_snapshot(
    conn: sqlite3.Connection,
    keys: list[tuple[str, str, str]],
    now: datetime,
) -> list[dict[str, Any]]:
    """按当前策略与当前时刻，对一组桶键返回补充后的实时余额快照（只读不落库）。"""
    out: list[dict[str, Any]] = []
    for scope, tenant, route in keys:
        pol = conn.execute(
            "SELECT capacity, refill_rate FROM policies "
            "WHERE scope=? AND tenant_id=? AND route_id=?",
            (scope, tenant, route),
        ).fetchone()
        if pol is None:
            continue  # 防御：当前版本不支持删除策略
        b = conn.execute(
            "SELECT balance, updated_at FROM buckets "
            "WHERE scope=? AND tenant_id=? AND route_id=?",
            (scope, tenant, route),
        ).fetchone()
        if b is None:
            balance = float(pol["capacity"])
        else:
            balance = _refill(
                b["balance"], b["updated_at"],
                pol["capacity"], pol["refill_rate"], now,
            )
        out.append(
            _bucket_out(
                scope, tenant, route,
                pol["capacity"], pol["refill_rate"], balance,
            )
        )
    return out


def _reservation_out(
    conn: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    replayed: bool = False,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    ts = now or now_utc()
    return {
        "reservation_id": row["reservation_id"],
        "status": row["status"],
        "allowed": row["status"] != "rejected",
        "tenant_id": row["tenant_id"] or None,
        "route_id": row["route_id"] or None,
        "cost": float(row["cost"]),
        "ttl_seconds": int(row["ttl_seconds"]),
        "created_at": row["created_at"],
        "expire_at": row["expire_at"],
        "confirmed_at": row["confirmed_at"],
        "cancelled_at": row["cancelled_at"],
        "expired_at": row["expired_at"],
        "replayed": bool(replayed),
        "buckets": _live_bucket_snapshot(
            conn, _reservation_bucket_keys(row), ts
        ),
    }


def _refund_to_buckets(
    conn: sqlite3.Connection,
    keys: list[tuple[str, str, str]],
    cost: float,
    now: datetime,
) -> None:
    """向给定的原命中桶返还 cost：先应用这些桶到期的定时切换并按当前策略
    补充，再加 cost，最终不超过当前容量（与撤销返还同一套规则）。

    不产生 low_balance 事件（事件只在获准裁决的扣减事务内写入）。
    """
    _apply_due_changes(conn, keys, now)
    now_iso = iso(now)
    for scope, tenant, route in keys:
        pol = conn.execute(
            "SELECT capacity, refill_rate FROM policies "
            "WHERE scope=? AND tenant_id=? AND route_id=?",
            (scope, tenant, route),
        ).fetchone()
        b = conn.execute(
            "SELECT balance, updated_at FROM buckets "
            "WHERE scope=? AND tenant_id=? AND route_id=?",
            (scope, tenant, route),
        ).fetchone()
        if pol is None or b is None:
            # 防御：策略/桶均不支持删除，正常流程中预占创建时桶必然已存在
            continue
        # 先按当前补充/定时切换规则计息，再补回 cost，并以当前容量为上限
        balance = _refill(
            b["balance"], b["updated_at"],
            pol["capacity"], pol["refill_rate"], now,
        )
        balance = min(float(pol["capacity"]), balance + float(cost))
        conn.execute(
            "UPDATE buckets SET balance=?, updated_at=? "
            "WHERE scope=? AND tenant_id=? AND route_id=?",
            (balance, now_iso, scope, tenant, route),
        )


def _expire_one_if_due(
    conn: sqlite3.Connection, reservation_id: str, now: datetime
) -> bool:
    """若指定预占为 pending 且 expire_at <= now，在当前事务内转为 expired
    并向原桶返还；返回是否发生了转换。

    确认/取消与到期竞争时，以事务时刻 now 为唯一裁决依据：到期优先——
    本检查一旦把行转成 expired，随后的确认/取消即返回 409。
    """
    row = conn.execute(
        f"SELECT {_RESERVATION_COLS} FROM reservations WHERE reservation_id=?",
        (reservation_id,),
    ).fetchone()
    if row is None or row["status"] != "pending" or row["expire_at"] > iso(now):
        return False
    cur = conn.execute(
        "UPDATE reservations SET status='expired', expired_at=? "
        "WHERE reservation_id=? AND status='pending' AND expire_at <= ?",
        (iso(now), reservation_id, iso(now)),
    )
    if cur.rowcount == 0:
        return False
    _refund_to_buckets(conn, _reservation_bucket_keys(row), float(row["cost"]), now)
    return True


def _expire_due_reservations(conn: sqlite3.Connection, now: datetime) -> int:
    """在当前写事务内把全部到期 pending 预占转为 expired 并向各自原桶返还。

    「所有余额写操作」在动桶之前调用本函数：预占不设后台任务，到期完全由
    裁决/撤销/策略更新/预占自身操作在同一 BEGIN IMMEDIATE 事务内惰性推进，
    到期转换、返还与随后的余额读改写原子完成，不会漏还或重复返还。
    """
    now_iso = iso(now)
    rows = conn.execute(
        f"SELECT {_RESERVATION_COLS} FROM reservations "
        "WHERE status='pending' AND expire_at <= ? ORDER BY expire_at, rowid",
        (now_iso,),
    ).fetchall()
    count = 0
    for row in rows:
        cur = conn.execute(
            "UPDATE reservations SET status='expired', expired_at=? "
            "WHERE reservation_id=? AND status='pending' AND expire_at <= ?",
            (now_iso, row["reservation_id"], now_iso),
        )
        if cur.rowcount == 0:
            continue
        _refund_to_buckets(
            conn, _reservation_bucket_keys(row), float(row["cost"]), now
        )
        count += 1
    return count


def create_reservation(
    conn: sqlite3.Connection,
    *,
    reservation_id: str,
    tenant_id: Optional[str],
    route_id: Optional[str],
    cost: float,
    ttl_seconds: int,
) -> dict[str, Any]:
    """创建配额预占，返回可直接响应的结果。

    全部命中桶在同一事务、同一时刻下先补充（含到期定时切换）再判足：
      - 都充足：所有命中桶统一预扣 cost，命中桶键快照存档，状态为 pending；
      - 任一不足：一个都不扣，预占以 rejected 终态存档（拒绝结果可重放）。
    动桶之前先清扫全局到期 pending 预占并返还。同 reservation_id 同载荷
    （tenant_id / route_id / cost / ttl_seconds）重放原结果，异载荷 409。
    """
    if cost <= 0:
        raise HTTPException(422, "cost 必须为正数")
    if route_id and not tenant_id:
        raise HTTPException(422, "提供 route_id 时必须同时提供 tenant_id")
    if not 1 <= int(ttl_seconds) <= 300:
        raise HTTPException(422, "ttl_seconds 必须在 1 到 300 秒之间")

    now = now_utc()
    _apply_due_changes(conn, _hit_keys(tenant_id, route_id), now)
    _expire_due_reservations(conn, now)

    payload = {
        "tenant_id": tenant_id or None,
        "route_id": route_id or None,
        "cost": float(cost),
        "ttl_seconds": int(ttl_seconds),
    }
    digest = payload_hash(payload)

    existing = conn.execute(
        f"SELECT {_RESERVATION_COLS} FROM reservations WHERE reservation_id=?",
        (reservation_id,),
    ).fetchone()
    if existing is not None:
        if existing["payload_hash"] != digest:
            raise HTTPException(
                409,
                f"reservation_id={reservation_id!r} 已存在但预占载荷不一致，拒绝重放",
            )
        return _reservation_out(conn, existing, replayed=True, now=now)

    levels = _load_policy_levels_batch(conn, tenant_id, route_id)
    if not levels:
        raise HTTPException(404, "没有任何命中的配额策略（请先配置至少一层策略）")

    states: list[dict[str, Any]] = []
    for scope, tenant, route, pol in levels:
        row = conn.execute(
            "SELECT balance, updated_at FROM buckets "
            "WHERE scope=? AND tenant_id=? AND route_id=?",
            (scope, tenant, route),
        ).fetchone()
        if row is None:
            balance = float(pol["capacity"])
            conn.execute(
                "INSERT INTO buckets (scope, tenant_id, route_id, balance, updated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (scope, tenant, route, balance, iso(now)),
            )
        else:
            balance = _refill(
                row["balance"], row["updated_at"],
                pol["capacity"], pol["refill_rate"], now,
            )
        states.append(
            {
                "scope": scope, "tenant": tenant, "route": route,
                "capacity": float(pol["capacity"]),
                "refill_rate": float(pol["refill_rate"]),
                "balance": balance,
            }
        )

    allowed = all(s["balance"] + 1e-12 >= cost for s in states)
    now_iso = iso(now)
    expire_at = iso(now + timedelta(seconds=int(ttl_seconds)))
    bucket_keys = [[s["scope"], s["tenant"], s["route"]] for s in states]

    if allowed:
        # 全部充足才统一预扣；预占扣减不写 low_balance 事件
        for s in states:
            after = s["balance"] - float(cost)
            s["balance"] = after
            conn.execute(
                "UPDATE buckets SET balance=?, updated_at=? "
                "WHERE scope=? AND tenant_id=? AND route_id=?",
                (after, now_iso, s["scope"], s["tenant"], s["route"]),
            )
        status = "pending"
    else:
        # 任一不足：一个都不扣（时间应得的补充按裁决惯例落库），存档为 rejected
        for s in states:
            conn.execute(
                "UPDATE buckets SET balance=?, updated_at=? "
                "WHERE scope=? AND tenant_id=? AND route_id=?",
                (s["balance"], now_iso, s["scope"], s["tenant"], s["route"]),
            )
        status = "rejected"

    conn.execute(
        """
        INSERT INTO reservations
            (reservation_id, payload_hash, payload_json, status, tenant_id,
             route_id, cost, ttl_seconds, created_at, expire_at, confirmed_at,
             cancelled_at, expired_at, buckets_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?)
        """,
        (
            reservation_id, digest,
            json.dumps(payload, ensure_ascii=False), status,
            tenant_id or EMPTY, route_id or EMPTY,
            float(cost), int(ttl_seconds), now_iso, expire_at,
            json.dumps(bucket_keys, ensure_ascii=False),
        ),
    )
    row = conn.execute(
        f"SELECT {_RESERVATION_COLS} FROM reservations WHERE reservation_id=?",
        (reservation_id,),
    ).fetchone()
    return _reservation_out(conn, row, replayed=False, now=now)


def confirm_reservation(
    conn: sqlite3.Connection, reservation_id: str
) -> dict[str, Any]:
    """确认预占：pending -> confirmed，仅翻转状态，不再扣减任何余额。

    确认与到期竞争时以事务内时间为准、到期优先：若 expire_at 已到，先在同一
    事务内转为 expired 并返还，再返回 409。
    重复确认已 confirmed 的预占幂等（不改变余额）；
    cancelled / expired / rejected 上的确认返回 409；未知 ID 返回 404。
    """
    now = now_utc()
    if _expire_one_if_due(conn, reservation_id, now):
        raise HTTPException(
            409, f"reservation_id={reservation_id!r} 已到期（expired），无法确认"
        )
    row = conn.execute(
        f"SELECT {_RESERVATION_COLS} FROM reservations WHERE reservation_id=?",
        (reservation_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(404, f"reservation_id={reservation_id!r} 不存在")
    if row["status"] == "confirmed":
        return _reservation_out(conn, row, replayed=True, now=now)
    if row["status"] != "pending":
        raise HTTPException(
            409,
            f"reservation_id={reservation_id!r} 当前状态为 {row['status']!r}，"
            "只有 pending 预占可以确认",
        )
    now_iso = iso(now)
    cur = conn.execute(
        "UPDATE reservations SET status='confirmed', confirmed_at=? "
        "WHERE reservation_id=? AND status='pending' AND expire_at > ?",
        (now_iso, reservation_id, now_iso),
    )
    if cur.rowcount == 0:
        # 并发兜底：本事务持有写锁，期间无其他写者能改此行，理论上不可达
        raise HTTPException(
            409, f"reservation_id={reservation_id!r} 已到期（expired），无法确认"
        )
    row = conn.execute(
        f"SELECT {_RESERVATION_COLS} FROM reservations WHERE reservation_id=?",
        (reservation_id,),
    ).fetchone()
    return _reservation_out(conn, row, replayed=False, now=now)


def cancel_reservation(
    conn: sqlite3.Connection, reservation_id: str
) -> dict[str, Any]:
    """取消预占：pending -> cancelled，并在同一事务内向原命中桶返还 cost。

    返还沿用当前补充与定时策略切换规则（先计息/切换，再加 cost），最终余额
    不超过桶当前容量。动桶前先做全局到期清扫：本预占若已到期会先变 expired
    （且已返还）再返回 409——到期优先。
    重复取消已 cancelled 的预占幂等（不再次返还、不改变余额）；
    confirmed / expired / rejected 上的取消返回 409；未知 ID 返回 404。
    """
    now = now_utc()
    # 余额写操作：先把所有到期 pending 预占（可能含本预占）转为 expired 并返还
    _expire_due_reservations(conn, now)

    row = conn.execute(
        f"SELECT {_RESERVATION_COLS} FROM reservations WHERE reservation_id=?",
        (reservation_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(404, f"reservation_id={reservation_id!r} 不存在")
    if row["status"] == "cancelled":
        return _reservation_out(conn, row, replayed=True, now=now)
    if row["status"] != "pending":
        raise HTTPException(
            409,
            f"reservation_id={reservation_id!r} 当前状态为 {row['status']!r}，"
            "只有 pending 预占可以取消",
        )

    now_iso = iso(now)
    cur = conn.execute(
        "UPDATE reservations SET status='cancelled', cancelled_at=? "
        "WHERE reservation_id=? AND status='pending' AND expire_at > ?",
        (now_iso, reservation_id, now_iso),
    )
    if cur.rowcount == 0:
        # 事务开头的全局清扫之后不可能再到期；防御性 409
        raise HTTPException(
            409, f"reservation_id={reservation_id!r} 已到期（expired），无法取消"
        )
    _refund_to_buckets(
        conn, _reservation_bucket_keys(row), float(row["cost"]), now
    )
    row = conn.execute(
        f"SELECT {_RESERVATION_COLS} FROM reservations WHERE reservation_id=?",
        (reservation_id,),
    ).fetchone()
    return _reservation_out(conn, row, replayed=False, now=now)


def get_reservation(
    conn: sqlite3.Connection, reservation_id: str
) -> dict[str, Any]:
    """查询预占状态及到期时间；若该预占恰好到期，先在同一事务内清理为
    expired 并向原桶返还（惰性推进），随后返回 expired 终态。

    只处理被查询的这一条，不做全局清扫（GET 不触碰其他桶/预占）。
    终态行可反复查询，重复调用不改变余额。未知 ID 返回 404。
    """
    now = now_utc()
    _expire_one_if_due(conn, reservation_id, now)
    row = conn.execute(
        f"SELECT {_RESERVATION_COLS} FROM reservations WHERE reservation_id=?",
        (reservation_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(404, f"reservation_id={reservation_id!r} 不存在")
    return _reservation_out(conn, row, replayed=False, now=now)
