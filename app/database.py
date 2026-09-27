"""SQLite 连接管理与建表。

写事务统一使用 BEGIN IMMEDIATE 抢占写锁；配合 busy_timeout，
无论单进程多线程还是多 worker 部署，同一时刻只有一个写者，
保证裁决/撤销的读-改-写序列不会交错超发。
"""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

# 所有策略层（全局 / 租户 / 路由）的公共行
# scope: 'global' | 'tenant' | 'route'
# low_balance_threshold: NULL 表示关闭低余额事件；否则取值须在 [0, capacity]
SCHEMA = """
CREATE TABLE IF NOT EXISTS policies (
    scope         TEXT NOT NULL,
    tenant_id     TEXT NOT NULL DEFAULT '',
    route_id      TEXT NOT NULL DEFAULT '',
    capacity      REAL NOT NULL CHECK (capacity >= 0),
    refill_rate   REAL NOT NULL CHECK (refill_rate >= 0),
    low_balance_threshold REAL
        CHECK (low_balance_threshold IS NULL OR low_balance_threshold >= 0),
    updated_at    TEXT NOT NULL,
    PRIMARY KEY (scope, tenant_id, route_id)
) STRICT;

-- 令牌桶惰性补充：仅在被裁决/撤销命中时才按经过时间补充并落库
CREATE TABLE IF NOT EXISTS buckets (
    scope         TEXT NOT NULL,
    tenant_id     TEXT NOT NULL DEFAULT '',
    route_id      TEXT NOT NULL DEFAULT '',
    balance       REAL NOT NULL CHECK (balance >= 0),
    updated_at    TEXT NOT NULL,
    PRIMARY KEY (scope, tenant_id, route_id)
) STRICT;

-- 裁决结果按 request_id 幂等存档
CREATE TABLE IF NOT EXISTS decisions (
    request_id        TEXT PRIMARY KEY,
    payload_hash      TEXT NOT NULL,
    payload_json      TEXT NOT NULL,
    allowed           INTEGER NOT NULL,
    cost              REAL NOT NULL,
    decided_at        TEXT NOT NULL,
    retry_at          TEXT,
    retry_after_secs  REAL,
    result_json       TEXT NOT NULL,
    revoked           INTEGER NOT NULL DEFAULT 0,
    revoked_at        TEXT
) STRICT;

-- 批量裁决结果按 batch_id 幂等存档（无论整批提交还是失败都保存）。
-- committed=1：全部条目获准，单笔裁决同时写入 decisions；
-- committed=0：failed_index 处条目不足或 request_id 已存在，桶余额/普通裁决/
-- 低余额事件均未改变（业务事务已整体回滚），result_json 保存失败时该条目桶状态。
-- batch_id 与完整载荷（payload_hash）一一对应：同键异载荷由业务层返回 409。
CREATE TABLE IF NOT EXISTS decide_batches (
    batch_id     TEXT PRIMARY KEY,
    payload_hash TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    committed    INTEGER NOT NULL CHECK (committed IN (0, 1)),
    failed_index INTEGER,
    result_json  TEXT NOT NULL,
    decided_at   TEXT NOT NULL
) STRICT;

-- 低余额事件：获准裁决令某桶从阈值之上降至不高于阈值时，
-- 与扣减在同一事务内写入；id 自增，作为 /events 分页的稳定游标
CREATE TABLE IF NOT EXISTS low_balance_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scope          TEXT NOT NULL,
    tenant_id      TEXT NOT NULL DEFAULT '',
    route_id       TEXT NOT NULL DEFAULT '',
    balance_before REAL NOT NULL,
    balance_after  REAL NOT NULL,
    threshold      REAL NOT NULL,
    request_id     TEXT NOT NULL,
    created_at     TEXT NOT NULL
) STRICT;

-- 策略定时切换：一条变更在 effective_at 到期后，由下一次命中该策略的
-- 裁决在同一写事务内惰性应用（无后台任务）。status 生命周期：
-- pending -> applied（已应用）/ cancelled（生效前取消）
CREATE TABLE IF NOT EXISTS policy_changes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    change_id    TEXT NOT NULL UNIQUE,
    scope        TEXT NOT NULL,
    tenant_id    TEXT NOT NULL DEFAULT '',
    route_id     TEXT NOT NULL DEFAULT '',
    new_capacity REAL NOT NULL CHECK (new_capacity >= 0),
    new_refill_rate REAL NOT NULL CHECK (new_refill_rate >= 0),
    new_low_balance_threshold REAL
        CHECK (new_low_balance_threshold IS NULL OR new_low_balance_threshold >= 0),
    effective_at TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'applied', 'cancelled')),
    created_at   TEXT NOT NULL,
    applied_at   TEXT,
    cancelled_at TEXT
) STRICT;

-- 同一策略至多一条待生效变更（应用/取消后可再提交新的）
CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_changes_one_pending
ON policy_changes (scope, tenant_id, route_id)
WHERE status = 'pending';

-- 策略版本审计：每次 PUT /policies 成功、定时切换实际生效、回滚成功，
-- 都在同一写事务内追加一条不可变记录（版本号在同一策略内单调递增）。
-- source: put（PUT /policies）| scheduled（定时切换到期生效）
--       | rollback（POST /policies/rollback）| baseline（老库迁移补登）
-- change_id 仅 scheduled 版本有值；restored_from_version 仅 rollback 版本有值。
-- 只追加不修改不删除，故不建外键约束，保证审计链永不因级联而缺失。
CREATE TABLE IF NOT EXISTS policy_versions (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    scope                   TEXT NOT NULL,
    tenant_id               TEXT NOT NULL DEFAULT '',
    route_id                TEXT NOT NULL DEFAULT '',
    version                 INTEGER NOT NULL CHECK (version >= 1),
    capacity                REAL NOT NULL CHECK (capacity >= 0),
    refill_rate             REAL NOT NULL CHECK (refill_rate >= 0),
    low_balance_threshold   REAL
        CHECK (low_balance_threshold IS NULL OR low_balance_threshold >= 0),
    source                  TEXT NOT NULL
        CHECK (source IN ('put', 'scheduled', 'rollback', 'baseline')),
    change_id               TEXT,
    restored_from_version   INTEGER,
    created_at              TEXT NOT NULL
) STRICT;

-- 版本历史按策略键查询、版本号单调；同策略版本号唯一
CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_versions_key_version
ON policy_versions (scope, tenant_id, route_id, version);

-- 审计表只追加：触发器在数据库层拒绝任何 UPDATE / DELETE（含手工 SQL），
-- 版本链一旦写入即不可篡改
CREATE TRIGGER IF NOT EXISTS trg_policy_versions_no_update
BEFORE UPDATE ON policy_versions
BEGIN
    SELECT RAISE(ABORT, 'policy_versions 为只追加的不可变审计表，禁止 UPDATE');
END;

CREATE TRIGGER IF NOT EXISTS trg_policy_versions_no_delete
BEFORE DELETE ON policy_versions
BEGIN
    SELECT RAISE(ABORT, 'policy_versions 为只追加的不可变审计表，禁止 DELETE');
END;

-- 配额预占（reservation）：创建时在同一写事务内对全部命中桶预扣 cost，
-- 并把命中桶键快照存入 buckets_json，供取消/到期按原桶返还。
-- status 生命周期：
--   pending   -> confirmed（确认，仅状态翻转，余额不变）
--              -> cancelled（取消，向原命中桶返还 cost）
--              -> expired（到期未确认，惰性转为 expired 并向原桶返还）
--   rejected  为创建即拒绝的终态（余额未扣），可同载荷重放、不可确认/取消
-- 没有后台任务：到期 pending 由下一次余额写操作（或该预占自身的确认/查询）
-- 在同一 BEGIN IMMEDIATE 事务内惰性转 expired 并返还。
CREATE TABLE IF NOT EXISTS reservations (
    reservation_id TEXT PRIMARY KEY,
    payload_hash   TEXT NOT NULL,
    payload_json   TEXT NOT NULL,
    status         TEXT NOT NULL
                   CHECK (status IN ('pending', 'confirmed', 'cancelled',
                                     'expired', 'rejected')),
    tenant_id      TEXT NOT NULL DEFAULT '',
    route_id       TEXT NOT NULL DEFAULT '',
    cost           REAL NOT NULL CHECK (cost > 0),
    ttl_seconds    INTEGER NOT NULL CHECK (ttl_seconds BETWEEN 1 AND 300),
    created_at     TEXT NOT NULL,
    expire_at      TEXT NOT NULL,
    confirmed_at   TEXT,
    cancelled_at   TEXT,
    expired_at     TEXT,
    -- 创建时命中桶键列表的 JSON（[["global","",""], ...]），返还时按此定位原桶
    buckets_json   TEXT NOT NULL
) STRICT;

-- 到期清扫只扫描 pending 行（部分索引），expire_at 与 ISO 8601 UTC 文本可直接字典序比较
CREATE INDEX IF NOT EXISTS idx_reservations_due
ON reservations (expire_at)
WHERE status = 'pending';

-- 管理写接口（PUT /policies、POST /policies/rollback、
-- POST /policy-changes、DELETE /policy-changes/{id}）的 HMAC 防重放 nonce。
-- 与 key_id 联合唯一：同一 key 在保留窗口（expires_at，300 秒）内重用 -> 409；
-- 过期行在每次认证写入前于同一事务内清理。登记必须与业务写入同事务提交，
-- 业务失败回滚时 nonce 行一并撤销（见 app/auth.py reserve_nonce）。
CREATE TABLE IF NOT EXISTS admin_nonces (
    key_id     TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (key_id, nonce)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_admin_nonces_expires
ON admin_nonces (expires_at);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
"""


def db_path() -> str:
    path = os.environ.get("QUOTA_DB_PATH", "/data/quota.db")
    return path


def connect(path: str | None = None) -> sqlite3.Connection:
    """打开一个连接。isolation_level=None 后由我们手动控制事务边界。"""
    target = path or db_path()
    Path(target).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        target,
        isolation_level=None,
        timeout=30.0,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    # WAL + busy_timeout 让并发写者自动排队等待而不是立刻报锁
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(path: str | None = None) -> None:
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        _migrate(conn)
    finally:
        conn.close()


def _migrate(conn: sqlite3.Connection) -> None:
    """老库就地升级：CREATE TABLE IF NOT EXISTS 不会给已有表补新列。"""
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(policies)")}
    if "low_balance_threshold" not in cols:
        conn.execute(
            "ALTER TABLE policies ADD COLUMN low_balance_threshold REAL "
            "CHECK (low_balance_threshold IS NULL OR low_balance_threshold >= 0)"
        )

    # 老库（或上个版本写入的策略）首次升级时，按当前策略为尚无版本记录的
    # 策略补登一条 version=1 的 baseline，时间取策略 updated_at。
    # 之后所有策略版本都从 2 开始单调递增；重复启动幂等。
    conn.execute(
        """
        INSERT INTO policy_versions
            (scope, tenant_id, route_id, version, capacity, refill_rate,
             low_balance_threshold, source, change_id, restored_from_version,
             created_at)
        SELECT p.scope, p.tenant_id, p.route_id, 1, p.capacity, p.refill_rate,
               p.low_balance_threshold, 'baseline', NULL, NULL, p.updated_at
        FROM policies p
        WHERE NOT EXISTS (
            SELECT 1 FROM policy_versions v
            WHERE v.scope = p.scope
              AND v.tenant_id = p.tenant_id
              AND v.route_id = p.route_id
        )
        """
    )


@contextmanager
def write_tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """BEGIN IMMEDIATE 立即获取 RESERVED 锁，把整个读-改-写串行化。"""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


@contextmanager
def read_tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """BEGIN（deferred）只读快照事务。

    WAL 模式下读事务不阻塞写者；事务内的多次 SELECT 看到同一快照，
    供策略影响预演这类「纯内存演算、绝不落库」的接口使用。
    """
    conn.execute("BEGIN")
    try:
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
