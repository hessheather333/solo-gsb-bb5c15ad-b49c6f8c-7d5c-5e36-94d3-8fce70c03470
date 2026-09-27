"""核心行为测试。用 QUOTA_DB_PATH 指向每个测试独立的临时 SQLite 文件。"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

ADMIN_KEY_ID = "test-admin-key"
ADMIN_HMAC_SECRET = "test-admin-secret"


@pytest.fixture()
def client(tmp_path, monkeypatch) -> TestClient:
    db_file = tmp_path / "test.db"
    monkeypatch.setenv("QUOTA_DB_PATH", str(db_file))
    monkeypatch.setenv("ADMIN_KEY_ID", ADMIN_KEY_ID)
    monkeypatch.setenv("ADMIN_HMAC_SECRET", ADMIN_HMAC_SECRET)
    # 延迟导入 app，确保它读到环境变量
    import importlib

    from app import database, main

    importlib.reload(database)
    importlib.reload(main)
    database.init_db(str(db_file))
    with TestClient(main.app) as c:
        yield c


_UNSET = object()


def sign_headers(method: str, target: str, body: bytes, *,
                 key_id: str = ADMIN_KEY_ID, secret: str = ADMIN_HMAC_SECRET,
                 timestamp: int | None = None, nonce: str | None = None) -> dict:
    """按服务端同样的规则构造管理写请求的四个签名头。"""
    ts = str(int(time.time()) if timestamp is None else timestamp)
    nonce = nonce or f"nonce-{time.time_ns()}-{threading.get_ident()}"
    body_hash = hashlib.sha256(body).hexdigest()
    signing = "\n".join([method, target, body_hash, ts, nonce]).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), signing, hashlib.sha256).hexdigest()
    return {
        "X-Key-Id": key_id,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Signature": signature,
    }


def admin_call(client, method, target, payload=None, *, raw_body=None,
               headers=None, **sign_kwargs):
    """发起带 HMAC 签名的管理写请求；签名覆盖实际发出的字节。

    sign_kwargs 可覆盖 nonce / timestamp / key_id / secret（用于重放测试）。
    """
    if raw_body is None:
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
    else:
        body = raw_body
    hdrs = {"Content-Type": "application/json"}
    hdrs.update(sign_headers(method, target, body, **sign_kwargs))
    if headers:
        hdrs.update(headers)
    return client.request(method, target, content=body, headers=hdrs)


def put_policy(client, scope, capacity, refill_rate, tenant=None, route=None,
               threshold=_UNSET):
    body = {
        "scope": scope,
        "tenant_id": tenant,
        "route_id": route,
        "capacity": capacity,
        "refill_rate": refill_rate,
    }
    if threshold is not _UNSET:
        body["low_balance_threshold"] = threshold
    return admin_call(client, "PUT", "/policies", body)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def post_change(client, change_id, scope, capacity, refill_rate, *,
                effective_in=1.0, tenant=None, route=None, threshold=_UNSET):
    body = {
        "change_id": change_id,
        "scope": scope,
        "tenant_id": tenant,
        "route_id": route,
        "capacity": capacity,
        "refill_rate": refill_rate,
        "effective_at": _iso(
            datetime.now(timezone.utc) + timedelta(seconds=effective_in)
        ),
    }
    if threshold is not _UNSET:
        body["low_balance_threshold"] = threshold
    return admin_call(client, "POST", "/policy-changes", body)


def rollback(client, scope, version, tenant=None, route=None):
    return admin_call(
        client,
        "POST",
        "/policies/rollback",
        {
            "scope": scope,
            "tenant_id": tenant,
            "route_id": route,
            "version": version,
        },
    )


def history(client, scope, **params):
    return client.get("/policies/history", params={"scope": scope, **params})


# ------------------------------------------------------------ 基本扣减与拒绝


def test_allow_and_atomic_deny_multilevel(client):
    assert put_policy(client, "global", 5, 0).status_code == 200
    assert put_policy(client, "tenant", 3, 0, tenant="t1").status_code == 200
    assert (
        put_policy(client, "route", 4, 0, tenant="t1", route="rA").status_code == 200
    )

    r = client.post(
        "/decide",
        json={"request_id": "d1", "tenant_id": "t1", "route_id": "rA", "cost": 3},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["allowed"] is True
    assert body["replayed"] is False
    by_scope = {b["scope"]: b["balance"] for b in body["buckets"]}
    assert by_scope == {"global": 2.0, "tenant": 0.0, "route": 1.0}

    # 租户桶已空 -> 拒绝；全局/路由桶一个都不应被扣
    r = client.post(
        "/decide",
        json={"request_id": "d2", "tenant_id": "t1", "route_id": "rA", "cost": 1},
    )
    body = r.json()
    assert body["allowed"] is False
    assert body["retry_possible"] is False  # refill_rate=0 永不可能
    assert body["retry_at"] is None
    by_scope = {b["scope"]: b["balance"] for b in body["buckets"]}
    assert by_scope == {"global": 2.0, "tenant": 0.0, "route": 1.0}


def test_deny_does_not_deduct_any_bucket(client):
    put_policy(client, "global", 2, 0)
    put_policy(client, "tenant", 10, 0, tenant="t")
    r = client.post(
        "/decide", json={"request_id": "x", "tenant_id": "t", "cost": 3}
    ).json()
    assert r["allowed"] is False
    # 全局桶容量只有 2，但绝不能被扣成负数
    global_b = [b for b in r["buckets"] if b["scope"] == "global"][0]
    tenant_b = [b for b in r["buckets"] if b["scope"] == "tenant"][0]
    assert global_b["balance"] == 2.0
    assert tenant_b["balance"] == 10.0


# ------------------------------------------------------------ 时间补充与重试时间


def test_refill_over_time(client):
    put_policy(client, "global", 10, 10)  # 10 令牌/秒
    # 连续打空
    for i in range(10):
        r = client.post("/decide", json={"request_id": f"e{i}", "cost": 1}).json()
        assert r["allowed"] is True
    r = client.post("/decide", json={"request_id": "e-empty", "cost": 1}).json()
    assert r["allowed"] is False
    assert r["retry_possible"] is True
    assert r["retry_after_seconds"] == pytest.approx(0.1, abs=0.25)
    import time

    time.sleep(0.3)
    r = client.post("/decide", json={"request_id": "e-refill", "cost": 1}).json()
    assert r["allowed"] is True


def test_retry_time_is_max_across_buckets(client):
    # 先打一笔 cost=6：全局 6->0（缺 4 @4/s=1s），租户 8->2（缺 2 @2/s=1s）
    # 再请求 cost=4 被拒，整组最早可重试时间取最大值 1s
    put_policy(client, "global", 6, 4)
    put_policy(client, "tenant", 8, 2, tenant="t")
    client.post("/decide", json={"request_id": "a", "tenant_id": "t", "cost": 6})
    r = client.post(
        "/decide", json={"request_id": "b", "tenant_id": "t", "cost": 4}
    ).json()
    assert r["allowed"] is False
    assert r["retry_after_seconds"] == pytest.approx(1.0, abs=0.5)
    assert r["retry_at"] is not None


def test_cost_above_capacity_means_impossible(client):
    put_policy(client, "global", 3, 10)
    r = client.post("/decide", json={"request_id": "big", "cost": 5}).json()
    assert r["allowed"] is False
    assert r["retry_possible"] is False
    assert r["retry_at"] is None


# -------------------------------------------- 重试时间预测与待生效的策略切换


def test_retry_prediction_pending_change_makes_retry_possible(client):
    # 当前速率 0：只看当前策略会判 retry_possible=false；但 60s 后切换到
    # 2/s，切换后约 2 秒补足 4 个 -> 应给出约 62s 后的重试时间
    put_policy(client, "global", 10, 0)
    client.post("/decide", json={"request_id": "a", "cost": 10})  # 打空
    post_change(client, "chg", "global", 10, 2, effective_in=60)
    r = client.post("/decide", json={"request_id": "b", "cost": 4}).json()
    assert r["allowed"] is False
    assert r["retry_possible"] is True
    assert r["retry_after_seconds"] == pytest.approx(62, abs=1.5)
    decided = datetime.fromisoformat(r["decided_at"].replace("Z", "+00:00"))
    retry = datetime.fromisoformat(r["retry_at"].replace("Z", "+00:00"))
    assert (retry - decided).total_seconds() == pytest.approx(62, abs=1.5)
    # 预测不提前应用切换：响应与桶观察仍是旧策略，变更保持 pending
    assert r["buckets"][0]["capacity"] == 10.0
    assert r["buckets"][0]["refill_rate"] == 0.0
    assert client.get("/buckets").json()[0]["capacity"] == 10.0
    assert client.get("/policy-changes/chg").json()["status"] == "pending"


def test_retry_prediction_capacity_raise_allows_oversized_cost(client):
    # cost 超过当前容量（只看当前策略必判不可能），但 30s 后容量升到 10：
    # 桶满额 3 创建，换算 3/3*10=10 >= 5，切换时刻即就绪
    put_policy(client, "global", 3, 0)
    post_change(client, "chg", "global", 10, 1, effective_in=30)
    r = client.post("/decide", json={"request_id": "big", "cost": 5}).json()
    assert r["allowed"] is False
    assert r["retry_possible"] is True
    assert r["retry_after_seconds"] == pytest.approx(30, abs=1.5)


def test_retry_prediction_scales_balance_at_switch(client):
    # 余 50/100（剩余比例 0.5），10s 后切到容量 200、速率 0：
    # 换算后 0.5*200=100 >= 80，切换时刻即就绪（旧速率 0 本会被判不可能）
    put_policy(client, "global", 100, 0)
    client.post("/decide", json={"request_id": "a", "cost": 50})
    post_change(client, "chg", "global", 200, 0, effective_in=10)
    r = client.post("/decide", json={"request_id": "b", "cost": 80}).json()
    assert r["allowed"] is False
    assert r["retry_possible"] is True
    assert r["retry_after_seconds"] == pytest.approx(10, abs=1.5)


def test_retry_prediction_old_rate_until_switch_then_new_rate(client):
    # 旧速率 10/s，5s 后切换为 1/s：切换前补到约 50（比例 0.5 -> 50），
    # 之后按 1/s 再补 30 -> 约 35s，而不是按旧速率直算的 8s
    put_policy(client, "global", 100, 10)
    client.post("/decide", json={"request_id": "a", "cost": 100})  # 打空
    post_change(client, "chg", "global", 100, 1, effective_in=5)
    r = client.post("/decide", json={"request_id": "b", "cost": 80}).json()
    assert r["allowed"] is False
    assert r["retry_possible"] is True
    assert r["retry_after_seconds"] == pytest.approx(35, abs=2.0)


def test_retry_impossible_when_switch_shrinks_sibling_bucket(client):
    # 租户桶约 5s 就绪；但全局桶 1s 后切换到容量 2 < cost 5 且新速率 0，
    # 此后永远不足 -> 不存在同时足额的时刻，retry_possible=false
    put_policy(client, "global", 100, 0)
    put_policy(client, "tenant", 10, 1, tenant="t")
    client.post("/decide", json={"request_id": "a", "tenant_id": "t", "cost": 10})
    post_change(client, "chg", "global", 2, 0, effective_in=1)
    r = client.post(
        "/decide", json={"request_id": "b", "tenant_id": "t", "cost": 5}
    ).json()
    assert r["allowed"] is False
    assert r["retry_possible"] is False
    assert r["retry_at"] is None
    assert r["retry_after_seconds"] is None


def test_retry_prediction_replay_returns_stored_result(client):
    # 拒绝结果（含按切换推算的重试时间）随裁决存档，重放原样返回、不再推算
    put_policy(client, "global", 10, 0)
    client.post("/decide", json={"request_id": "a", "cost": 10})
    post_change(client, "chg", "global", 10, 2, effective_in=60)
    denied = client.post("/decide", json={"request_id": "b", "cost": 4}).json()
    assert denied["allowed"] is False and denied["retry_possible"] is True
    replay = client.post("/decide", json={"request_id": "b", "cost": 4}).json()
    assert replay["replayed"] is True
    assert replay["retry_at"] == denied["retry_at"]
    assert replay["retry_after_seconds"] == denied["retry_after_seconds"]
    # 重放不消耗令牌、不应用切换
    assert client.get("/policy-changes/chg").json()["status"] == "pending"


# ------------------------------------------------------------ 幂等


def test_idempotent_replay_same_payload(client):
    put_policy(client, "global", 1, 0)
    payload = {"request_id": "id1", "cost": 1}
    first = client.post("/decide", json=payload).json()
    assert first["allowed"] is True
    second = client.post("/decide", json=payload).json()
    assert second["allowed"] is True
    assert second["replayed"] is True
    # 余额没有因为“再来一次”被扣两次
    assert second["buckets"][0]["balance"] == 0.0
    assert second["decided_at"] == first["decided_at"]


def test_idempotent_replay_denied(client):
    put_policy(client, "global", 1, 0)
    client.post("/decide", json={"request_id": "n1", "cost": 1})
    denied = client.post(
        "/decide", json={"request_id": "n2", "cost": 1}
    ).json()
    assert denied["allowed"] is False
    replay = client.post(
        "/decide", json={"request_id": "n2", "cost": 1}
    ).json()
    assert replay["allowed"] is False
    assert replay["replayed"] is True


def test_payload_conflict_returns_409(client):
    put_policy(client, "global", 100, 0)
    client.post("/decide", json={"request_id": "k1", "cost": 1})
    r = client.post("/decide", json={"request_id": "k1", "cost": 2})
    assert r.status_code == 409


# ------------------------------------------------------------ 撤销


def test_revoke_refunds_and_is_idempotent(client):
    put_policy(client, "global", 10, 0)
    put_policy(client, "tenant", 10, 0, tenant="t")
    client.post(
        "/decide", json={"request_id": "rv", "tenant_id": "t", "cost": 4}
    )
    r = client.post("/decide/rv/revoke")
    assert r.status_code == 200
    body = r.json()
    assert body["revoked"] is True
    assert all(b["balance"] == 10.0 for b in body["buckets"])

    # 重复撤销幂等
    r2 = client.post("/decide/rv/revoke")
    assert r2.status_code == 200
    assert r2.json()["revoked"] is True

    # 令牌已补回，新的裁决可以通过；不会因为撤销两次而多出令牌
    ok = client.post(
        "/decide", json={"request_id": "rv-next", "tenant_id": "t", "cost": 10}
    ).json()
    assert ok["allowed"] is True


def test_revoke_refund_capped_at_capacity(client):
    put_policy(client, "global", 10, 100)  # 高补充率：撤销前桶可能早已回满
    client.post("/decide", json={"request_id": "c1", "cost": 3})
    body = client.post("/decide/c1/revoke").json()
    assert all(b["balance"] <= b["capacity"] for b in body["buckets"])
    assert body["buckets"][0]["balance"] == 10.0


def test_revoke_denied_decision_conflicts(client):
    put_policy(client, "global", 1, 0)
    client.post("/decide", json={"request_id": "ok", "cost": 1})
    client.post("/decide", json={"request_id": "no", "cost": 1})
    r = client.post("/decide/no/revoke")
    assert r.status_code == 409


def test_revoke_unknown_404(client):
    assert client.post("/decide/nope/revoke").status_code == 404


# ------------------------------------------------------------ 策略更新


def test_policy_update_clamps_balance(client):
    put_policy(client, "global", 100, 0)
    client.post("/decide", json={"request_id": "p1", "cost": 10})
    # 容量缩小到 5：余额 90 被截断到 5
    put_policy(client, "global", 5, 0)
    r = client.post("/decide", json={"request_id": "p2", "cost": 6}).json()
    assert r["allowed"] is False  # 5 < 6，且 rate=0
    assert r["buckets"][0]["balance"] == 5.0


# ------------------------------------------------------------ 并发不超发


def test_concurrent_decisions_never_overspend(client):
    capacity = 50
    put_policy(client, "global", capacity, 0)

    n_threads, per_thread = 20, 5
    results: list[bool] = []
    lock = threading.Lock()

    def worker(idx):
        for i in range(per_thread):
            body = client.post(
                "/decide",
                json={"request_id": f"c-{idx}-{i}", "cost": 1},
            ).json()
            with lock:
                results.append(body["allowed"])

    threads = [threading.Thread(target=worker, args=(j,)) for j in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 恰好 capacity 个通过，其余拒绝；余额精确为 0，即无超发也无少发
    assert sum(results) == capacity
    buckets = client.get("/buckets").json()
    assert buckets[0]["balance"] == 0


def test_concurrent_multilevel_never_overspend(client):
    put_policy(client, "global", 30, 0)
    put_policy(client, "tenant", 12, 0, tenant="t")
    results: list[bool] = []
    lock = threading.Lock()

    def worker(idx):
        for i in range(5):
            body = client.post(
                "/decide",
                json={"request_id": f"m-{idx}-{i}", "tenant_id": "t", "cost": 1},
            ).json()
            with lock:
                results.append(body["allowed"])

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(results) == 12  # 租户桶上限 12，不可能更多
    buckets = {b["scope"]: b["balance"] for b in client.get("/buckets").json()}
    assert buckets["tenant"] == 0
    assert buckets["global"] == 30 - 12


def test_validation_errors(client):
    # route 必须带 tenant
    r = client.post("/decide", json={"request_id": "v", "route_id": "r", "cost": 1})
    assert r.status_code == 422
    # 无策略可命中
    r = client.post("/decide", json={"request_id": "v2", "cost": 1})
    assert r.status_code == 404
    # cost 必须为正
    r = client.post("/decide", json={"request_id": "v3", "cost": 0})
    assert r.status_code == 422


# ------------------------------------------------------------ 低余额事件


def test_threshold_validation(client):
    # 负数、超过 capacity 都非法
    assert put_policy(client, "global", 10, 0, threshold=-0.1).status_code == 422
    assert put_policy(client, "global", 10, 0, threshold=10.5).status_code == 422
    # null（关闭）、0、等于 capacity 都合法
    assert put_policy(client, "global", 10, 0, threshold=None).status_code == 200
    assert put_policy(client, "global", 10, 0, threshold=0).status_code == 200
    r = put_policy(client, "global", 10, 0, threshold=10)
    assert r.status_code == 200
    assert r.json()["low_balance_threshold"] == 10.0
    # PUT 全量替换：不传字段即关闭
    r = put_policy(client, "global", 10, 0)
    assert r.json()["low_balance_threshold"] is None
    listed = client.get("/policies").json()
    assert listed[0]["low_balance_threshold"] is None


def test_low_balance_event_on_crossing(client):
    put_policy(client, "global", 10, 0, threshold=4)
    # 10 -> 7：仍在阈值之上，无事件
    client.post("/decide", json={"request_id": "lb1", "cost": 3})
    assert client.get("/events").json() == []
    # 7 -> 4：恰好降到阈值（不高于阈值），产生唯一事件
    client.post("/decide", json={"request_id": "lb2", "cost": 3})
    events = client.get("/events").json()
    assert len(events) == 1
    ev = events[0]
    assert ev["id"] == 1
    assert ev["scope"] == "global"
    assert ev["tenant_id"] is None
    assert ev["route_id"] is None
    assert ev["balance_before"] == 7.0
    assert ev["balance_after"] == 4.0
    assert ev["threshold"] == 4.0
    assert ev["request_id"] == "lb2"
    assert ev["created_at"]


def test_no_event_when_already_below_threshold(client):
    put_policy(client, "global", 10, 0, threshold=4)
    client.post("/decide", json={"request_id": "a", "cost": 6})  # 10 -> 4，越线
    client.post("/decide", json={"request_id": "b", "cost": 2})  # 4 -> 2，不越线
    client.post("/decide", json={"request_id": "c", "cost": 2})  # 2 -> 0，不越线
    events = client.get("/events").json()
    assert [e["request_id"] for e in events] == ["a"]


def test_no_event_on_deny_or_replay(client):
    put_policy(client, "global", 5, 0, threshold=2)
    client.post("/decide", json={"request_id": "ok", "cost": 4})  # 5 -> 1，事件
    denied = client.post("/decide", json={"request_id": "no", "cost": 4}).json()
    assert denied["allowed"] is False
    replay = client.post("/decide", json={"request_id": "ok", "cost": 4}).json()
    assert replay["replayed"] is True
    events = client.get("/events").json()
    assert [e["request_id"] for e in events] == ["ok"]


def test_event_rearms_after_refill(client):
    put_policy(client, "global", 10, 100, threshold=5)  # 100 令牌/秒，迅速回满
    client.post("/decide", json={"request_id": "r1", "cost": 8})  # 10 -> 2，事件
    import time

    time.sleep(0.2)  # 时间补充把余额重新抬到阈值之上
    client.post("/decide", json={"request_id": "r2", "cost": 8})  # 再次越线
    events = client.get("/events").json()
    assert [e["request_id"] for e in events] == ["r1", "r2"]
    assert events[0]["id"] < events[1]["id"]


def test_event_rearms_after_revoke(client):
    put_policy(client, "global", 10, 0, threshold=5)
    client.post("/decide", json={"request_id": "v1", "cost": 8})  # 10 -> 2，事件
    client.post("/decide/v1/revoke")  # 撤销补回 -> 10
    client.post("/decide", json={"request_id": "v2", "cost": 8})  # 再次越线
    events = client.get("/events").json()
    assert [e["request_id"] for e in events] == ["v1", "v2"]


def test_event_rearms_after_threshold_lowered(client):
    put_policy(client, "global", 10, 0, threshold=5)
    client.post("/decide", json={"request_id": "t1", "cost": 8})  # 10 -> 2，事件
    # 策略更新把阈值调到 1：余额 2 重新高于阈值
    put_policy(client, "global", 10, 0, threshold=1)
    client.post("/decide", json={"request_id": "t2", "cost": 2})  # 2 -> 0，再越线
    events = client.get("/events").json()
    assert [e["request_id"] for e in events] == ["t1", "t2"]
    assert events[1]["threshold"] == 1.0


def test_multilevel_crossing_emits_one_event_per_bucket(client):
    put_policy(client, "global", 10, 0, threshold=5)
    put_policy(client, "tenant", 8, 0, tenant="acme", threshold=3)
    put_policy(client, "route", 6, 0, tenant="acme", route="/r")  # 阈值关闭
    client.post(
        "/decide",
        json={"request_id": "m1", "tenant_id": "acme", "route_id": "/r", "cost": 6},
    )
    # global 10->4 越线、tenant 8->2 越线、route 未配置阈值 -> 恰好 2 个事件
    events = client.get("/events").json()
    assert [(e["scope"], e["request_id"]) for e in events] == [
        ("global", "m1"),
        ("tenant", "m1"),
    ]
    by_scope = {e["scope"]: e for e in events}
    assert by_scope["global"]["balance_after"] == 4.0
    assert by_scope["tenant"]["balance_after"] == 2.0
    assert by_scope["tenant"]["tenant_id"] == "acme"


def test_events_pagination_stable(client):
    put_policy(client, "global", 3, 0, threshold=0)
    # 打空 -> 撤销补回 -> 再打空，循环 3 次，产生 3 个事件
    for i in range(3):
        client.post("/decide", json={"request_id": f"p{i}", "cost": 3})
        client.post(f"/decide/p{i}/revoke")

    page1 = client.get("/events", params={"limit": 2}).json()
    assert [e["id"] for e in page1] == [1, 2]
    page2 = client.get(
        "/events", params={"after_id": page1[-1]["id"], "limit": 2}
    ).json()
    assert [e["id"] for e in page2] == [3]
    page3 = client.get(
        "/events", params={"after_id": page2[-1]["id"], "limit": 2}
    ).json()
    assert page3 == []
    # 参数校验
    assert client.get("/events", params={"after_id": -1}).status_code == 422
    assert client.get("/events", params={"limit": 0}).status_code == 422


def test_old_database_is_migrated(tmp_path):
    """老库（policies 无 low_balance_threshold 列）init_db 后读写正常。"""
    import sqlite3

    from app import database, quota

    db_file = tmp_path / "old.db"
    conn = sqlite3.connect(str(db_file))
    conn.execute(
        "CREATE TABLE policies ("
        "  scope TEXT NOT NULL, tenant_id TEXT NOT NULL DEFAULT '',"
        "  route_id TEXT NOT NULL DEFAULT '', capacity REAL NOT NULL,"
        "  refill_rate REAL NOT NULL, updated_at TEXT NOT NULL,"
        "  PRIMARY KEY (scope, tenant_id, route_id)) STRICT"
    )
    conn.execute(
        "INSERT INTO policies VALUES ('global', '', '', 10, 1, '2026-01-01T00:00:00Z')"
    )
    conn.commit()
    conn.close()

    database.init_db(str(db_file))
    conn = database.connect(str(db_file))
    try:
        policies = quota.list_policies(conn)
        # 老数据阈值视为关闭；新列可正常 upsert
        quota.upsert_policy(
            conn, scope="global", tenant_id=None, route_id=None,
            capacity=10, refill_rate=1, low_balance_threshold=5,
        )
        updated = quota.list_policies(conn)
    finally:
        conn.close()
    assert policies[0]["low_balance_threshold"] is None
    assert updated[0]["low_balance_threshold"] == 5.0


# ------------------------------------------------------------ 策略定时切换


def test_policy_change_lifecycle_and_conflicts(client):
    put_policy(client, "global", 100, 0)

    # 成功登记
    r = post_change(client, "ch1", "global", 50, 10, threshold=5,
                    effective_in=3600)
    assert r.status_code == 200
    body = r.json()
    assert body["change_id"] == "ch1"
    assert body["status"] == "pending"
    assert body["capacity"] == 50.0
    assert body["refill_rate"] == 10.0
    assert body["low_balance_threshold"] == 5.0
    assert body["effective_at"].endswith("Z")
    assert body["applied_at"] is None and body["cancelled_at"] is None

    # 同一策略第二条 pending -> 409
    assert post_change(client, "ch2", "global", 10, 0,
                       effective_in=3600).status_code == 409
    # change_id 重复 -> 409（即使指向另一策略）
    put_policy(client, "tenant", 5, 0, tenant="t")
    r = post_change(client, "ch1", "tenant", 5, 0, tenant="t",
                    effective_in=3600)
    assert r.status_code == 409
    # pending 期间 PUT 更新该策略 -> 409
    assert put_policy(client, "global", 200, 0).status_code == 409
    # 未涉及 pending 变更的其他策略仍可更新
    assert put_policy(client, "tenant", 6, 0, tenant="t").status_code == 200

    # 列表 / 查询 / 过滤
    assert client.get("/policy-changes").json()[0]["change_id"] == "ch1"
    pending = client.get("/policy-changes", params={"status": "pending"}).json()
    assert [c["change_id"] for c in pending] == ["ch1"]
    assert client.get(
        "/policy-changes", params={"scope": "global", "status": "applied"}
    ).json() == []
    assert client.get("/policy-changes/ch1").status_code == 200
    assert client.get("/policy-changes/missing").status_code == 404

    # 取消后：PUT 恢复、可再提交；重复取消幂等
    r = admin_call(client, "DELETE", "/policy-changes/ch1")
    assert r.status_code == 200 and r.json()["status"] == "cancelled"
    assert r.json()["cancelled_at"]
    assert admin_call(client, "DELETE", "/policy-changes/ch1").json()["status"] == "cancelled"
    assert put_policy(client, "global", 200, 0).status_code == 200
    r = post_change(client, "ch1b", "global", 50, 10, effective_in=3600)
    assert r.status_code == 200


def test_policy_change_validation(client):
    put_policy(client, "global", 100, 0)
    put_policy(client, "tenant", 10, 0, tenant="t")

    # 目标策略不存在 -> 404
    r = post_change(client, "x", "tenant", 5, 0, tenant="nope",
                    effective_in=10)
    assert r.status_code == 404
    # 非法 scope 组合 / 越界阈值 -> 422
    r = post_change(client, "x", "tenant", 5, 0, effective_in=10)
    assert r.status_code == 422
    r = post_change(client, "x", "global", 10, 0, threshold=11,
                    effective_in=10)
    assert r.status_code == 422
    # effective_at 必须是未来（带签名通过认证后才到 422 校验）
    r = admin_call(client, "POST", "/policy-changes", {
        "change_id": "x", "scope": "global", "capacity": 10, "refill_rate": 0,
        "effective_at": _iso(datetime.now(timezone.utc) - timedelta(seconds=5)),
    })
    assert r.status_code == 422
    # effective_at 必须显式带时区
    r = admin_call(client, "POST", "/policy-changes", {
        "change_id": "x", "scope": "global", "capacity": 10, "refill_rate": 0,
        "effective_at": "2026-10-01T00:00:00",
    })
    assert r.status_code == 422
    # 未知 status 过滤值 -> 422
    assert client.get("/policy-changes", params={"status": "wat"}).status_code == 422


def test_decide_before_effective_keeps_old_policy(client):
    put_policy(client, "global", 100, 0)
    post_change(client, "ch1", "global", 50, 0, threshold=10, effective_in=3600)
    # 未到生效时刻：容量/速率/阈值全按旧策略走
    r = client.post("/decide", json={"request_id": "d1", "cost": 100}).json()
    assert r["allowed"] is True
    assert r["buckets"][0]["capacity"] == 100.0
    assert r["buckets"][0]["balance"] == 0.0
    assert client.get("/policy-changes/ch1").json()["status"] == "pending"
    # 桶观察接口同样仍是旧容量
    assert client.get("/buckets").json()[0]["capacity"] == 100.0


def test_change_application_scales_balance_proportionally(client):
    # 旧容量 100、速率 0；花掉 20 -> 剩余比例 0.8
    put_policy(client, "global", 100, 0)
    client.post("/decide", json={"request_id": "d1", "cost": 20})
    post_change(client, "ch1", "global", 50, 0, effective_in=1)

    import time
    time.sleep(1.2)
    # 到期首次裁决：余额应换算为 0.8*50 = 40；速率仍为 0
    r = client.post("/decide", json={"request_id": "d2", "cost": 40}).json()
    assert r["allowed"] is True
    b = r["buckets"][0]
    assert b["capacity"] == 50.0
    assert b["refill_rate"] == 0.0
    assert b["balance"] == pytest.approx(0.0, abs=1e-9)
    ch = client.get("/policy-changes/ch1").json()
    assert ch["status"] == "applied" and ch["applied_at"]
    # applied 后可以提交新的 pending，也可以直接 PUT
    assert post_change(client, "ch2", "global", 10, 0,
                       effective_in=3600).status_code == 200
    assert admin_call(client, "DELETE", "/policy-changes/ch2").status_code == 200
    assert put_policy(client, "global", 50, 0).status_code == 200


def test_change_application_refills_old_then_new_rate(client):
    # 旧容量 100、速率 10；花掉 80（余 20）。变更在 1s 后生效 -> 旧速率先补满
    # 到 30（20+10*1）；新容量 200 -> 余额 60；随后按新速率 20/s 继续补充。
    put_policy(client, "global", 100, 10)
    client.post("/decide", json={"request_id": "d1", "cost": 80})
    post_change(client, "ch1", "global", 200, 20, effective_in=1)

    import time
    time.sleep(1.3)
    r = client.post("/decide", json={"request_id": "d2", "cost": 1}).json()
    assert r["allowed"] is True
    b = r["buckets"][0]
    assert b["capacity"] == 200.0
    assert b["refill_rate"] == 20.0
    # 60 + 20*（裁决时刻-effective_at 约 0.3s+）- 1，区间断言避开计时抖动
    assert 63.0 < b["balance"] < 75.0, b["balance"]


def test_change_from_zero_capacity_balance_starts_zero(client):
    # 旧容量 0：被拒裁决也会把余额 0 的桶行落库；规格规定旧容量为 0 时余额为 0，
    # 故切换后余额从 0 开始按「新速率」补充（而不是凭空按新容量满额）
    put_policy(client, "global", 0, 0)
    r = client.post("/decide", json={"request_id": "d1", "cost": 1}).json()
    assert r["allowed"] is False
    assert client.get("/buckets").json()[0]["balance"] == 0.0
    post_change(client, "ch1", "global", 10, 100, effective_in=1)

    import time
    time.sleep(1.15)
    # 生效瞬间余额 0，新速率 100/s 补充到裁决时刻，已回满到新容量 10
    r = client.post("/decide", json={"request_id": "d2", "cost": 10}).json()
    assert r["allowed"] is True
    assert r["buckets"][0]["capacity"] == 10.0
    assert r["buckets"][0]["balance"] == 0.0


def test_change_with_old_capacity_zero_and_existing_bucket(client):
    # 旧容量 0 但桶行已存在（先非零打空再 PUT 成 0）：换算后余额必须为 0
    put_policy(client, "global", 5, 0)
    client.post("/decide", json={"request_id": "d1", "cost": 5})
    put_policy(client, "global", 0, 0)
    post_change(client, "ch1", "global", 100, 0, effective_in=1)

    import time
    time.sleep(1.2)
    r = client.post("/decide", json={"request_id": "d2", "cost": 1}).json()
    assert r["allowed"] is False
    assert r["buckets"][0]["balance"] == 0.0


def test_change_threshold_applies_after_effective(client):
    put_policy(client, "global", 100, 0)
    client.post("/decide", json={"request_id": "d1", "cost": 50})  # 余 50，旧阈值关闭
    post_change(client, "ch1", "global", 100, 0, threshold=10, effective_in=1)

    import time
    time.sleep(1.2)
    # 50 -> 45：仍高于新阈值 10，无事件
    client.post("/decide", json={"request_id": "d2", "cost": 5})
    assert client.get("/events").json() == []
    # 45 -> 5：越过新阈值，产生事件，事件记录的是新阈值
    client.post("/decide", json={"request_id": "d3", "cost": 40})
    events = client.get("/events").json()
    assert len(events) == 1
    assert events[0]["threshold"] == 10.0
    assert events[0]["balance_before"] == 45.0
    assert events[0]["balance_after"] == 5.0


def test_change_application_is_multilevel_and_atomic(client):
    put_policy(client, "global", 100, 0)
    put_policy(client, "tenant", 100, 0, tenant="t")
    client.post("/decide", json={"request_id": "d1", "tenant_id": "t", "cost": 50})
    post_change(client, "cg", "global", 10, 0, effective_in=1)
    post_change(client, "ct", "tenant", 10, 0, tenant="t", effective_in=1)

    import time
    time.sleep(1.2)
    # 同一裁决事务同时应用两条变更：两桶余额都按 0.5 比例缩到 5
    r = client.post(
        "/decide", json={"request_id": "d2", "tenant_id": "t", "cost": 5}
    ).json()
    assert r["allowed"] is True
    by_scope = {b["scope"]: b["balance"] for b in r["buckets"]}
    assert by_scope == {"global": 0.0, "tenant": 0.0}
    statuses = {c["change_id"]: c["status"] for c in client.get(
        "/policy-changes").json()}
    assert statuses == {"cg": "applied", "ct": "applied"}


def test_concurrent_decisions_apply_change_consistently(client):
    # 旧容量 100 满额 -> 2s 后切换为容量 50（满额比例 1 => 50），速率始终 0。
    # 阶段一在生效前打 60 个：全部按旧策略放行，余 40（无任何请求看到新策略）；
    # 等切换到期后阶段二并发打 60 个：新容量余额 50/100*50=20，只能再放 20。
    # 每个请求看到的要么全旧要么全新，总扣减恰好 80，绝不超发。
    put_policy(client, "global", 100, 0)
    post_change(client, "cg", "global", 50, 0, effective_in=2)

    results: list[bool] = []
    caps: list[float] = []
    lock = threading.Lock()

    def worker(prefix, n):
        for i in range(n):
            body = client.post(
                "/decide", json={"request_id": f"{prefix}-{i}", "cost": 1}
            ).json()
            with lock:
                results.append(body["allowed"])
                caps.append(body["buckets"][0]["capacity"])

    t1 = [threading.Thread(target=worker, args=(f"b{j}", 15)) for j in range(4)]
    for t in t1:
        t.start()
    for t in t1:
        t.join()
    assert all(cap == 100.0 for cap in caps), caps
    assert sum(results) == 60

    import time
    time.sleep(2.2)  # 等待生效

    t2 = [threading.Thread(target=worker, args=(f"a{j}", 15)) for j in range(4)]
    for t in t2:
        t.start()
    for t in t2:
        t.join()

    # 生效后的请求全部看到新容量（不会出现旧状态/中间态）
    assert all(cap == 50.0 for cap in caps[60:]), caps[60:]
    assert sum(results) == 80
    buckets = client.get("/buckets").json()
    assert buckets[0]["capacity"] == 50.0
    assert buckets[0]["balance"] == 0.0
    assert client.get("/policy-changes/cg").json()["status"] == "applied"


def test_revoke_applies_due_change_before_refund(client):
    # 旧容量 100 速率 0：花掉 80（余 20）；1s 后切到容量 50、速率 100。
    # 到期后先撤销：变更应在撤销事务内先应用（余额 20/100*50=10），
    # 再按新速率补充并补回 80，最终以新容量 50 截断 -> 恰好 50
    put_policy(client, "global", 100, 0)
    client.post("/decide", json={"request_id": "d1", "cost": 80})
    post_change(client, "ch1", "global", 50, 100, effective_in=1)

    import time
    time.sleep(1.15)
    r = client.post("/decide/d1/revoke")
    assert r.status_code == 200
    b = r.json()["buckets"][0]
    assert b["capacity"] == 50.0
    assert b["refill_rate"] == 100.0
    assert b["balance"] == 50.0
    assert client.get("/policy-changes/ch1").json()["status"] == "applied"


def test_cancel_after_effective_time_conflicts(client):
    put_policy(client, "global", 100, 0)
    post_change(client, "ch1", "global", 50, 0, effective_in=1)
    assert admin_call(client, "DELETE", "/policy-changes/ch1").status_code == 200
    # 取消后已无 pending，可以重新提交一条
    post_change(client, "ch2", "global", 50, 0, effective_in=1)

    import time
    time.sleep(1.2)
    # 到期后取消 -> 409；触发一次裁决令其应用
    assert admin_call(client, "DELETE", "/policy-changes/ch2").status_code == 409
    client.post("/decide", json={"request_id": "d1", "cost": 1})
    assert client.get("/policy-changes/ch2").json()["status"] == "applied"
    assert admin_call(client, "DELETE", "/policy-changes/ch2").status_code == 409


# ------------------------------------------------------------ 策略版本审计与回滚


def test_put_appends_monotonic_versions_and_history(client):
    r = put_policy(client, "global", 100, 0, threshold=10)
    assert r.status_code == 200
    put_policy(client, "global", 50, 1, threshold=5)
    put_policy(client, "tenant", 8, 2, tenant="t", threshold=1)

    h = history(client, "global").json()
    # 新到旧：version 2 在前
    assert [v["version"] for v in h] == [2, 1]
    v2, v1 = h
    assert v1["source"] == "put"
    assert v1["capacity"] == 100.0 and v1["refill_rate"] == 0.0
    assert v1["low_balance_threshold"] == 10.0
    assert v1["change_id"] is None and v1["restored_from_version"] is None
    assert v1["created_at"]
    assert v2["capacity"] == 50.0 and v2["refill_rate"] == 1.0
    assert v2["low_balance_threshold"] == 5.0
    # 历史只含该策略：tenant 策略不在 global 历史里
    assert all(v["scope"] == "global" for v in h)
    th = history(client, "tenant", tenant_id="t").json()
    assert [v["version"] for v in th] == [1]
    assert th[0]["capacity"] == 8.0
    assert th[0]["tenant_id"] == "t" and th[0]["route_id"] is None
    # PUT 为全量替换：不传阈值即关闭，也应有独立版本
    put_policy(client, "global", 50, 1)
    assert history(client, "global").json()[0]["low_balance_threshold"] is None


def test_history_filters_by_policy_key(client):
    put_policy(client, "global", 10, 0)
    put_policy(client, "tenant", 10, 0, tenant="t1")
    put_policy(client, "route", 10, 0, tenant="t1", route="rA")
    # 不同策略键各自独立计数
    assert history(client, "global").json()[0]["version"] == 1
    assert history(client, "tenant", tenant_id="t1").json()[0]["version"] == 1
    assert history(client, "route", tenant_id="t1", route_id="rA").json()[0][
        "version"
    ] == 1
    # scope 必传 / 非法组合 -> 422
    assert client.get("/policies/history").status_code == 422
    assert client.get(
        "/policies/history", params={"scope": "wat"}
    ).status_code == 422
    assert history(client, "tenant").status_code == 422
    assert history(client, "route", tenant_id="t1").status_code == 422
    # 从未创建过的策略：历史为空（不报错）
    assert history(client, "tenant", tenant_id="nope").json() == []


def test_rollback_restores_parameters_and_appends_version(client):
    put_policy(client, "global", 100, 0, threshold=10)  # v1
    put_policy(client, "global", 50, 1, threshold=5)    # v2
    put_policy(client, "global", 20, 2)                 # v3

    r = rollback(client, "global", 1)
    assert r.status_code == 200
    nv = r.json()
    assert nv["version"] == 4
    assert nv["source"] == "rollback"
    assert nv["restored_from_version"] == 1
    assert nv["capacity"] == 100.0
    assert nv["refill_rate"] == 0.0
    assert nv["low_balance_threshold"] == 10.0
    # 策略本身已恢复
    p = client.get("/policies").json()[0]
    assert p["capacity"] == 100.0 and p["refill_rate"] == 0.0
    assert p["low_balance_threshold"] == 10.0
    # 历史新到旧，回滚版本在最前
    h = history(client, "global").json()
    assert [v["version"] for v in h] == [4, 3, 2, 1]
    assert h[0]["source"] == "rollback"
    assert h[1]["source"] == "put"
    # 回滚后裁决按恢复后的策略走：容量 100
    d = client.post("/decide", json={"request_id": "d1", "cost": 100}).json()
    assert d["allowed"] is True
    assert d["buckets"][0]["balance"] == 0.0


def test_rollback_clamps_existing_bucket_to_target_capacity(client):
    # v1 容量 20、速率 0：花掉 5 -> 余 15；v2 容量 100、速率 100。
    # v2 生效后桶被补满到 100；回滚到 v1（容量 20）时先按当前策略补充，
    # 再截断回 20。
    put_policy(client, "global", 20, 0)
    client.post("/decide", json={"request_id": "d1", "cost": 5})
    put_policy(client, "global", 100, 100)

    import time
    time.sleep(1.0)
    # 一次裁决把补充后的高余额落库：补满到 100 再扣 1 -> 99
    d = client.post("/decide", json={"request_id": "d2", "cost": 1}).json()
    assert d["allowed"] is True
    assert d["buckets"][0]["balance"] == 99.0

    assert rollback(client, "global", 1).status_code == 200
    b = client.get("/buckets").json()[0]
    assert b["capacity"] == 20.0
    assert b["balance"] == 20.0


def test_rollback_refills_with_current_policy_before_clamp(client):
    # 当前容量 100、速率 100，回滚目标容量 200（放大）：
    # 先按当前策略补充（上限 100），再截到 200 -> 100（不是目标容量 200）。
    put_policy(client, "global", 200, 0)                    # v1
    client.post("/decide", json={"request_id": "d1", "cost": 150})  # 余 50
    put_policy(client, "global", 100, 100)                  # v2，落库余额 50
    import time
    time.sleep(0.7)  # 50 + 100*0.7 = 120 -> 按当前容量封顶 100
    r = rollback(client, "global", 1)
    assert r.status_code == 200
    assert client.get("/buckets").json()[0]["balance"] == 100.0


def test_rollback_errors(client):
    put_policy(client, "global", 10, 0)
    # 未知策略 -> 404
    assert rollback(client, "tenant", 1, tenant="nope").status_code == 404
    # 未知版本 -> 404
    assert rollback(client, "global", 99).status_code == 404
    assert rollback(client, "global", 0).status_code == 422
    # 非法 scope 组合 -> 422
    assert rollback(client, "tenant", 1).status_code == 422


def test_rollblock_blocked_by_pending_change(client):
    put_policy(client, "global", 100, 0)  # v1
    put_policy(client, "global", 50, 0)   # v2
    post_change(client, "ch1", "global", 20, 0, effective_in=3600)
    # 有 pending：回滚 409，策略与历史不变
    r = rollback(client, "global", 1)
    assert r.status_code == 409
    p = client.get("/policies").json()[0]
    assert p["capacity"] == 50.0
    assert [v["version"] for v in history(client, "global").json()] == [2, 1]
    # 取消后可以回滚
    assert admin_call(client, "DELETE", "/policy-changes/ch1").status_code == 200
    assert rollback(client, "global", 1).status_code == 200


def test_scheduled_change_application_appends_version(client):
    put_policy(client, "global", 100, 0)  # v1 put
    post_change(client, "ch1", "global", 50, 0, effective_in=1)
    assert [v["version"] for v in history(client, "global").json()] == [1]

    import time
    time.sleep(1.2)
    client.post("/decide", json={"request_id": "d1", "cost": 1})
    h = history(client, "global").json()
    assert [v["version"] for v in h] == [2, 1]
    v2 = h[0]
    assert v2["source"] == "scheduled"
    assert v2["change_id"] == "ch1"
    assert v2["restored_from_version"] is None
    assert v2["capacity"] == 50.0


def test_rollback_after_scheduled_change(client):
    put_policy(client, "global", 100, 0)  # v1 put
    post_change(client, "ch1", "global", 50, 0, effective_in=1)
    import time
    time.sleep(1.2)
    client.post("/decide", json={"request_id": "d1", "cost": 1})  # v2 scheduled
    # 回到变更前的 v1
    r = rollback(client, "global", 1)
    assert r.status_code == 200
    assert r.json()["source"] == "rollback"
    assert r.json()["restored_from_version"] == 1
    assert client.get("/policies").json()[0]["capacity"] == 100.0
    h = history(client, "global").json()
    assert [v["version"] for v in h] == [3, 2, 1]
    assert [v["source"] for v in h] == ["rollback", "scheduled", "put"]
    # 已应用的变更不受影响，且 applied 后无 pending，回滚不被阻挡
    assert client.get("/policy-changes/ch1").json()["status"] == "applied"


def test_old_database_is_backfilled_with_baseline_versions(tmp_path):
    """老库升级：现有策略补登 version=1 baseline，随后变更从 version 2 递增。"""
    import sqlite3

    from app import database, quota

    db_file = tmp_path / "oldv.db"
    conn = sqlite3.connect(str(db_file))
    conn.execute(
        "CREATE TABLE policies ("
        "  scope TEXT NOT NULL, tenant_id TEXT NOT NULL DEFAULT '',"
        "  route_id TEXT NOT NULL DEFAULT '', capacity REAL NOT NULL,"
        "  refill_rate REAL NOT NULL, updated_at TEXT NOT NULL,"
        "  PRIMARY KEY (scope, tenant_id, route_id)) STRICT"
    )
    conn.execute(
        "INSERT INTO policies VALUES ('global', '', '', 10, 1, '2026-01-01T00:00:00Z')"
    )
    conn.commit()
    conn.close()

    database.init_db(str(db_file))
    conn = database.connect(str(db_file))
    try:
        from app.database import write_tx

        with write_tx(conn):
            h = quota.list_policy_versions(conn, scope="global")
            assert len(h) == 1
            assert h[0]["version"] == 1
            assert h[0]["source"] == "baseline"
            assert h[0]["capacity"] == 10.0
            assert h[0]["created_at"] == "2026-01-01T00:00:00Z"
            # baseline 可直接作为回滚目标
            rolled = quota.rollback_policy(
                conn, scope="global", tenant_id=None, route_id=None, version=1
            )
            assert rolled["version"] == 2
            assert rolled["source"] == "rollback"
            assert rolled["restored_from_version"] == 1
        # 再次 init_db 幂等：不重复补登
        database.init_db(str(db_file))
        with write_tx(conn):
            h2 = quota.list_policy_versions(conn, scope="global")
        assert [v["version"] for v in h2] == [2, 1]
        assert sum(v["source"] == "baseline" for v in h2) == 1
    finally:
        conn.close()


def test_policy_versions_are_append_only(tmp_path):
    """审计表在数据库层拒绝 UPDATE / DELETE（触发器）。"""
    import sqlite3

    from app import database, quota

    db_file = tmp_path / "imm.db"
    database.init_db(str(db_file))
    conn = database.connect(str(db_file))
    try:
        with database.write_tx(conn):
            quota.upsert_policy(
                conn, scope="global", tenant_id=None, route_id=None,
                capacity=10, refill_rate=1,
            )
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("UPDATE policy_versions SET capacity=999 WHERE version=1")
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("DELETE FROM policy_versions WHERE version=1")
        # 记录完好无损，且仍可继续追加
        with database.write_tx(conn):
            quota.upsert_policy(
                conn, scope="global", tenant_id=None, route_id=None,
                capacity=11, refill_rate=1,
            )
        rows = conn.execute(
            "SELECT version, capacity FROM policy_versions ORDER BY version"
        ).fetchall()
        assert [(r[0], r[1]) for r in rows] == [(1, 10.0), (2, 11.0)]
    finally:
        conn.close()

# ------------------------------------------------------------ 批量裁决


def post_batch(client, batch_id, requests_):
    return client.post(
        "/decide-batches", json={"batch_id": batch_id, "requests": requests_}
    )


def test_batch_all_allowed_commits_in_array_order(client):
    # 全局桶 10、速率 0；两笔 4 + 6 恰好打空，前项余额供后项使用
    put_policy(client, "global", 10, 0)
    r = post_batch(client, "b1", [
        {"request_id": "q1", "cost": 4},
        {"request_id": "q2", "cost": 6},
    ])
    assert r.status_code == 200
    body = r.json()
    assert body["committed"] is True
    assert body["replayed"] is False
    assert body["failed_index"] is None and body["failure"] is None
    assert [x["index"] for x in body["results"]] == [0, 1]
    assert [x["request_id"] for x in body["results"]] == ["q1", "q2"]
    assert body["results"][0]["buckets"][0]["balance"] == 6.0
    assert body["results"][1]["buckets"][0]["balance"] == 0.0
    # 全部条目同一时刻演算
    assert body["results"][0]["decided_at"] == body["results"][1]["decided_at"]
    # 桶余额已落库
    assert client.get("/buckets").json()[0]["balance"] == 0.0


def test_batch_multilevel_shared_buckets(client):
    put_policy(client, "global", 5, 0)
    put_policy(client, "tenant", 3, 0, tenant="t")
    body = post_batch(client, "b1", [
        {"request_id": "q1", "tenant_id": "t", "cost": 2},
        {"request_id": "q2", "tenant_id": "t", "cost": 1},
    ]).json()
    assert body["committed"] is True
    bal = [
        {b["scope"]: b["balance"] for b in x["buckets"]}
        for x in body["results"]
    ]
    # global: 5->3->2；tenant: 3->1->0
    assert bal == [{"global": 3.0, "tenant": 1.0}, {"global": 2.0, "tenant": 0.0}]
    buckets = {b["scope"]: b["balance"] for b in client.get("/buckets").json()}
    assert buckets == {"global": 2.0, "tenant": 0.0}


def test_batch_insufficient_balance_changes_nothing(client):
    put_policy(client, "global", 10, 0)
    # 先落一个桶行（10 -> 9），随后 6 + 5 = 11 > 9：第二项失败，
    # 前项的模拟扣减不得落库
    client.post("/decide", json={"request_id": "seed", "cost": 1})
    r = post_batch(client, "b1", [
        {"request_id": "q1", "cost": 6},
        {"request_id": "q2", "cost": 5},
    ])
    body = r.json()
    assert body["committed"] is False
    assert body["failed_index"] == 1
    assert body["results"] is None
    failure = body["failure"]
    assert failure["index"] == 1
    assert failure["reason"] == "insufficient_balance"
    assert failure["request_id"] == "q2"
    # 失败快照：前项模拟扣减后的余额 3 供后项使用
    assert failure["buckets"][0]["balance"] == 3.0
    # 业务数据不变：桶仍为 9，无任何 events
    assert client.get("/buckets").json()[0]["balance"] == 9.0
    assert client.get("/events").json() == []
    # 失败批次的 request_id 没有占用：随后可以正常单笔裁决
    ok = client.post("/decide", json={"request_id": "q1", "cost": 6}).json()
    assert ok["allowed"] is True


def test_batch_failed_result_is_persisted_and_replayable(client):
    put_policy(client, "global", 1, 0)
    payload = [{"request_id": "q1", "cost": 2}]
    first = post_batch(client, "b1", payload).json()
    assert first["committed"] is False and first["replayed"] is False
    # 同键同载荷重放：返回存档的失败结果，replayed=true
    second = post_batch(client, "b1", payload).json()
    assert second["committed"] is False
    assert second["replayed"] is True
    assert second["failed_index"] == 0
    assert second["failure"]["reason"] == "insufficient_balance"


def test_batch_same_id_divergent_payload_returns_409(client):
    put_policy(client, "global", 100, 0)
    assert post_batch(client, "b1", [{"request_id": "q1", "cost": 1}]).status_code == 200
    # 改 cost / request_id / 条目数均视为异载荷
    for divergent in (
        [{"request_id": "q1", "cost": 2}],
        [{"request_id": "q2", "cost": 1}],
        [{"request_id": "q1", "cost": 1}, {"request_id": "q2", "cost": 1}],
    ):
        assert post_batch(client, "b1", divergent).status_code == 409
    # 同键同载荷仍可重放
    replay = post_batch(client, "b1", [{"request_id": "q1", "cost": 1}]).json()
    assert replay["committed"] is True and replay["replayed"] is True


def test_batch_failed_then_same_id_divergent_returns_409(client):
    put_policy(client, "global", 1, 0)
    post_batch(client, "b1", [{"request_id": "q1", "cost": 2}])
    assert post_batch(client, "b1", [{"request_id": "q1", "cost": 1}]).status_code == 409


def test_batch_request_id_already_in_decisions(client):
    # 已被单笔裁决占用的 request_id 让整批失败，且不消耗前项
    put_policy(client, "global", 10, 0)
    client.post("/decide", json={"request_id": "old", "cost": 1})
    body = post_batch(client, "b1", [
        {"request_id": "q1", "cost": 1},
        {"request_id": "old", "cost": 1},
    ]).json()
    assert body["committed"] is False
    assert body["failed_index"] == 1
    assert body["failure"]["reason"] == "request_id_exists"
    assert client.get("/buckets").json()[0]["balance"] == 9.0


def test_batch_request_id_from_prior_committed_batch(client):
    put_policy(client, "global", 10, 0)
    post_batch(client, "b1", [{"request_id": "q1", "cost": 1}])
    body = post_batch(client, "b2", [{"request_id": "q1", "cost": 1}]).json()
    assert body["committed"] is False
    assert body["failed_index"] == 0
    assert body["failure"]["reason"] == "request_id_exists"
    # 快照为当前余额（9）
    assert body["failure"]["buckets"][0]["balance"] == 9.0


def test_batch_duplicate_request_id_within_batch(client):
    put_policy(client, "global", 10, 0)
    client.post("/decide", json={"request_id": "seed", "cost": 1})
    body = post_batch(client, "b1", [
        {"request_id": "dup", "cost": 1},
        {"request_id": "dup", "cost": 1},
    ]).json()
    assert body["committed"] is False
    assert body["failed_index"] == 1
    assert body["failure"]["reason"] == "request_id_exists"
    # 整批回滚，桶无变化
    assert client.get("/buckets").json()[0]["balance"] == 9.0


def test_batch_committed_items_replay_and_revoke_via_single_api(client):
    put_policy(client, "global", 10, 0)
    post_batch(client, "b1", [
        {"request_id": "q1", "cost": 4},
        {"request_id": "q2", "cost": 3},
    ])
    # /decide 同载荷重放批次中的单笔裁决：replayed=true，不重复扣减
    replay = client.post("/decide", json={"request_id": "q1", "cost": 4}).json()
    assert replay["allowed"] is True and replay["replayed"] is True
    assert client.get("/buckets").json()[0]["balance"] == 3.0
    # /revoke 撤销批次中的单笔裁决，只补回该笔
    r = client.post("/decide/q2/revoke")
    assert r.status_code == 200
    assert r.json()["revoked"] is True
    assert client.get("/buckets").json()[0]["balance"] == 6.0
    # 重复撤销幂等
    assert client.post("/decide/q2/revoke").json()["revoked"] is True


def test_batch_low_balance_events_only_on_commit(client):
    put_policy(client, "global", 10, 0, threshold=5)
    # 10 -> 8（未越线）-> 3（越过阈值 5）：仅第二项产事件
    body = post_batch(client, "b1", [
        {"request_id": "q1", "cost": 2},
        {"request_id": "q2", "cost": 5},
    ]).json()
    assert body["committed"] is True
    events = client.get("/events").json()
    assert [(e["request_id"], e["balance_before"], e["balance_after"])
            for e in events] == [("q2", 8.0, 3.0)]
    assert events[0]["threshold"] == 5.0

    # 失败批次：模拟中即便越过阈值也不写事件
    failed = post_batch(client, "b2", [
        {"request_id": "q3", "cost": 1},
        {"request_id": "q4", "cost": 5},  # 余额 2，不足
    ]).json()
    assert failed["committed"] is False
    assert len(client.get("/events").json()) == 1


def test_batch_multilevel_events_one_per_crossing_bucket(client):
    put_policy(client, "global", 10, 0, threshold=5)
    put_policy(client, "tenant", 8, 0, tenant="t", threshold=3)
    body = post_batch(client, "b1", [
        {"request_id": "q1", "tenant_id": "t", "cost": 6},
    ]).json()
    assert body["committed"] is True
    # global 10->4、tenant 8->2，两层都越线，各一条
    events = client.get("/events").json()
    assert sorted((e["scope"], e["request_id"]) for e in events) == [
        ("global", "q1"), ("tenant", "q1"),
    ]


def test_batch_applies_due_policy_changes_at_single_instant(client):
    # 旧全局桶 100 速率 0，打掉 80（余 20）后登记 1s 后切到容量 50；
    # 到期后的批次在同一事务先应用切换（20/100*50=10）再演算两项 4+6
    put_policy(client, "global", 100, 0)
    client.post("/decide", json={"request_id": "pre", "cost": 80})
    post_change(client, "cg", "global", 50, 0, effective_in=1)
    import time
    time.sleep(1.2)
    body = post_batch(client, "b1", [
        {"request_id": "q1", "cost": 4},
        {"request_id": "q2", "cost": 6},
    ]).json()
    assert body["committed"] is True
    assert body["results"][0]["buckets"][0]["capacity"] == 50.0
    assert body["results"][0]["buckets"][0]["balance"] == 6.0
    assert body["results"][1]["buckets"][0]["balance"] == 0.0
    assert client.get("/policy-changes/cg").json()["status"] == "applied"
    assert client.get("/buckets").json()[0]["capacity"] == 50.0


def test_batch_failed_leaves_due_change_pending(client):
    # 到期切换虽在批事务内被惰性应用，但整批失败回滚后切换恢复 pending，
    # 桶与策略也保持旧状态（业务数据不变）
    put_policy(client, "global", 5, 0)
    # 先创建桶（5 -> 4），便于回滚后校验桶行未被切换改写
    client.post("/decide", json={"request_id": "seed", "cost": 1})
    post_change(client, "cg", "global", 50, 0, effective_in=1)
    import time
    time.sleep(1.2)
    # cost=99 超过新容量 50：切换后仍必然不足；失败回滚后切换恢复 pending
    body = post_batch(client, "b1", [{"request_id": "q1", "cost": 99}]).json()
    assert body["committed"] is False
    assert body["failure"]["reason"] == "insufficient_balance"
    assert client.get("/policy-changes/cg").json()["status"] == "pending"
    bucket = client.get("/buckets").json()[0]
    assert bucket["capacity"] == 5.0
    assert bucket["balance"] == 4.0
    # 批次失败结果仍已存档
    replay = post_batch(client, "b1", [{"request_id": "q1", "cost": 99}]).json()
    assert replay["replayed"] is True and replay["committed"] is False


def test_batch_validation_errors(client):
    put_policy(client, "global", 1, 0)
    # 空数组 / 超过 50 项 -> 422
    assert post_batch(client, "b", []).status_code == 422
    r = post_batch(client, "b", [
        {"request_id": f"x{i}", "cost": 1} for i in range(51)
    ])
    assert r.status_code == 422
    # batch_id / request_id 为空 -> 422
    assert post_batch(client, "", [{"request_id": "q", "cost": 1}]).status_code == 422
    assert post_batch(client, "b", [{"request_id": "", "cost": 1}]).status_code == 422
    # cost 非正 -> 422
    assert post_batch(client, "b", [{"request_id": "q", "cost": 0}]).status_code == 422
    # route 不带 tenant -> 422
    r = post_batch(client, "b", [
        {"request_id": "q", "route_id": "r", "cost": 1}
    ])
    assert r.status_code == 422


def test_batch_no_matching_policy_returns_404(client):
    # 无任何策略：不保存批次档案（与单笔裁决一致的用法错误）
    r = post_batch(client, "b1", [{"request_id": "q1", "cost": 1}])
    assert r.status_code == 404
    # 同 batch_id 随后可正常使用（先前未存档）
    put_policy(client, "global", 1, 0)
    assert post_batch(client, "b1", [{"request_id": "q1", "cost": 1}]).status_code == 200


def test_batch_remains_anonymous(client):
    # 无签名头即可访问（404 表示已穿过认证层到达业务）
    r = client.post("/decide-batches", json={
        "batch_id": "b", "requests": [{"request_id": "q", "cost": 1}]})
    assert r.status_code == 404


def test_concurrent_batches_never_overspend(client):
    capacity = 50
    put_policy(client, "global", capacity, 0)

    # 20 个线程各提交一个含 5 笔的批次；任一批失败都不得扣减，
    # 全部成功批次的总扣减数恰好为 capacity
    committed_items: list[int] = []
    lock = threading.Lock()

    def worker(idx):
        body = post_batch(client, f"batch-{idx}", [
            {"request_id": f"c-{idx}-{i}", "cost": 1} for i in range(5)
        ]).json()
        with lock:
            if body["committed"]:
                committed_items.append(len(body["results"]))

    threads = [threading.Thread(target=worker, args=(j,)) for j in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(committed_items) == capacity
    assert client.get("/buckets").json()[0]["balance"] == 0


# ------------------------------------------------------------ 管理写接口 HMAC 防重放认证


def test_admin_writes_require_signature(client):
    # 四个管理写接口不带签名头一律 401
    assert client.put("/policies", json={
        "scope": "global", "capacity": 10, "refill_rate": 0}).status_code == 401
    assert client.post("/policies/rollback", json={
        "scope": "global", "version": 1}).status_code == 401
    assert client.post("/policy-changes", json={
        "change_id": "c", "scope": "global", "capacity": 1, "refill_rate": 0,
        "effective_at": _iso(datetime.now(timezone.utc) + timedelta(hours=1)),
    }).status_code == 401
    assert client.delete("/policy-changes/nope").status_code == 401


def test_get_decide_and_revoke_remain_anonymous(client):
    # GET 全部匿名
    assert client.get("/health").status_code == 200
    assert client.get("/policies").status_code == 200
    assert client.get("/policy-changes").status_code == 200
    assert client.get("/buckets").status_code == 200
    assert client.get("/events").status_code == 200
    # 裁决 / 撤销匿名（404 说明已经穿过认证层到达业务）
    assert client.post("/decide", json={
        "request_id": "d", "cost": 1}).status_code == 404
    assert client.post("/decide/nope/revoke").status_code == 404


def test_signed_put_succeeds(client):
    r = admin_call(client, "PUT", "/policies",
                   {"scope": "global", "capacity": 10, "refill_rate": 1})
    assert r.status_code == 200
    assert r.json()["capacity"] == 10.0


def test_missing_or_partial_headers_401(client):
    body = json.dumps({"scope": "global", "capacity": 10, "refill_rate": 0}).encode()
    full = sign_headers("PUT", "/policies", body)
    for drop in ("X-Key-Id", "X-Timestamp", "X-Nonce", "X-Signature"):
        hdrs = {k: v for k, v in full.items() if k != drop}
        hdrs["Content-Type"] = "application/json"
        r = client.request("PUT", "/policies", content=body, headers=hdrs)
        assert r.status_code == 401, drop


def test_wrong_key_id_401(client):
    body = b'{"scope":"global","capacity":10,"refill_rate":0}'
    r = admin_call(client, "PUT", "/policies", raw_body=body,
                   key_id="wrong-key")
    assert r.status_code == 401


def test_wrong_secret_401(client):
    body = b'{"scope":"global","capacity":10,"refill_rate":0}'
    r = admin_call(client, "PUT", "/policies", raw_body=body,
                   secret="a-different-secret")
    assert r.status_code == 401


def test_bad_signature_format_401(client):
    body = b'{"scope":"global","capacity":10,"refill_rate":0}'
    # 大写十六进制不合规（签名值必须是小写 hex）
    hdrs = sign_headers("PUT", "/policies", body)
    hdrs["X-Signature"] = hdrs["X-Signature"].upper()
    r = client.request("PUT", "/policies", content=body, headers=hdrs)
    assert r.status_code == 401
    # 长度不足 / 非 hex
    for bad in ("abc", "z" * 64):
        hdrs2 = sign_headers("PUT", "/policies", body)
        hdrs2["X-Signature"] = bad
        r = client.request("PUT", "/policies", content=body, headers=hdrs2)
        assert r.status_code == 401


def test_tampered_body_or_method_or_path_401(client):
    body = json.dumps({"scope": "global", "capacity": 10, "refill_rate": 0}).encode()
    # 签名覆盖的 body 与实际 body 不一致
    hdrs = sign_headers("PUT", "/policies", body)
    tampered = body.replace(b'"capacity": 10', b'"capacity": 11')
    assert tampered != body
    r = client.request("PUT", "/policies", content=tampered, headers=hdrs)
    assert r.status_code == 401

    # 用另一路径的签名打到 /policies
    hdrs = sign_headers("PUT", "/other", body)
    r = client.request("PUT", "/policies", content=body, headers=hdrs)
    assert r.status_code == 401

    # 用 GET 的方法签名发 PUT
    hdrs = sign_headers("GET", "/policies", body)
    r = client.request("PUT", "/policies", content=body, headers=hdrs)
    assert r.status_code == 401


def test_query_string_is_part_of_signature(client):
    # 路径含查询串时必须把「原始路径及查询串」整体纳入签名
    target = "/policies/history?scope=global"
    # GET 本来就免认证；这里只验证：带查询串计算的签名服务端可复现。
    # 借 DELETE（空 body）在一个不存在的 change_id 上验证：
    # 查询串不参与该路径，因此用 404（业务）vs 401（签名错）区分
    target_del = "/policy-changes/c1?x=1"
    body = b""
    r = admin_call(client, "DELETE", target_del)
    assert r.status_code == 404  # 签名正确（含 ?x=1），只是变更不存在

    # 签名时漏算查询串 -> 401
    hdrs = sign_headers("DELETE", "/policy-changes/c1", body)
    r = client.request("DELETE", target_del, content=body, headers=hdrs)
    assert r.status_code == 401

    # 签名时查询串错误 -> 401
    hdrs = sign_headers("DELETE", "/policy-changes/c1?x=2", body)
    r = client.request("DELETE", target_del, content=body, headers=hdrs)
    assert r.status_code == 401


def test_timestamp_outside_window_401(client):
    now = int(time.time())
    for offset in (-301, 301, 10_000, -10_000):
        r = admin_call(
            client, "PUT", "/policies",
            {"scope": "global", "capacity": 10, "refill_rate": 0},
            timestamp=now + offset,
        )
        assert r.status_code == 401, offset


def test_timestamp_boundary_accepted(client):
    now = int(time.time())
    # 用 ±299 避开 ±300 边界上的毫秒级时钟/调度抖动
    for offset in (-299, 0, 299):
        r = admin_call(
            client, "PUT", "/policies",
            {"scope": "global", "capacity": 10, "refill_rate": 0},
            timestamp=now + offset, nonce=f"n-boundary-{offset}",
        )
        assert r.status_code == 200, (offset, r.status_code)


def test_timestamp_must_be_unix_seconds_401(client):
    body = b'{"scope":"global","capacity":10,"refill_rate":0}'
    # 非数字 / 小数：先正常签名，再把时间戳头替换成非法值
    for bad in ("abc", "1700000000.5", "-12", ""):
        hdrs = sign_headers("PUT", "/policies", body)
        hdrs["X-Timestamp"] = bad
        r = client.request("PUT", "/policies", content=body, headers=hdrs)
        assert r.status_code == 401, bad
    # 11 位数字能过格式检查但远超 ±300 秒窗口
    r = admin_call(
        client, "PUT", "/policies",
        {"scope": "global", "capacity": 10, "refill_rate": 0},
        timestamp=17_000_000_000,
    )
    assert r.status_code == 401


def test_nonce_reuse_same_key_409(client):
    body = {"scope": "global", "capacity": 10, "refill_rate": 0}
    r = admin_call(client, "PUT", "/policies", body, nonce="fixed-nonce")
    assert r.status_code == 200
    # 完全相同的请求 + 相同 nonce：时间戳仍新鲜 -> 409（不是 401）
    r = admin_call(client, "PUT", "/policies", body, nonce="fixed-nonce")
    assert r.status_code == 409
    # 换一个 nonce 即可成功
    r = admin_call(client, "PUT", "/policies", body, nonce="another-nonce")
    assert r.status_code == 200


def test_nonce_reuse_after_expiry_is_allowed(client, tmp_path, monkeypatch):
    """nonce 只在 300 秒窗口内防重放：过期行清理后同一 nonce 可再用。"""
    from app import database

    body = {"scope": "global", "capacity": 10, "refill_rate": 0}
    r = admin_call(client, "PUT", "/policies", body, nonce="expiring-nonce")
    assert r.status_code == 200

    # 直接把该 nonce 的 expires_at 改成已过期
    conn = database.connect()
    try:
        conn.execute(
            "UPDATE admin_nonces SET expires_at=? WHERE nonce='expiring-nonce'",
            (int(time.time()) - 1,),
        )
        conn.commit()
    finally:
        conn.close()

    # 新请求先清理过期行再插入，同一 nonce 可重新使用
    r = admin_call(client, "PUT", "/policies", body, nonce="expiring-nonce")
    assert r.status_code == 200


def test_same_nonce_under_different_key_is_allowed(client, monkeypatch):
    # 先用配置中的 key 成功一次
    body = {"scope": "global", "capacity": 10, "refill_rate": 0}
    r = admin_call(client, "PUT", "/policies", body, nonce="shared-nonce")
    assert r.status_code == 200
    # 另一把 key 使用相同 nonce 字符串：key 不匹配 -> 401（先验 key）
    r = admin_call(client, "PUT", "/policies", body,
                   key_id="other-key", secret="whatever", nonce="shared-nonce")
    assert r.status_code == 401
    # 同一 nonce 在不同 (key, nonce) 组合下隔离：直接验证表结构层面的
    # 组合唯一——用 reserve_nonce 以另一 key 登记不应冲突
    import sqlite3
    from app import database
    from app.auth import reserve_nonce
    conn = database.connect()
    try:
        with database.write_tx(conn):
            reserve_nonce(conn, "other-key", "shared-nonce")
        rows = conn.execute(
            "SELECT key_id FROM admin_nonces WHERE nonce='shared-nonce'"
        ).fetchall()
        assert {r[0] for r in rows} == {ADMIN_KEY_ID, "other-key"}
    finally:
        conn.close()


def test_business_failure_does_not_consume_nonce(client):
    # 业务失败（阈值越界 -> 422）回滚事务，nonce 不应被占用：
    # 修正载荷后用同一 nonce 重试应成功
    bad = {"scope": "global", "capacity": 10, "refill_rate": 0,
           "low_balance_threshold": 11}
    r = admin_call(client, "PUT", "/policies", bad, nonce="n-retry")
    assert r.status_code == 422

    good = {"scope": "global", "capacity": 10, "refill_rate": 0,
            "low_balance_threshold": 1}
    r = admin_call(client, "PUT", "/policies", good, nonce="n-retry")
    assert r.status_code == 200


def test_404_business_failure_does_not_consume_nonce(client):
    # DELETE 不存在的变更 -> 404 回滚；同一 nonce 随后可成功用于合法取消
    r = admin_call(client, "DELETE", "/policy-changes/missing", nonce="n-del")
    assert r.status_code == 404

    put_policy(client, "global", 10, 0)
    post_change(client, "ch1", "global", 5, 0, effective_in=3600)
    r = admin_call(client, "DELETE", "/policy-changes/ch1", nonce="n-del")
    assert r.status_code == 200


def test_duplicate_nonce_rejected_before_business_validation(client):
    # 先用一个合法请求占用 nonce
    body = {"scope": "global", "capacity": 10, "refill_rate": 0}
    assert admin_call(client, "PUT", "/policies", body,
                      nonce="n-dup").status_code == 200
    # 即使本次载荷业务上非法（阈值越界），也先撞 nonce -> 409 而非 422
    bad = {"scope": "global", "capacity": 10, "refill_rate": 0,
           "low_balance_threshold": 99}
    r = admin_call(client, "PUT", "/policies", bad, nonce="n-dup")
    assert r.status_code == 409


def test_replay_identical_signed_request_is_409(client):
    # 完整重放一个已成功的管理请求（含相同签名头与新鲜时间戳）也不能两次生效：
    # 这里固定 nonce，仅刷新时间戳仍因 nonce 已登记而 409
    body = {"scope": "global", "capacity": 10, "refill_rate": 0}
    nonce = "n-once"
    assert admin_call(client, "PUT", "/policies", body, nonce=nonce).status_code == 200
    # 同签名串重放（时间戳也照旧）：nonce 已存在 -> 409
    ts = str(int(time.time()))
    body_b = json.dumps(body).encode()
    hdrs = sign_headers("PUT", "/policies", body_b, timestamp=ts, nonce=nonce)
    hdrs["Content-Type"] = "application/json"
    r = client.request("PUT", "/policies", content=body_b, headers=hdrs)
    assert r.status_code == 409


def test_empty_body_delete_uses_sha256_of_empty(client):
    put_policy(client, "global", 10, 0)
    post_change(client, "ch1", "global", 5, 0, effective_in=3600)
    # DELETE 无请求体：签名时请求体摘要取 sha256(b"")
    r = admin_call(client, "DELETE", "/policy-changes/ch1", nonce="n-empty")
    assert r.status_code == 200
    # 用非空 body 的摘要给空 body 请求签名 -> 401
    ts = str(int(time.time()))
    wrong_hash = hashlib.sha256(b"x").hexdigest()
    signing = "\n".join(
        ["DELETE", "/policy-changes/ch1", wrong_hash, ts, "n-empty2"]
    ).encode()
    sig = hmac.new(ADMIN_HMAC_SECRET.encode(), signing, hashlib.sha256).hexdigest()
    hdrs = {
        "X-Key-Id": ADMIN_KEY_ID, "X-Timestamp": ts,
        "X-Nonce": "n-empty2", "X-Signature": sig,
    }
    r = client.request("DELETE", "/policy-changes/ch1", content=b"", headers=hdrs)
    assert r.status_code == 401


def test_all_four_admin_endpoints_have_nonce_rows(client):
    put_policy(client, "global", 10, 0)
    post_change(client, "ch1", "global", 5, 0, effective_in=3600)
    admin_call(client, "DELETE", "/policy-changes/ch1", nonce="n1")
    # ch1 已取消（无 pending），回滚才合法
    rollback(client, "global", 1)
    post_change(client, "ch2", "global", 5, 0, effective_in=3600)
    admin_call(client, "DELETE", "/policy-changes/ch2", nonce="n2")

    from app import database
    conn = database.connect()
    try:
        n = conn.execute("SELECT COUNT(*) FROM admin_nonces").fetchone()[0]
        # PUT policy + create ch1 + delete ch1 + rollback + create ch2 + delete ch2
        assert n == 6
    finally:
        conn.close()


def test_unconfigured_admin_credentials_503(tmp_path, monkeypatch):
    """未配置 ADMIN_KEY_ID / ADMIN_HMAC_SECRET 时管理接口 fail-closed 503。"""
    import importlib
    from fastapi.testclient import TestClient
    from app import database, main

    db_file = tmp_path / "noconf.db"
    monkeypatch.setenv("QUOTA_DB_PATH", str(db_file))
    monkeypatch.delenv("ADMIN_KEY_ID", raising=False)
    monkeypatch.delenv("ADMIN_HMAC_SECRET", raising=False)
    importlib.reload(database)
    importlib.reload(main)
    database.init_db(str(db_file))
    with TestClient(main.app) as c:
        # 免认证接口不受影响
        assert c.get("/health").status_code == 200
        assert c.post("/decide", json={"request_id": "d", "cost": 1}).status_code == 404
        # 管理接口 503（而非放行）
        r = c.put("/policies", json={
            "scope": "global", "capacity": 1, "refill_rate": 0})
        assert r.status_code == 503


# ------------------------------------------------------------ 策略影响预演


def post_preview(client, scope, capacity, refill_rate, requests,
                 tenant=None, route=None):
    return client.post(
        "/policies/impact-preview",
        json={
            "scope": scope,
            "tenant_id": tenant,
            "route_id": route,
            "capacity": capacity,
            "refill_rate": refill_rate,
            "requests": requests,
        },
    )


def test_impact_preview_two_sides_and_diff(client):
    # 全局桶 10、速率 0；候选容量 4：起点余额截断到 4，后续逐条发散
    put_policy(client, "global", 10, 0)
    r = post_preview(client, "global", 4, 0, [
        {"cost": 3, "at_seconds": 0},
        {"cost": 3, "at_seconds": 10},
        {"cost": 3, "at_seconds": 20},
    ])
    assert r.status_code == 200
    body = r.json()
    assert body["scope"] == "global"
    assert body["tenant_id"] is None and body["route_id"] is None
    assert body["current_capacity"] == 10.0 and body["current_refill_rate"] == 0.0
    assert body["candidate_capacity"] == 4.0 and body["candidate_refill_rate"] == 0.0
    assert "started_at" in body

    items = body["items"]
    assert [it["index"] for it in items] == [0, 1, 2]
    assert [it["at_seconds"] for it in items] == [0.0, 10.0, 20.0]
    # 现行：10 -> 7 -> 4 -> 1，全部获准
    assert [it["current"]["allowed"] for it in items] == [True, True, True]
    assert [it["current"]["buckets"][0]["balance"] for it in items] == [7.0, 4.0, 1.0]
    # 候选：起点截断到 4 -> 1，之后两条均被拒且不扣减
    assert [it["candidate"]["allowed"] for it in items] == [True, False, False]
    assert [it["candidate"]["buckets"][0]["balance"] for it in items] == [1.0, 1.0, 1.0]
    assert [it["allowed_changed"] for it in items] == [False, True, True]
    # 逐条差异：候选桶余额 - 现行桶余额
    diff1 = items[1]["bucket_diffs"][0]
    assert diff1["scope"] == "global"
    assert diff1["current_balance"] == 4.0
    assert diff1["candidate_balance"] == 1.0
    assert diff1["balance_delta"] == -3.0
    assert body["summary"] == {
        "total_items": 3,
        "current_allowed": 3,
        "candidate_allowed": 1,
        "allowed_changed_items": 2,
    }


def test_impact_preview_truncates_initial_balance_to_candidate_capacity(client):
    put_policy(client, "global", 10, 0)
    # 先落一个桶行：10 -> 8（速率 0，余额不再随时间变化）
    client.post("/decide", json={"request_id": "seed", "cost": 2})
    body = post_preview(client, "global", 5, 0, [{"cost": 6, "at_seconds": 0}]).json()
    item = body["items"][0]
    # 现行：起点余额 8，获准后 2；候选：起点截断到 5，不足被拒且不扣减
    assert item["current"]["allowed"] is True
    assert item["current"]["buckets"][0]["balance"] == 2.0
    assert item["candidate"]["allowed"] is False
    assert item["candidate"]["buckets"][0]["balance"] == 5.0
    assert item["allowed_changed"] is True


def test_impact_preview_refills_per_side_over_time(client):
    # 两侧补充速率不同：起点一致，随 at_seconds 推进逐渐拉开
    put_policy(client, "global", 10, 1)
    body = post_preview(client, "global", 10, 0.1, [
        {"cost": 5, "at_seconds": 0},
        {"cost": 5, "at_seconds": 10},
    ]).json()
    items = body["items"]
    # 现行：10-5=5；10 秒后补满 10，再扣 5 -> 5
    assert items[1]["current"]["allowed"] is True
    assert items[1]["current"]["buckets"][0]["balance"] == 5.0
    # 候选：10-5=5；10 秒补 1 -> 6，再扣 5 -> 1
    assert items[1]["candidate"]["allowed"] is True
    assert items[1]["candidate"]["buckets"][0]["balance"] == 1.0
    assert items[1]["allowed_changed"] is False
    assert items[1]["bucket_diffs"][0]["balance_delta"] == -4.0


def test_impact_preview_rejection_does_not_deduct_and_chains(client):
    # 候选侧拒绝不扣减：余额留给后续项，后续项因此获准
    put_policy(client, "global", 5, 0)
    body = post_preview(client, "global", 5, 0, [
        {"cost": 4, "at_seconds": 0},
        {"cost": 2, "at_seconds": 5},
        {"cost": 2, "at_seconds": 5},  # 相同 at_seconds 允许（非递减）
    ]).json()
    items = body["items"]
    # 两侧一致：5-4=1；第二条 1<2 拒绝（余额仍 1）；第三条同样拒绝
    assert [it["current"]["allowed"] for it in items] == [True, False, False]
    assert [it["current"]["buckets"][0]["balance"] for it in items] == [1.0, 1.0, 1.0]
    assert [it["candidate"]["allowed"] for it in items] == [True, False, False]
    assert body["summary"]["allowed_changed_items"] == 0


def test_impact_preview_multilevel_shared_buckets(client):
    put_policy(client, "global", 10, 0)
    put_policy(client, "tenant", 6, 0, tenant="t")
    body = post_preview(client, "tenant", 3, 0, [
        {"tenant_id": "t", "cost": 4, "at_seconds": 0},
        {"tenant_id": "t", "cost": 2, "at_seconds": 10},
    ], tenant="t").json()
    items = body["items"]
    # 现行：item0 获准（global 10->6，tenant 6->2）；item1 获准（4, 0）
    cur0 = {b["scope"]: b["balance"] for b in items[0]["current"]["buckets"]}
    cur1 = {b["scope"]: b["balance"] for b in items[1]["current"]["buckets"]}
    assert cur0 == {"global": 6.0, "tenant": 2.0}
    assert cur1 == {"global": 4.0, "tenant": 0.0}
    # 候选：tenant 截断到 3，item0 cost 4 被拒 -> 两个桶都不扣；
    # item1 时 global 仍 10、tenant 仍 3，获准 -> (8, 1)
    cand0 = {b["scope"]: b["balance"] for b in items[0]["candidate"]["buckets"]}
    cand1 = {b["scope"]: b["balance"] for b in items[1]["candidate"]["buckets"]}
    assert items[0]["candidate"]["allowed"] is False
    assert cand0 == {"global": 10.0, "tenant": 3.0}
    assert items[1]["candidate"]["allowed"] is True
    assert cand1 == {"global": 8.0, "tenant": 1.0}
    # 差异按桶给出：item1 的 global 因候选侧前项未扣减而更高
    diffs = {d["scope"]: d for d in items[1]["bucket_diffs"]}
    assert diffs["global"]["balance_delta"] == 4.0
    assert diffs["tenant"]["balance_delta"] == 1.0


def test_impact_preview_is_read_only(client):
    put_policy(client, "global", 10, 0, threshold=8)
    put_policy(client, "tenant", 6, 0, tenant="t")
    client.post("/decide", json={"request_id": "seed", "tenant_id": "t", "cost": 1})
    before_buckets = client.get("/buckets").json()
    before_events = client.get("/events").json()

    r = post_preview(client, "global", 2, 0, [
        {"tenant_id": "t", "cost": 3, "at_seconds": 0},
        {"tenant_id": "t", "cost": 3, "at_seconds": 30},
    ])
    assert r.status_code == 200
    # 预演不改动桶、裁决与事件：/buckets 与 /events 完全不变
    assert client.get("/buckets").json() == before_buckets
    assert client.get("/events").json() == before_events == []
    # 已存档裁决仍按原样重放（预演没有扣减真实余额）
    replay = client.post(
        "/decide", json={"request_id": "seed", "tenant_id": "t", "cost": 1}
    ).json()
    assert replay["replayed"] is True
    # 预演里「虚拟扣减」不占用真实余额：随后真实裁决按预演前余额裁决
    fresh = client.post(
        "/decide", json={"request_id": "after", "tenant_id": "t", "cost": 5}
    ).json()
    assert fresh["allowed"] is True


def test_impact_preview_unknown_policy_404(client):
    r = post_preview(client, "global", 1, 1, [{"cost": 1, "at_seconds": 0}])
    assert r.status_code == 404
    put_policy(client, "global", 10, 0)
    r = post_preview(client, "tenant", 1, 1, [{"cost": 1, "at_seconds": 0}], tenant="ghost")
    assert r.status_code == 404


def test_impact_preview_pending_change_409(client):
    put_policy(client, "global", 10, 0)
    put_policy(client, "tenant", 6, 0, tenant="t")
    put_policy(client, "tenant", 6, 0, tenant="other")
    post_change(client, "ch-t", "tenant", 9, 1, effective_in=600, tenant="t")

    # 请求命中带 pending 变更的策略 -> 409
    r = post_preview(client, "global", 5, 0, [{"tenant_id": "t", "cost": 1, "at_seconds": 0}])
    assert r.status_code == 409
    # 目标策略自身有 pending 变更，即使请求不命中它 -> 409
    r = post_preview(client, "tenant", 5, 0, [{"cost": 1, "at_seconds": 0}], tenant="t")
    assert r.status_code == 409
    # 无关策略的 pending 变更不影响预演
    post_change(client, "ch-other", "tenant", 9, 1, effective_in=600, tenant="other")
    r = post_preview(client, "global", 5, 0, [{"cost": 1, "at_seconds": 0}])
    assert r.status_code == 200
    # 取消后恢复可预演
    admin_call(client, "DELETE", "/policy-changes/ch-t")
    r = post_preview(client, "global", 5, 0, [{"tenant_id": "t", "cost": 1, "at_seconds": 0}])
    assert r.status_code == 200


def test_impact_preview_validation_422(client):
    put_policy(client, "global", 10, 0)
    # at_seconds 必须非递减
    r = post_preview(client, "global", 1, 1, [
        {"cost": 1, "at_seconds": 10}, {"cost": 1, "at_seconds": 5}])
    assert r.status_code == 422
    # at_seconds 越界（>3600 或 <0）
    assert post_preview(client, "global", 1, 1, [
        {"cost": 1, "at_seconds": 3601}]).status_code == 422
    assert post_preview(client, "global", 1, 1, [
        {"cost": 1, "at_seconds": -1}]).status_code == 422
    # cost 必须为正
    assert post_preview(client, "global", 1, 1, [
        {"cost": 0, "at_seconds": 0}]).status_code == 422
    # route_id 必须带 tenant_id
    assert post_preview(client, "global", 1, 1, [
        {"route_id": "/r", "cost": 1, "at_seconds": 0}]).status_code == 422
    # 请求数 1～50
    assert post_preview(client, "global", 1, 1, []).status_code == 422
    assert post_preview(client, "global", 1, 1, [
        {"cost": 1, "at_seconds": 0}] * 51).status_code == 422
    # 候选容量/速率必须非负
    assert post_preview(client, "global", -1, 1, [
        {"cost": 1, "at_seconds": 0}]).status_code == 422
    assert post_preview(client, "global", 1, -0.5, [
        {"cost": 1, "at_seconds": 0}]).status_code == 422
    # scope=tenant/route 必须带齐策略键
    assert post_preview(client, "tenant", 1, 1, [
        {"cost": 1, "at_seconds": 0}]).status_code == 422
    assert post_preview(client, "route", 1, 1, [
        {"cost": 1, "at_seconds": 0}], tenant="t").status_code == 422
    # 恰好 50 条、at_seconds 边界 0 与 3600 合法
    ok = post_preview(client, "global", 1, 1, [
        {"cost": 1, "at_seconds": 0}] + [{"cost": 1, "at_seconds": 3600}] * 49)
    assert ok.status_code == 200
    assert len(ok.json()["items"]) == 50


def test_impact_preview_item_hitting_no_policy_is_admitted(client):
    # 只配置了租户 t1 的策略；t2 的请求不命中任何已配置层级：
    # 两侧均准入且 buckets 为空（无配额层可限制）
    put_policy(client, "tenant", 6, 0, tenant="t1")
    body = post_preview(client, "tenant", 3, 0, [
        {"tenant_id": "t2", "cost": 100, "at_seconds": 0},
    ], tenant="t1").json()
    item = body["items"][0]
    assert item["current"] == {"allowed": True, "buckets": []}
    assert item["candidate"] == {"allowed": True, "buckets": []}
    assert item["allowed_changed"] is False
    assert item["bucket_diffs"] == []


def test_impact_preview_remains_anonymous(client):
    put_policy(client, "global", 10, 0)
    # 不带任何签名头即可调用（与 GET / 裁决接口一致）
    r = client.post(
        "/policies/impact-preview",
        json={
            "scope": "global", "capacity": 5, "refill_rate": 1,
            "requests": [{"cost": 1, "at_seconds": 0}],
        },
    )
    assert r.status_code == 200


# ============================================================ 配额预占


class _FakeClock:
    """可控的 UTC 时钟：替换 quota.now_utc 后，预占到期判定完全由测试驱动。"""

    def __init__(self, start: datetime):
        self.t = start

    def now(self) -> datetime:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += timedelta(seconds=seconds)


@pytest.fixture()
def clock(client, monkeypatch) -> _FakeClock:
    from app import quota

    clk = _FakeClock(datetime(2026, 9, 27, 12, 0, 0, tzinfo=timezone.utc))
    monkeypatch.setattr(quota, "now_utc", clk.now)
    return clk


def _global_balance(client) -> float:
    rows = client.get("/buckets").json()
    return next(b["balance"] for b in rows if b["scope"] == "global")


def _reserve(client, reservation_id, cost, *, ttl=60, tenant=None, route=None):
    return client.post(
        "/reservations",
        json={
            "reservation_id": reservation_id,
            "tenant_id": tenant,
            "route_id": route,
            "cost": cost,
            "ttl_seconds": ttl,
        },
    )


def test_reservation_deducts_all_hit_buckets_and_saves_origin(client, clock):
    put_policy(client, "global", 10, 0)
    put_policy(client, "tenant", 6, 0, tenant="t1")
    put_policy(client, "route", 4, 0, tenant="t1", route="/r1")

    r = _reserve(client, "rsv-1", 3, ttl=60, tenant="t1", route="/r1")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "pending"
    assert body["allowed"] is True
    assert body["replayed"] is False
    assert body["ttl_seconds"] == 60
    assert body["expire_at"] == "2026-09-27T12:01:00Z"
    assert [b["scope"] for b in body["buckets"]] == ["global", "tenant", "route"]
    assert [b["balance"] for b in body["buckets"]] == [7.0, 3.0, 1.0]

    buckets = {b["scope"]: b["balance"] for b in client.get("/buckets").json()}
    assert buckets["global"] == 7.0
    assert buckets["tenant"] == 3.0
    assert buckets["route"] == 1.0


def test_reservation_insufficient_deducts_nothing_and_is_rejected(client, clock):
    put_policy(client, "global", 10, 0)
    put_policy(client, "tenant", 2, 0, tenant="t1")

    r = _reserve(client, "rsv-x", 3, ttl=60, tenant="t1")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "rejected"
    assert body["allowed"] is False
    # 全部不扣：全局 10 与租户 2 均不变
    assert [b["balance"] for b in body["buckets"]] == [10.0, 2.0]
    assert client.get("/buckets").json()[0]["balance"] == 10.0

    # rejected 是终态：不能确认也不能取消
    assert client.post("/reservations/rsv-x/confirm").status_code == 409
    assert client.post("/reservations/rsv-x/cancel").status_code == 409


def test_reservation_replay_same_payload_and_conflict_409(client, clock):
    put_policy(client, "global", 10, 0)
    b1 = _reserve(client, "rsv-r", 3, ttl=60).json()
    assert b1["replayed"] is False

    b2 = _reserve(client, "rsv-r", 3, ttl=60).json()
    assert b2["replayed"] is True
    assert b2["status"] == "pending"
    assert _global_balance(client) == 7.0  # 重放不重复扣减

    # 异载荷（cost / ttl / tenant / route 任一不同）-> 409
    assert _reserve(client, "rsv-r", 4, ttl=60).status_code == 409
    assert _reserve(client, "rsv-r", 3, ttl=61).status_code == 409

    # rejected 预占同样支持同载荷重放、异载荷 409
    _reserve(client, "rsv-z", 999, ttl=10)
    rep = _reserve(client, "rsv-z", 999, ttl=10).json()
    assert rep["status"] == "rejected"
    assert rep["replayed"] is True
    assert _reserve(client, "rsv-z", 998, ttl=10).status_code == 409


def test_reservation_validation_and_missing_policy(client, clock):
    # 尚无任何策略：载荷校验（422）先于策略命中查找
    # cost 非正
    assert client.post(
        "/reservations",
        json={"reservation_id": "v1", "cost": 0, "ttl_seconds": 60},
    ).status_code == 422
    # ttl 越界
    assert client.post(
        "/reservations",
        json={"reservation_id": "v2", "cost": 1, "ttl_seconds": 0},
    ).status_code == 422
    assert client.post(
        "/reservations",
        json={"reservation_id": "v3", "cost": 1, "ttl_seconds": 301},
    ).status_code == 422
    # 只给 route_id 不给 tenant_id
    assert client.post(
        "/reservations",
        json={"reservation_id": "v4", "route_id": "/r", "cost": 1, "ttl_seconds": 60},
    ).status_code == 422

    # 无任何命中策略 -> 404，且不留存档
    r = _reserve(client, "v5", 1, ttl=60, tenant="nope")
    assert r.status_code == 404
    assert client.get("/reservations/v5").status_code == 404


def test_confirm_only_transitions_without_deduction(client, clock):
    put_policy(client, "global", 10, 0)
    _reserve(client, "rsv-c", 3, ttl=60)
    assert _global_balance(client) == 7.0

    r = client.post("/reservations/rsv-c/confirm")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "confirmed"
    assert body["confirmed_at"] == "2026-09-27T12:00:00Z"
    assert _global_balance(client) == 7.0  # 确认不再扣减

    # 重复确认幂等，不改变余额
    again = client.post("/reservations/rsv-c/confirm").json()
    assert again["status"] == "confirmed"
    assert again["replayed"] is True
    assert _global_balance(client) == 7.0

    # 已确认不可取消（其他终态转换 409）
    assert client.post("/reservations/rsv-c/cancel").status_code == 409
    # 已确认的预占即使时钟走过 expire_at 也保持 confirmed，不返还
    clock.advance(120)
    assert client.get("/reservations/rsv-c").json()["status"] == "confirmed"
    assert _global_balance(client) == 7.0


def test_cancel_refunds_original_buckets_capped_at_capacity(client, clock):
    put_policy(client, "global", 10, 10)  # 10/s，取消时先补充再返还
    put_policy(client, "tenant", 6, 0, tenant="t1")
    _reserve(client, "rsv-k", 3, ttl=60, tenant="t1")
    assert _global_balance(client) == 7.0

    clock.advance(1)  # 全局桶时间补充：7 -> min(10, 7+10) = 10
    r = client.post("/reservations/rsv-k/cancel")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "cancelled"
    assert body["cancelled_at"] == "2026-09-27T12:00:01Z"
    buckets = {b["scope"]: b["balance"] for b in body["buckets"]}
    assert buckets["global"] == 10.0   # 10 + 3 超过容量，截断不超过当前容量
    assert buckets["tenant"] == 6.0    # 3 + 3 = 6（租户速率 0 无补充，恰好回到容量）

    # 重复取消幂等：不再次返还
    again = client.post("/reservations/rsv-k/cancel").json()
    assert again["status"] == "cancelled"
    assert again["replayed"] is True
    assert _global_balance(client) == 10.0
    tenant_bal = next(
        b["balance"] for b in client.get("/buckets").json()
        if b["scope"] == "tenant"
    )
    assert tenant_bal == 6.0

    # 已取消不可确认
    assert client.post("/reservations/rsv-k/confirm").status_code == 409


def test_expiry_wins_over_confirm_at_boundary(client, clock):
    put_policy(client, "global", 10, 0)
    _reserve(client, "rsv-e", 3, ttl=60)
    assert _global_balance(client) == 7.0

    # 恰好到期时刻：expire_at <= now，到期优先于确认
    clock.advance(60)
    r = client.post("/reservations/rsv-e/confirm")
    assert r.status_code == 409
    body = client.get("/reservations/rsv-e").json()
    assert body["status"] == "expired"
    assert body["expired_at"] == "2026-09-27T12:01:00Z"
    assert _global_balance(client) == 10.0  # 到期已返还

    # 到期后确认/取消均 409；重复查询终态不变、余额不变
    assert client.post("/reservations/rsv-e/confirm").status_code == 409
    assert client.post("/reservations/rsv-e/cancel").status_code == 409
    again = client.get("/reservations/rsv-e").json()
    assert again["status"] == "expired"
    assert _global_balance(client) == 10.0


def test_cancel_at_exact_expiry_goes_to_expired_not_cancelled(client, clock):
    put_policy(client, "global", 10, 0)
    _reserve(client, "rsv-ce", 4, ttl=30)
    clock.advance(30)
    # 到期时刻取消：全局清扫先把它转 expired（已返还），随后 409
    assert client.post("/reservations/rsv-ce/cancel").status_code == 409
    body = client.get("/reservations/rsv-ce").json()
    assert body["status"] == "expired"
    assert body["cancelled_at"] is None
    assert _global_balance(client) == 10.0


def test_get_reservation_returns_status_and_expiry_and_cleans_due(client, clock):
    put_policy(client, "global", 10, 0)
    _reserve(client, "rsv-g", 3, ttl=60)

    before = client.get("/reservations/rsv-g").json()
    assert before["status"] == "pending"
    assert before["expire_at"] == "2026-09-27T12:01:00Z"
    assert before["expired_at"] is None
    assert _global_balance(client) == 7.0  # 未到期查询不动余额

    # 到期后查询触发该预占自身的惰性清理：转 expired 并返还
    clock.advance(61)
    after = client.get("/reservations/rsv-g").json()
    assert after["status"] == "expired"
    # expired_at 是惰性转换实际发生的事务时刻（与 policy_changes.applied_at 同语义）
    assert after["expired_at"] == "2026-09-27T12:01:01Z"
    assert _global_balance(client) == 10.0

    assert client.get("/reservations/missing").status_code == 404


def test_balance_write_sweeps_all_due_pending_before_deducting(client, clock):
    put_policy(client, "global", 10, 0)
    _reserve(client, "rsv-1", 3, ttl=10)
    _reserve(client, "rsv-2", 2, ttl=20)
    assert _global_balance(client) == 5.0

    clock.advance(15)  # rsv-1 到期，rsv-2 未到期
    # 裁决是余额写操作：事务内先把 rsv-1 转 expired 并返还 3 -> 8，再扣 4
    r = client.post("/decide", json={"request_id": "d1", "cost": 4})
    assert r.json()["allowed"] is True
    assert _global_balance(client) == 4.0
    assert client.get("/reservations/rsv-1").json()["status"] == "expired"
    assert client.get("/reservations/rsv-2").json()["status"] == "pending"

    # rsv-2 到期后，撤销裁决同样先清扫返还 2（4 -> 6），再补裁决 cost 4 -> 10
    clock.advance(10)
    client.post("/decide/d1/revoke")
    assert _global_balance(client) == 10.0
    assert client.get("/reservations/rsv-2").json()["status"] == "expired"


def test_due_pending_blocks_new_reservation_until_swept(client, clock):
    put_policy(client, "global", 5, 0)
    _reserve(client, "rsv-old", 5, ttl=10)
    assert _global_balance(client) == 0.0
    # 未到期：余额为 0，新预占被拒
    assert _reserve(client, "rsv-new", 1, ttl=10).json()["status"] == "rejected"
    # 到期后的余额写操作先返还 5，新预占即可成功扣 1
    clock.advance(11)
    body = _reserve(client, "rsv-new2", 1, ttl=10).json()
    assert body["status"] == "pending"
    assert _global_balance(client) == 4.0


def test_expired_reservation_replay_does_not_refund_again(client, clock):
    put_policy(client, "global", 10, 0)
    _reserve(client, "rsv-rr", 3, ttl=10)
    clock.advance(11)
    assert client.get("/reservations/rsv-rr").json()["status"] == "expired"
    assert _global_balance(client) == 10.0
    # 同载荷重放只返回 expired 存档，不再返还、状态不再变
    rep = _reserve(client, "rsv-rr", 3, ttl=10)
    assert rep.status_code == 200
    assert rep.json()["status"] == "expired"
    assert rep.json()["replayed"] is True
    assert _global_balance(client) == 10.0


def test_reservation_refund_uses_scheduled_switch_rules(client, clock):
    # 旧策略容量 10、速率 0；预占 4 后余额 6。
    # 10 秒后容量切换为 20：先按旧率补充（6），按比例换算 6/10*20=12，
    # 返还 4 -> 16（不超过新容量 20）。
    from app import quota

    put_policy(client, "global", 10, 0)
    _reserve(client, "rsv-sw", 4, ttl=100)
    assert _global_balance(client) == 6.0

    # 在当前时刻（12:00:00）登记 12:00:10 生效的切换（effective_at 必须严格在未来）
    admin_call(
        client, "POST", "/policy-changes",
        {
            "change_id": "chg-sw", "scope": "global",
            "capacity": 20, "refill_rate": 0,
            "effective_at": _iso(datetime(2026, 9, 27, 12, 0, 10, tzinfo=timezone.utc)),
        },
    )
    clock.advance(10)
    # 取消是余额写操作：事务内先应用到期切换，再按当前规则返还
    body = client.post("/reservations/rsv-sw/cancel").json()
    assert body["status"] == "cancelled"
    assert body["buckets"][0]["capacity"] == 20.0
    assert body["buckets"][0]["balance"] == 16.0


def test_reservation_rejected_when_bucket_missing_after_switch_shrink(client, clock):
    # 到期切换把容量缩到 1 并已生效，cost=2 的新预占必被拒（一个都不扣）
    put_policy(client, "global", 10, 0)
    _reserve(client, "rsv-shrink", 9, ttl=100)
    # 在 12:00:00 登记 12:00:05 生效的缩容切换
    admin_call(
        client, "POST", "/policy-changes",
        {
            "change_id": "chg-shrink", "scope": "global",
            "capacity": 1, "refill_rate": 0,
            "effective_at": _iso(datetime(2026, 9, 27, 12, 0, 5, tzinfo=timezone.utc)),
        },
    )
    clock.advance(5)
    body = _reserve(client, "rsv-after", 2, ttl=10).json()
    assert body["status"] == "rejected"
    # 切换换算：旧余额 1/旧容量 10*新容量 1 = 0.1；拒绝不扣
    assert body["buckets"][0]["capacity"] == 1.0
    assert body["buckets"][0]["balance"] == pytest.approx(0.1)


def test_reservation_apis_remain_anonymous(client):
    put_policy(client, "global", 10, 0)
    # 预占四个接口都不带签名头即可访问
    r = client.post(
        "/reservations",
        json={"reservation_id": "anon-1", "cost": 1, "ttl_seconds": 60},
    )
    assert r.status_code == 200
    assert client.post("/reservations/anon-1/confirm").status_code == 200
    assert client.get("/reservations/anon-1").status_code == 200
    r2 = client.post(
        "/reservations",
        json={"reservation_id": "anon-2", "cost": 1, "ttl_seconds": 60},
    )
    assert r2.status_code == 200
    assert client.post("/reservations/anon-2/cancel").status_code == 200


def test_concurrent_reservations_never_oversell(client):
    # 使用真实时钟与 ttl=300，排除到期清扫干扰；20 线程各预占 1，容量 10
    put_policy(client, "global", 10, 0)
    results: list[bool] = []
    lock = threading.Lock()

    def worker(i: int) -> None:
        r = client.post(
            "/reservations",
            json={
                "reservation_id": f"c-rsv-{i}",
                "cost": 1,
                "ttl_seconds": 300,
            },
        )
        with lock:
            results.append(r.json()["status"] == "pending")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(results) == 10           # 恰好 10 个预占成功
    assert _global_balance(client) == 0.0
