# 多级配额裁决 API（Multi-Level Quota Decider）

使用 **Python 3.11 + FastAPI + SQLite** 实现的本地多级配额裁决服务。
配额策略可分别在 **全局（global）/ 租户（tenant）/ 路由（route）** 三级配置，
每级独立设置桶容量（capacity）与每秒令牌补充率（refill_rate）。

## 核心语义

- **惰性令牌桶**：桶只在被裁决/撤销命中时，按距上次更新经过的时间补充令牌，
  补充量 = `elapsed × refill_rate`，且余额永远不超过桶容量。
- **整组原子裁决**：一次请求命中的所有桶（全局 → 租户 → 路由，缺失的层不限制），
  在**同一个 `BEGIN IMMEDIATE` 事务**、同一个时间戳下完成「补充 → 判足 → 扣减」。
  - 所有桶都足够：全部同时扣减 `cost`，返回 `allowed=true`；
  - 任一桶不足：**一个令牌都不扣**（时间应得的补充仍会落库），返回 `allowed=false`。
- **整组最早可重试时间**：拒绝时，以裁决时刻为起点对**全部命中桶**做纯演算
  （不改动任何落库状态、不提前应用切换）：各桶先按当前策略补充；命中层若
  存在待生效（pending）的定时切换，到 `effective_at` 按
  `旧余额 / 旧容量 × 新容量` 的剩余比例规则换算（旧容量为 `0` 则余额归零），
  此后按新速率补充。取所有命中层**首次同时足额**的时刻作为
  `retry_at` / `retry_after_seconds`；无 pending 切换时即退化为各不足桶
  `(cost - balance) / refill_rate` 的最大值。若某命中层在切换后的最终策略下
  `refill_rate=0` 或 `cost` 超过容量（即无论等多久都不可能同时足额），返回
  `retry_possible=false`、`retry_at=null`。
- **幂等重放**：相同 `request_id` 且裁决载荷（tenant_id / route_id / cost）一致时，
  直接返回原裁决结果（`replayed=true`），不重复扣减；载荷冲突返回 **409**。
  通过与拒绝的裁决都会存档。
- **批量裁决（POST /decide-batches）**：一次提交一个 `batch_id` 与 **1～50** 个
  含 `request_id`、`tenant_id`、`route_id`、`cost` 的请求，整个批次在**一个
  `BEGIN IMMEDIATE` 事务**内完成：
  - 先以**同一时刻**应用所有条目命中且到期的策略定时切换（一次），再**按数组
    顺序**演算共享的多级桶——**前项扣减后的余额供后项使用**；
  - **仅当全部条目获准**时，才写入桶余额、普通裁决（`decisions`）与低余额
    事件；任一项余额不足（`insufficient_balance`）或 `request_id` 已存在
    （含批内重复，`request_id_exists`）时，这些业务数据**一律不变**（业务事务
    整体回滚），返回 `committed=false`、首个失败项下标 `failed_index` 和该项
    **当时**命中桶的状态（已含前项的模拟扣减，但未持久化）；
  - **无论成败批次结果都保存**，按 `batch_id` 对**完整载荷**幂等：同键同载荷
    重放原结果（成功/失败均重放，`replayed=true`）；同键异载荷返回 **409**；
  - 成功批次中的每笔裁决都以其自身的 `request_id` 写入普通裁决存档，仍可由
    `POST /decide`（同载荷重放）查询、由 `POST /decide/{request_id}/revoke`
    撤销；低余额事件的 `request_id` 归属触发它的那个条目；
  - 与单笔裁决相同，批中某条目没有命中任何已配置策略层级时整批返回 **404**。
- **撤销**：可撤销已通过的裁决并向当时命中的桶补回令牌，重复撤销保持幂等；
  补回时同样先补充再退还，最终余额**不超过桶容量**。
- **低余额事件**：策略可配置 `low_balance_threshold`（`null` 关闭，否则须在
  `0` 到 `capacity` 之间）。一次**获准**裁决若令某命中桶的余额
  **从阈值之上降至不高于阈值**，会在扣减的同一事务内为该桶写入唯一一条
  `low_balance` 事件（递增 `id`、桶键、扣减前后余额、阈值、`request_id`、时间）。
  拒绝与幂等重放不产生事件；余额已在阈值之下的继续扣减也不算越线。
  当时间补充、撤销或策略更新（如调低阈值）使余额重新高于阈值后，
  后续再次越线会产生**新**事件。事件通过 `GET /events` 按 `id` 稳定递增分页读取。
- **策略定时切换**：通过 `POST /policy-changes` 为**已存在**的策略提交一条带
  唯一 `change_id` 与未来 UTC 时间 `effective_at` 的变更（新容量、新补充速率、
  新低余额阈值）。同一策略至多有一条**待生效（pending）**变更；该期间
  `PUT /policies` 直接更新该策略会返回 **409**。可在生效前用
  `DELETE /policy-changes/{change_id}` 取消（重复取消幂等）。
  **没有后台任务**：每次裁决在**同一个 `BEGIN IMMEDIATE` 事务内**先应用所有命中且
  到期的变更，再执行原有裁决。应用时：① 先按**旧策略**把余额补充到
  `effective_at`；② 再按 `旧余额 / 旧容量 × 新容量` 保持剩余比例（旧容量为 `0`
  时余额为 `0`）；③ 桶时间锚点移到 `effective_at`，此后按**新速率**继续补充。
  变更落库（换算余额 + 覆盖策略 + 标记 applied）与本次裁决原子完成，
  并发请求只能观察到完整的旧状态或完整的新状态。
- **策略版本审计与回滚**：每次 `PUT /policies` 成功、定时切换**实际生效**、
  回滚成功，都会在**同一写事务内**追加一条**不可变**版本记录（同策略
  `version` 从 1 开始单调递增），内容包含完整参数（容量/速率/阈值）、
  变更来源（`put` / `scheduled` / `rollback`，老库升级补登为 `baseline`）、
  关联信息（定时变更的 `change_id`、回滚的 `restored_from_version`）与时间。
  `GET /policies/history` 按 `scope` + `tenant_id` + `route_id` 查询，
  新版本在前；`POST /policies/rollback` 提交策略键与目标 `version`，
  在**同一 `BEGIN IMMEDIATE` 写事务**内恢复该版本参数，已有桶先按**当前**
  策略补充到事务时刻、再按目标容量截断，并追加一条 `source=rollback` 的新版本。
  策略存在 `pending` 定时变更时回滚返回 **409**；未知策略或版本返回 **404**。
- **策略影响预演（POST /policies/impact-preview）**：对一个**已存在**的策略键
  提交候选 `capacity` / `refill_rate`，以及 **1～50** 条含 `tenant_id`、
  `route_id`、`cost`、`at_seconds` 的请求（`at_seconds` 为相对预演起点的
  **0～3600** 秒，必须按**非递减**顺序提交）。服务在**同一只读快照**内把所有
  涉及桶按**现行**策略补充到预演起点，再构建**现行 / 候选**两套独立内存
  状态——候选侧仅替换指定策略，并把该桶起点余额**截断到候选容量**；两侧按
  各项时间逐条「补充 → 判足 → 扣减」，**前项余额影响后项，拒绝项不扣减**。
  响应逐条给出两侧的准入结果、命中桶余额与差异（`allowed_changed` 与逐桶
  `bucket_diffs`），并附汇总计数。目标策略或任一请求命中的策略存在
  **待生效（pending）**定时变更时返回 **409**；目标策略不存在返回 **404**。
  预演**全程只读**：不改动策略、桶、裁决与事件数据，且无需认证。
- **并发不超发**：SQLite 处于 WAL 模式，写事务一律 `BEGIN IMMEDIATE` 立即加写锁，
  配合 `busy_timeout=30s` 让并发写者排队，读-改-写序列天然串行化。
  单进程多线程、多进程（多个实例共享同一数据库文件）下均不会超发。
- **管理写接口 HMAC-SHA256 防重放认证**：仅保护四个管理写接口——
  `PUT /policies`（策略新增/更新）、`POST /policies/rollback`（回滚）、
  `POST /policy-changes`（定时变更创建）、`DELETE /policy-changes/{change_id}`
  （定时变更取消）。**所有 GET、`POST /decide`、`POST /decide-batches` 裁决、
`POST /policies/impact-preview` 预演与撤销接口保持原样、无需认证**。
  客户端发送 `X-Key-Id`、`X-Timestamp`（Unix 秒）、`X-Nonce`、`X-Signature` 四个头，
  签名原文为 `方法\n原始路径及查询串\n请求体 SHA-256 十六进制\n时间戳\nnonce`，
  签名值为小写十六进制 HMAC-SHA256。服务端用 `ADMIN_KEY_ID` / `ADMIN_HMAC_SECRET`
  做常量时间比较；时间戳偏离当前时间超过 **300 秒**或签名/key 不符返回 **401**。
  通过认证的 `(key_id, nonce)` 在 SQLite 中保留 **300 秒**，同一 key 重用 nonce
  返回 **409**；nonce 登记与业务写入在**同一个 `BEGIN IMMEDIATE` 事务**中提交，
  业务失败回滚不会占用 nonce（可用同一 nonce 修正后重试）。详见下文
  [管理写接口签名认证](#管理写接口签名认证) 一节。

## 一条命令启动（需要 Docker + Compose）

```bash
docker compose up --build
# 后台运行：
docker compose up --build -d
```

Compose 已内置**可直接启动的开发默认凭据**（`ADMIN_KEY_ID=admin-key-1`、
`ADMIN_HMAC_SECRET=change-me-please-use-openssl-rand-hex-32`），因此无需任何准备
即可跑通；**生产部署必须覆盖为自己的高强度随机密钥**，启动前在 shell 导出或通过
环境文件注入即可：

```bash
# 方式一：导出环境变量后再启动（compose 中的 ${...:-默认值} 会优先采用）
export ADMIN_KEY_ID="your-key-id"
export ADMIN_HMAC_SECRET="$(openssl rand -hex 32)"
docker compose up --build -d

# 方式二：使用 .env 文件（docker compose 会自动读取当前目录的 .env）
cat > .env <<'ENV'
ADMIN_KEY_ID=your-key-id
ADMIN_HMAC_SECRET=replace-with-openssl-rand-hex-32-output
ENV
docker compose up --build -d
```

> 若服务端**未配置** `ADMIN_KEY_ID` / `ADMIN_HMAC_SECRET`（两者任一为空），
> 四个管理写接口以 **503** 显式拒绝（fail-closed，绝不放行）；
> GET / 裁决 / 撤销接口不受影响。

服务监听 **8000 端口**：

- API 基址：`http://localhost:8000`
- 健康检查：`GET http://localhost:8000/health`
- 交互式文档（Swagger UI）：`http://localhost:8000/docs`
- OpenAPI Schema：`http://localhost:8000/openapi.json`

SQLite 数据文件保存在命名卷 `quota-data`（容器内 `/data/quota.db`），
`docker compose down` 不会删除；如需清空：`docker compose down -v`。

### 配置项（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ADMIN_KEY_ID` | `admin-key-1`（仅 compose 内置默认） | 管理写接口期望的 `X-Key-Id`；与 `X-Signature` 均做常量时间比较 |
| `ADMIN_HMAC_SECRET` | `change-me-...`（仅 compose 内置默认） | HMAC-SHA256 密钥，生产请用 `openssl rand -hex 32` 生成 |
| `QUOTA_DB_PATH` | `/data/quota.db` | SQLite 数据库文件路径 |

签名相关常量（服务端固定）：时间戳窗口 **300 秒**、nonce 保留 **300 秒**。

## 管理写接口签名认证

需要认证的接口（其余接口一律免认证）：

| 方法 | 路径 |
| --- | --- |
| `PUT` | `/policies` |
| `POST` | `/policies/rollback` |
| `POST` | `/policy-changes` |
| `DELETE` | `/policy-changes/{change_id}` |

### 请求头

| 头 | 含义 |
| --- | --- |
| `X-Key-Id` | 密钥标识，必须等于服务端 `ADMIN_KEY_ID` |
| `X-Timestamp` | 请求时刻的 **Unix 秒**（整数）；与服务器时间偏差超过 300 秒返回 401 |
| `X-Nonce` | 每次请求唯一的随机串；同一 `X-Key-Id` 在 300 秒内重用返回 409 |
| `X-Signature` | HMAC-SHA256 签名，**小写**十六进制（64 个字符） |

### 签名原文

共 5 段，以换行符 `\n` 分隔（**末尾不带换行**）：

```
<METHOD>
<原始路径及查询串>
<请求体 SHA-256 的小写十六进制>
<X-Timestamp>
<X-Nonce>
```

- **METHOD**：大写 HTTP 方法，如 `PUT` / `POST` / `DELETE`。
- **原始路径及查询串**：请求行中的 path 与 query 原样拼接（未做 URL 解码）。
  有查询串时形如 `/policy-changes/c1?x=1`，无查询串时不带 `?`
  （如 `/policies`）。百分号编码必须与实际请求完全一致。
- **请求体摘要**：`sha256(原始请求体字节)` 的小写十六进制；
  `DELETE` 无请求体时取空字节的摘要：
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`。
- **签名**：`HMAC_SHA256(ADMIN_HMAC_SECRET, 签名原文)`，输出**小写**十六进制。

### 签名与发送示例（bash + curl + openssl）

```bash
KEY_ID="admin-key-1"
SECRET="change-me-please-use-openssl-rand-hex-32"
BASE="http://localhost:8000"

# 1) 准备请求体与四个头
BODY='{"scope":"global","capacity":10,"refill_rate":1}'
METHOD="PUT"
TARGET="/policies"                       # 有查询串时连查询串一起，如 /x?a=1
TS="$(date +%s)"                          # Unix 秒
NONCE="$(openssl rand -hex 16)"           # 一次性随机串
BODY_HASH="$(printf '%s' "$BODY" | openssl dgst -sha256 | awk '{print $2}')"

# 2) 组装签名原文并计算 HMAC（5 段，恰好 4 个换行）
SIGNING="$(printf '%s\n%s\n%s\n%s\n%s' \
  "$METHOD" "$TARGET" "$BODY_HASH" "$TS" "$NONCE")"
SIG="$(printf '%s' "$SIGNING" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')"

# 3) 发送（签名覆盖的 TARGET 必须与实际 URL 的路径+查询串逐字节一致）
curl -s -X PUT "$BASE$TARGET" \
  -H 'Content-Type: application/json' \
  -H "X-Key-Id: $KEY_ID" \
  -H "X-Timestamp: $TS" \
  -H "X-Nonce: $NONCE" \
  -H "X-Signature: $SIG" \
  -d "$BODY"
```

Python 版本（等价实现，`DELETE` 时把 `body` 置为 `b""`）：

```python
import hashlib, hmac, time, secrets, urllib.request, json

key_id, secret = "admin-key-1", b"change-me-please-use-openssl-rand-hex-32"
method, target = "PUT", "/policies"
body = json.dumps({"scope": "global", "capacity": 10, "refill_rate": 1}).encode()
ts = str(int(time.time()))
nonce = secrets.token_hex(16)
body_hash = hashlib.sha256(body).hexdigest()
signing = "\n".join([method, target, body_hash, ts, nonce]).encode()
signature = hmac.new(secret, signing, hashlib.sha256).hexdigest()  # 小写 hex

req = urllib.request.Request(
    f"http://localhost:8000{target}", data=body, method=method,
    headers={
        "Content-Type": "application/json",
        "X-Key-Id": key_id,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Signature": signature,
    },
)
print(urllib.request.urlopen(req).read().decode())
```

### 状态码与防重放语义

| 状态码 | 触发条件 |
| --- | --- |
| `200` | 签名有效、nonce 首次使用，业务成功 |
| `401` | 缺少签名头；`X-Key-Id` 不符；时间戳非 Unix 秒或偏离 > 300 秒；`X-Signature` 非 64 位小写 hex；签名不匹配（方法/路径/查询串/请求体摘要/时间戳/nonce 任一被改） |
| `409` | 同一 `X-Key-Id` 在 300 秒内重用 `X-Nonce`（业务自身的 409，如 pending 变更冲突，含义见各接口说明） |
| `503` | 服务端未配置 `ADMIN_KEY_ID` / `ADMIN_HMAC_SECRET`（fail-closed） |

要点：

- **业务失败不占用 nonce**：nonce 的登记与业务写入处于同一个
  `BEGIN IMMEDIATE` 事务。若业务返回 4xx/5xx（如阈值越界 422、策略不存在 404、
  pending 冲突 409），事务整体回滚，nonce 一并撤销，客户端修正请求后
  **可用同一 nonce 重试**。只有随业务成功一起提交的 nonce 才在 300 秒内防重放。
- **nonce 按 key 隔离**：唯一约束是 `(key_id, nonce)`，不同 key 使用相同 nonce
  字符串互不影响；过期行（超过 300 秒）在下一次认证写入时自动清理，清理后
  同一 nonce 可再次使用。
- 防篡改同时覆盖**查询串**：`/policies/history?scope=global` 等路径若出现在
  被保护接口上，必须把 `?scope=global` 原样纳入第二段。
- 时钟校准请用 NTP；300 秒窗口用于吸收客户端与服务器之间的正常时钟偏差。

## API 一览

> 🔐 = 管理写接口，需要 HMAC-SHA256 签名（见
> [管理写接口签名认证](#管理写接口签名认证)）；其余接口免认证。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET`  | `/health` | 健康检查 |
| `GET`  | `/policies` | 列出全部策略 |
| `PUT` 🔐 | `/policies` | 创建/更新一层策略（按 scope+tenant_id+route_id 幂等 upsert）；该策略有 pending 变更时返回 409；成功后追加一条 `put` 版本 |
| `GET`  | `/policies/history` | 按 scope/tenant_id/route_id 查询单策略的不可变版本历史（新版本在前） |
| `POST` 🔐 | `/policies/rollback` | 在同一写事务内把策略恢复到指定历史版本并追加 `rollback` 版本；有 pending 变更时 409，未知策略/版本 404 |
| `POST` | `/policies/impact-preview` | 只读预演候选容量/速率对未来 0～3600 秒请求序列的影响（现行/候选双侧逐条对比，不落库）；目标策略不存在 404，命中 pending 变更 409 |
| `POST` 🔐 | `/policy-changes` | 为已存在的策略提交一条未来生效的定时切换 |
| `GET`  | `/policy-changes` | 列出定时变更（可按 `status` / 策略键过滤） |
| `GET`  | `/policy-changes/{change_id}` | 查询单条定时变更 |
| `DELETE` 🔐 | `/policy-changes/{change_id}` | 在生效前取消待生效变更（重复取消幂等） |
| `GET`  | `/buckets` | 查看所有已创建桶补充后的实时余额（只读，不落库） |
| `POST` | `/decide` | 提交一次多级裁决（事务内先应用命中且到期的变更） |
| `POST` | `/decide-batches` | 一个事务内整批裁决 1～50 个请求（同刻应用到期切换、按序演算共享桶、全获准才落库、batch_id 幂等） |
| `POST` | `/decide/{request_id}/revoke` | 撤销一次已通过的裁决（含成功批次中的单笔；重复撤销幂等） |
| `GET`  | `/events` | 按 id 递增分页查询 low_balance 事件（`after_id` / `limit`） |

策略对象：

```json
{
  "scope": "global | tenant | route",
  "tenant_id": "acme（tenant/route 必填）",
  "route_id": "/v1/search（route 必填，且必须带 tenant_id）",
  "capacity": 10,
  "refill_rate": 0.5,
  "low_balance_threshold": 2
}
```

> `low_balance_threshold` 可省略或为 `null`：关闭该层的低余额事件；
> 否则必须在 `0` 到 `capacity` 之间（含边界），超出范围返回 `422`。
> `PUT` 为全量替换：更新策略时不传该字段即视为关闭。

定时变更请求（`POST /policy-changes`）：

```json
{
  "change_id": "chg-20261001-global",
  "scope": "global",
  "capacity": 20,
  "refill_rate": 2,
  "low_balance_threshold": 3,
  "effective_at": "2026-10-01T00:00:00Z"
}
```

> - `change_id` 为变更的全局唯一幂等键，重复使用返回 `409`；
> - 目标策略必须已通过 `PUT /policies` 创建，否则返回 `404`；
> - `effective_at` 必须是**未来的、显式带时区**的 UTC 时间（ISO 8601，
>   如 `2026-10-01T00:00:00Z`），不带时区或不在未来返回 `422`；
> - `capacity` / `refill_rate` / `low_balance_threshold` 的取值约束与
>   `PUT /policies` 完全一致；
> - 同一 `scope+tenant_id+route_id` 至多一条 `pending` 变更，再提交返回 `409`；
>   变更被应用或取消后才能提交下一条。

变更对象（响应及 `GET /policy-changes` 返回元素）：

```json
{
  "change_id": "chg-20261001-global",
  "scope": "global",
  "tenant_id": null,
  "route_id": null,
  "capacity": 20.0,
  "refill_rate": 2.0,
  "low_balance_threshold": 3.0,
  "effective_at": "2026-10-01T00:00:00Z",
  "status": "pending",
  "created_at": "2026-09-17T12:56:09.556564Z",
  "applied_at": null,
  "cancelled_at": null
}
```

> `status` 生命周期：`pending`（待生效）→ `applied`（已由某次裁决事务应用）
> 或 `cancelled`（生效前取消）。`GET /policy-changes` 可用
> `?status=pending|applied|cancelled` 及 `scope` / `tenant_id` / `route_id` 过滤。

事件对象（`GET /events` 的返回元素）：

```json
{
  "id": 1,
  "scope": "tenant",
  "tenant_id": "acme",
  "route_id": null,
  "balance_before": 7.0,
  "balance_after": 4.0,
  "threshold": 4.0,
  "request_id": "req-1",
  "created_at": "2026-09-17T12:56:09.556564Z"
}
```

| 字段 | 含义 |
| --- | --- |
| `id` | 单调递增的事件 id，用作分页游标 |
| `scope` / `tenant_id` / `route_id` | 触发事件的桶键 |
| `balance_before` / `balance_after` | 本次裁决扣减前（时间补充后）/ 扣减后的余额 |
| `threshold` | 触发本事件时策略上的低余额阈值 |
| `request_id` | 触发本事件的裁决幂等键 |
| `created_at` | 事件时间（ISO 8601 UTC） |

裁决请求：

```json
{
  "request_id": "req-001",
  "tenant_id": "acme",
  "route_id": "/v1/search",
  "cost": 3
}
```

> `tenant_id`、`route_id` 均可省略；省略即不命中对应层级。
> `cost` 对所有命中桶统一扣减同一数量。

批量裁决请求（`POST /decide-batches`，免认证；`requests` 长度 1～50）：

```json
{
  "batch_id": "batch-20260918-001",
  "requests": [
    {"request_id": "req-001", "tenant_id": "acme", "route_id": "/v1/search", "cost": 3},
    {"request_id": "req-002", "tenant_id": "acme", "route_id": "/v1/search", "cost": 2},
    {"request_id": "req-003", "tenant_id": "acme", "cost": 1}
  ]
}
```

> - 所有条目在**同一事务、同一时刻**先应用命中且到期的策略切换，再**按数组
>   顺序**演算共享桶：前项扣减后的余额供后项使用；
> - 全部获准才统一落库。`batch_id` 对**完整载荷**（各条目的 request_id /
>   tenant_id / route_id / cost 与数组顺序）幂等：同键同载荷重放原结果，
>   同键异载荷返回 **409**；
> - 成功批次中的单笔裁决以各自 `request_id` 存档，可用 `POST /decide` 重放、
>   `POST /decide/{request_id}/revoke` 撤销。

成功响应（`committed=true`，`results` 按下标顺序给出各单笔裁决，结构同
`POST /decide`）：

```json
{
  "batch_id": "batch-20260918-001",
  "committed": true,
  "replayed": false,
  "decided_at": "2026-09-18T10:00:00.000000Z",
  "results": [
    {"index": 0, "request_id": "req-001", "allowed": true, "cost": 3.0,
     "tenant_id": "acme", "route_id": "/v1/search",
     "decided_at": "2026-09-18T10:00:00.000000Z",
     "buckets": [ {"scope": "global", "balance": 7.0},
                  {"scope": "tenant", "tenant_id": "acme", "balance": 3.0},
                  {"scope": "route",  "tenant_id": "acme", "route_id": "/v1/search", "balance": 1.0} ]},
    {"index": 1, "request_id": "req-002", "allowed": true, "cost": 2.0,
     "tenant_id": "acme", "route_id": "/v1/search",
     "decided_at": "2026-09-18T10:00:00.000000Z",
     "buckets": [ {"scope": "global", "balance": 5.0},
                  {"scope": "tenant", "tenant_id": "acme", "balance": 1.0} ]}
  ],
  "failed_index": null,
  "failure": null
}
```

失败响应（HTTP 仍为 200，`committed=false`：桶余额、普通裁决与低余额事件均未
改变；`failure.buckets` 是失败那一刻该项命中桶的状态，已反映前项的模拟扣减）：

```json
{
  "batch_id": "batch-20260918-002",
  "committed": false,
  "replayed": false,
  "decided_at": "2026-09-18T10:01:00.000000Z",
  "results": null,
  "failed_index": 1,
  "failure": {
    "index": 1,
    "request_id": "req-002",
    "reason": "insufficient_balance",
    "cost": 2.0,
    "tenant_id": "acme",
    "route_id": "/v1/search",
    "buckets": [ {"scope": "global", "balance": 7.0},
                 {"scope": "tenant", "tenant_id": "acme", "balance": 0.0} ]
  }
}
```

> `reason` 取值：`insufficient_balance`（该项某命中桶余额不足）或
> `request_id_exists`（该 `request_id` 已被单笔裁决/先前成功批次存档，或在本
> 批次内重复）。失败批次同样按 `batch_id` 存档，重放返回同一失败结果且
> `replayed=true`。空数组、超过 50 项、空 `batch_id`/`request_id`、`cost<=0`、
> 只给 `route_id` 不给 `tenant_id` 均返回 **422**。

## 示例请求

> 下文标记 🔐 的管理写接口需要签名头。先在 shell 定义下面的辅助函数
> （依赖 `openssl`，签名规则见
> [管理写接口签名认证](#管理写接口签名认证)）：
>
> ```bash
> BASE="http://localhost:8000"
> KEY_ID="admin-key-1"                                   # 与 compose 默认 ADMIN_KEY_ID 一致
> SECRET="change-me-please-use-openssl-rand-hex-32"      # 与 compose 默认 ADMIN_HMAC_SECRET 一致
>
> # 用法：admin_curl <METHOD> <TARGET> [BODY]
> admin_curl() {
>   local m="$1" t="$2" body="${3:-}" ts nonce bh sig
>   ts="$(date +%s)"; nonce="$(openssl rand -hex 16)"
>   bh="$(printf '%s' "$body" | openssl dgst -sha256 | awk '{print $2}')"
>   sig="$(printf '%s\n%s\n%s\n%s\n%s' "$m" "$t" "$bh" "$ts" "$nonce" \
>          | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')"
>   curl -s -X "$m" "$BASE$t" -H 'Content-Type: application/json' \
>     -H "X-Key-Id: $KEY_ID" -H "X-Timestamp: $ts" \
>     -H "X-Nonce: $nonce" -H "X-Signature: $sig" ${body:+-d "$body"}
> }
> ```
>
> 裁决、撤销与所有 GET 仍然直接用普通 `curl`，无需任何头。

### 1. 配置三级策略 🔐

```bash
# 全局：容量 10，0.5 令牌/秒
admin_curl PUT /policies '{"scope":"global","capacity":10,"refill_rate":0.5}'

# 租户 acme：容量 6，1 令牌/秒
admin_curl PUT /policies '{"scope":"tenant","tenant_id":"acme","capacity":6,"refill_rate":1}'

# 路由（acme 的 /v1/search）：容量 4，2 令牌/秒
admin_curl PUT /policies '{"scope":"route","tenant_id":"acme","route_id":"/v1/search","capacity":4,"refill_rate":2}'
```

### 2. 裁决（通过，三级桶同时扣 3）

```bash
curl -s -X POST http://localhost:8000/decide \
  -H 'Content-Type: application/json' \
  -d '{"request_id":"req-1","tenant_id":"acme","route_id":"/v1/search","cost":3}'
```

响应中 `buckets` 返回每个命中桶的容量、补充率和裁决后余额（7 / 3 / 1）：

```json
{
  "request_id": "req-1",
  "allowed": true,
  "cost": 3.0,
  "tenant_id": "acme",
  "route_id": "/v1/search",
  "decided_at": "2026-09-17T12:56:09.556564Z",
  "retry_at": null,
  "retry_after_seconds": null,
  "retry_possible": true,
  "replayed": false,
  "revoked": false,
  "revoked_at": null,
  "buckets": [
    {"scope": "global", "tenant_id": null, "route_id": null, "capacity": 10.0, "refill_rate": 0.5, "balance": 7.0},
    {"scope": "tenant", "tenant_id": "acme", "route_id": null, "capacity": 6.0, "refill_rate": 1.0, "balance": 3.0},
    {"scope": "route",  "tenant_id": "acme", "route_id": "/v1/search", "capacity": 4.0, "refill_rate": 2.0, "balance": 1.0}
  ]
}
```

### 3. 裁决（路由桶不足 → 整组拒绝，全部不扣）

```bash
curl -s -X POST http://localhost:8000/decide \
  -H 'Content-Type: application/json' \
  -d '{"request_id":"req-2","tenant_id":"acme","route_id":"/v1/search","cost":2}'
```

```json
{
  "request_id": "req-2",
  "allowed": false,
  "retry_at": "2026-09-17T12:56:10.056564Z",
  "retry_after_seconds": 0.48,
  "retry_possible": true,
  "buckets": [ {"scope": "global", "balance": 7.0}, {"scope": "tenant", "balance": 3.0}, {"scope": "route", "balance": 1.0} ]
}
```

### 4. 幂等重放与 409 冲突

```bash
# 相同 request_id + 相同载荷：重放原结果（replayed=true），不再扣令牌
curl -s -X POST http://localhost:8000/decide \
  -H 'Content-Type: application/json' \
  -d '{"request_id":"req-1","tenant_id":"acme","route_id":"/v1/search","cost":3}'

# 相同 request_id 但载荷不同（如 cost 改变）：HTTP 409
curl -i -X POST http://localhost:8000/decide \
  -H 'Content-Type: application/json' \
  -d '{"request_id":"req-1","tenant_id":"acme","route_id":"/v1/search","cost":4}'
```

### 5. 撤销与重复撤销

```bash
# 撤销已通过的裁决，向当时命中的桶补回令牌（不超过容量）
curl -s -X POST http://localhost:8000/decide/req-1/revoke

# 再次撤销：幂等，返回同一撤销结果（replayed=true）
curl -s -X POST http://localhost:8000/decide/req-1/revoke
```

对被拒绝的裁决撤销返回 409；对不存在的 `request_id` 撤销返回 404。

### 5b. 批量裁决（整批原子、按序共享桶、批次幂等）

```bash
# 全局桶容量 10；两项 4+6 恰好打空：前项余额（6）供后项使用
curl -s -X POST http://localhost:8000/decide-batches \
  -H 'Content-Type: application/json' \
  -d '{"batch_id":"b-1","requests":[
    {"request_id":"req-b1","cost":4},
    {"request_id":"req-b2","cost":6}
  ]}'
# committed=true；results[0].buckets[0].balance=6，results[1]...=0

# 总量超过余额：第二项不足 -> committed=false，桶余额/裁决/事件全部不变；
# failure.buckets[0].balance 是前项模拟扣减后的 6
curl -s -X POST http://localhost:8000/decide-batches \
  -H 'Content-Type: application/json' \
  -d '{"batch_id":"b-2","requests":[
    {"request_id":"req-b3","cost":4},
    {"request_id":"req-b4","cost":7}
  ]}'

# batch_id 对完整载荷幂等：重放原结果（committed=false, replayed=true）
curl -s -X POST http://localhost:8000/decide-batches \
  -H 'Content-Type: application/json' \
  -d '{"batch_id":"b-2","requests":[
    {"request_id":"req-b3","cost":4},
    {"request_id":"req-b4","cost":7}
  ]}'

# 成功批次中的单笔裁决照常查询（重放）与撤销
curl -s -X POST http://localhost:8000/decide \
  -H 'Content-Type: application/json' \
  -d '{"request_id":"req-b1","cost":4}'   # replayed=true，不重复扣减
curl -s -X POST http://localhost:8000/decide/req-b2/revoke
```

### 6. 查看桶余额

```bash
curl -s http://localhost:8000/buckets
```

### 7. 低余额事件：配置阈值、触发与分页查询

```bash
# 给租户 acme 配置阈值 2：余额从 2 以上降到 2 或以下时产生事件
admin_curl PUT /policies '{"scope":"tenant","tenant_id":"acme","capacity":6,"refill_rate":1,"low_balance_threshold":2}'

# 裁决通过，租户桶 6 -> 3：仍在阈值之上，无事件
curl -s -X POST http://localhost:8000/decide \
  -H 'Content-Type: application/json' \
  -d '{"request_id":"req-10","tenant_id":"acme","cost":3}'

# 再次裁决，租户桶 3 -> 1：越过阈值，写入一条 low_balance 事件
curl -s -X POST http://localhost:8000/decide \
  -H 'Content-Type: application/json' \
  -d '{"request_id":"req-11","tenant_id":"acme","cost":2}'

# 查询事件（默认按 id 升序返回最多 100 条）
curl -s http://localhost:8000/events

# 稳定分页：limit 控制页大小，after_id 传上一页最后一条的 id
curl -s 'http://localhost:8000/events?limit=10'
curl -s 'http://localhost:8000/events?after_id=1&limit=10'
```

事件响应示例：

```json
[
  {
    "id": 1,
    "scope": "tenant",
    "tenant_id": "acme",
    "route_id": null,
    "balance_before": 3.0,
    "balance_after": 1.0,
    "threshold": 2.0,
    "request_id": "req-11",
    "created_at": "2026-09-17T12:56:12.000000Z"
  }
]
```

### 8. 策略定时切换：提交、冲突、取消与到期生效

```bash
# 全局策略当前为容量 10、0.5 令牌/秒（沿用第 1 步的配置）
# 先花掉 5 个令牌，使余额为 5（剩余比例 0.5）
curl -s -X POST http://localhost:8000/decide \
  -H 'Content-Type: application/json' \
  -d '{"request_id":"req-20","cost":5}'

# 提交一条 60 秒后生效的变更：容量 20、2 令牌/秒、低余额阈值 3
# （effective_at 必须是未来 UTC 时间，这里用 date 动态生成）
admin_curl POST /policy-changes "{
  \"change_id\":\"chg-1\",
  \"scope\":\"global\",
  \"capacity\":20,
  \"refill_rate\":2,
  \"low_balance_threshold\":3,
  \"effective_at\":\"$(date -u -d '60 seconds' +%Y-%m-%dT%H:%M:%SZ)\"
}"

# 待生效期间直接 PUT 该策略 -> 409（业务冲突；注意签名仍必须有效）
admin_curl PUT /policies '{"scope":"global","capacity":100,"refill_rate":0}'
# {"detail":"该策略存在待生效的定时变更 change_id='chg-1' ..."}

# 同一策略再提交一条 pending -> 409；change_id 重复 -> 409
# 目标策略不存在 -> 404；effective_at 已过期或不带时区 -> 422

# 查看 / 过滤待生效变更
curl -s 'http://localhost:8000/policy-changes?status=pending'

# 生效前取消（重复取消幂等；已生效或已到生效时刻再取消返回 409）
admin_curl DELETE /policy-changes/chg-1
```

到期时刻**不需要任何后台动作**：60 秒后的第一次 `POST /decide` 会在同一事务内
先应用变更再裁决。以上面余额 5 / 旧容量 10、新容量 20 为例：

1. 先按旧速率 `0.5/s` 把余额补充到 `effective_at`：`min(10, 5 + 0.5×60) = 10`；
2. 按剩余比例换算到新容量：`10 / 10 × 20 = 20`；
3. 桶的时间锚点移到 `effective_at`，之后按新速率 `2/s` 继续补充，
   新阈值 `3` 立即生效。

```bash
# 到期后的第一次裁决：响应中的桶已是新容量/新速率
curl -s -X POST http://localhost:8000/decide \
  -H 'Content-Type: application/json' \
  -d '{"request_id":"req-21","cost":1}'
# buckets[0]: capacity=20.0, refill_rate=2.0, balance≈19（补充后再扣 1）

# 变更状态变为 applied；此后 PUT /policies 恢复正常，也可提交新的变更
curl -s http://localhost:8000/policy-changes/chg-1
```

### 9. 策略版本审计与回滚

每次 `PUT /policies` 成功与定时切换实际生效，都会为该策略追加一条不可变版本：

```bash
# 查询某策略的版本历史（按版本号新到旧返回）
curl -s 'http://localhost:8000/policies/history?scope=global'
curl -s 'http://localhost:8000/policies/history?scope=tenant&tenant_id=acme'
curl -s 'http://localhost:8000/policies/history?scope=route&tenant_id=acme&route_id=/v1/search'
```

版本对象：

```json
[
  {
    "version": 3,
    "scope": "global",
    "tenant_id": null,
    "route_id": null,
    "capacity": 20.0,
    "refill_rate": 2.0,
    "low_balance_threshold": 3.0,
    "source": "scheduled",
    "change_id": "chg-1",
    "restored_from_version": null,
    "created_at": "2026-09-18T00:00:00.000000Z"
  },
  {
    "version": 2,
    "scope": "global",
    "tenant_id": null,
    "route_id": null,
    "capacity": 100.0,
    "refill_rate": 0.0,
    "low_balance_threshold": null,
    "source": "put",
    "change_id": null,
    "restored_from_version": null,
    "created_at": "2026-09-17T12:56:09.556564Z"
  },
  {
    "version": 1,
    "scope": "global",
    "tenant_id": null,
    "route_id": null,
    "capacity": 10.0,
    "refill_rate": 0.5,
    "low_balance_threshold": null,
    "source": "put",
    "change_id": null,
    "restored_from_version": null,
    "created_at": "2026-09-17T12:00:00.000000Z"
  }
]
```

> `source` 取值：`put`（`PUT /policies` 成功）、`scheduled`（定时切换由裁决
> 事务实际应用，`change_id` 指向对应变更）、`rollback`（回滚产生，
> `restored_from_version` 指向被恢复的版本）、`baseline`（老库升级时按当时
> 策略补登的 version=1）。

回滚到指定版本（恢复参数 + 桶补充后截断 + 追加新版本在同一写事务内完成）🔐：

```bash
admin_curl POST /policies/rollback '{"scope":"global","version":1}'
```

```json
{
  "version": 4,
  "scope": "global",
  "tenant_id": null,
  "route_id": null,
  "capacity": 10.0,
  "refill_rate": 0.5,
  "low_balance_threshold": null,
  "source": "rollback",
  "change_id": null,
  "restored_from_version": 1,
  "created_at": "2026-09-18T09:30:00.000000Z"
}
```

> - 回滚不是「跳到旧版本」：恢复后产生的是一个**新版本号**，版本链只增不改；
> - 已有桶先按**当前**策略补充到事务时刻，再按目标版本容量截断
>   （放大容量时余额不会凭空变满）；
> - 策略存在 `pending` 定时变更时返回 `409`，请先取消或等其生效；
> - 目标策略不存在、或该版本不属于该策略，返回 `404`；
> - 回滚成功后无 `pending` 变更，可正常继续 PUT / 提交定时切换 / 再次回滚。

### 10. 策略影响预演（POST /policies/impact-preview，免认证、只读）

在**不改动任何数据**的前提下，回答「如果把某策略的容量/速率改成候选值，
接下来一段时间内的请求序列会被怎样裁决」。请求体给一个**已存在**的策略键、
候选 `capacity` / `refill_rate`，以及 1～50 条按 `at_seconds`（相对预演起点
0～3600 秒）**非递减**排列的请求：

```bash
# 现行全局策略：容量 10、0.5 令牌/秒；预演候选：容量 4、0.05 令牌/秒
curl -s -X POST http://localhost:8000/policies/impact-preview \
  -H 'Content-Type: application/json' \
  -d '{
    "scope": "global",
    "capacity": 4,
    "refill_rate": 0.05,
    "requests": [
      {"tenant_id": "acme", "cost": 3, "at_seconds": 0},
      {"tenant_id": "acme", "cost": 3, "at_seconds": 30},
      {"tenant_id": "acme", "cost": 2, "at_seconds": 60}
    ]
  }'
```

响应逐条给出**现行（current）/ 候选（candidate）**两侧的准入结果与命中桶
余额，以及差异（`allowed_changed`、逐桶 `bucket_diffs`）和汇总（`summary`）。
下面截取了关键字段：第 2 条在候选策略下因余额不足被拒（`allowed_changed:
true`，候选侧余额 2.5 不扣减），第 3 条在两侧均获准：

```json
{
  "scope": "global",
  "tenant_id": null,
  "route_id": null,
  "current_capacity": 10.0,
  "current_refill_rate": 0.5,
  "candidate_capacity": 4.0,
  "candidate_refill_rate": 0.05,
  "started_at": "2026-09-26T22:41:20.974283Z",
  "items": [
    {
      "index": 1,
      "at_seconds": 30.0,
      "tenant_id": "acme",
      "route_id": null,
      "cost": 3.0,
      "current":  {"allowed": true,  "buckets": [{"scope": "global", "tenant_id": null, "route_id": null, "capacity": 10.0, "refill_rate": 0.5,  "balance": 7.0}]},
      "candidate": {"allowed": false, "buckets": [{"scope": "global", "tenant_id": null, "route_id": null, "capacity": 4.0, "refill_rate": 0.05, "balance": 2.5}]},
      "allowed_changed": true,
      "bucket_diffs": [
        {"scope": "global", "tenant_id": null, "route_id": null,
         "current_balance": 7.0, "candidate_balance": 2.5, "balance_delta": -4.5}
      ]
    }
  ],
  "summary": {"total_items": 3, "current_allowed": 3, "candidate_allowed": 2, "allowed_changed_items": 1}
}
```

> - 预演起点（`at_seconds=0` 对应的时刻）即服务端处理该请求的时刻，
>   返回在 `started_at` 中；各涉及桶先按**现行**策略补充到起点，候选侧再把
>   目标桶的起点余额**截断到候选容量**；
> - 两侧各自按 `at_seconds` 逐条「补充 → 判足 → 扣减」：前项余额影响后项，
>   **拒绝项不扣减**（时间应得的补充仍计入）；未命中任何已配置策略层的请求
>   两侧均准入、`buckets` 为空；
> - 目标策略不存在返回 **404**；目标策略或任一请求命中的策略存在
>   `pending` 定时变更返回 **409**（预演假设窗口内策略不变）；
> - `at_seconds` 越界（非 0～3600）或未按非递减顺序、`cost<=0`、只给
>   `route_id` 不给 `tenant_id`、请求数非 1～50 均返回 **422**；
> - 预演**全程只读**：策略、桶、裁决（`decisions`）与低余额事件均不受影响，
>   也不产生任何事件；接口免认证。

## 行为约定与边界

- 桶首次被命中时按当前容量**满额**创建。
- 更新策略容量时，已有桶先按旧率补充到当前时刻，再截断到新容量
  （缩小容量不会让余额超过新容量）。
- 策略存在 `pending` 变更期间，`PUT /policies` 更新该策略返回 `409`，
  避免直接更新与到期应用两条路径交错破坏余额换算；请先取消变更或等其生效。
- 定时变更到期时由下一次**命中该策略的裁决**惰性应用：未命中该策略的时间内
  什么都不做；应用与裁决在同一 `BEGIN IMMEDIATE` 事务内原子提交，
  并发请求只能看到完整旧状态或完整新状态。
- 到期应用的余额换算：旧策略补充到 `effective_at` →
  `旧余额 / 旧容量 × 新容量`（旧容量为 `0` 时余额为 `0`，随后按新速率从 0 补充）
  → 按新速率从 `effective_at` 补充至裁决时刻。新容量更小时换算结果以新容量为上限。
- 取消只对生效时刻仍在未来的 `pending` 变更有效；已应用的不可撤销
  （如需回退，再用 `PUT /policies`、提交一条反向变更，或直接
  `POST /policies/rollback` 回到历史版本）。
- 版本记录只追加、不修改、不删除：同一策略的 `version` 在写事务内
  `max(version)+1` 单调分配；PUT、定时切换生效、回滚三个来源与触发动作
  在同一 `BEGIN IMMEDIATE` 事务内提交。老库启动时自动为现有策略补登
  version=1 的 `baseline`（幂等），历史策略因此也可直接回滚。
- 低余额事件只在**获准**裁决的扣减事务内产生：拒绝、幂等重放、
  撤销与策略更新/变更应用本身都不写事件；一次裁决中每个越线桶各写一条。
- 阈值判定为「扣减前余额 > 阈值 ≥ 扣减后余额」；余额本就在阈值之下的
  扣减不会重复触发，待余额重新高于阈值后才会再次武装。
- 若一次裁决没有命中任何已配置的层级，返回 `404`（提示先配置策略）。
- `cost ≤ 0` 返回 `422`；`route_id` 必须与 `tenant_id` 一起提供，否则 `422`；
  `low_balance_threshold` 超出 `[0, capacity]` 返回 `422`。
- 批量裁决（`POST /decide-batches`）的额外约定：
  - `requests` 长度必须为 1～50，空批次/超长批次、空 `batch_id`/`request_id`、
    批内 `cost ≤ 0`、只给 `route_id` 不给 `tenant_id` 均返回 `422`，且不保存
    批次档案；批中某条目没有命中任何策略层级返回 `404`（同样不存档）；
  - 到期策略切换、补充与所有条目的演算共用**同一时刻**；桶的时间补充对每个
    命中桶在批次开始时只计算一次，之后仅在条目间传递扣减；
  - 失败回滚不改变桶余额、`decisions` 与低余额事件，也不把批内的到期切换
    标记为 applied（切换保持 pending，下次裁决仍会惰性应用）；仅批次档案
    （`decide_batches`，含成功与失败）在独立事务中写入；
  - 同一桶在批次中被多个条目命中时，低余额事件按数组顺序逐个判定，事件的
    `request_id` 为触发越线的那个条目；
  - 成功批次的每笔裁决都独立写入 `decisions`，其 `decided_at` 为批次时刻，
    后续单笔重放/撤销语义与普通裁决完全一致。
- 裁决只保证「整组原子扣减」与最终一致；重试时间是服务端按当前策略与已登记的
  待生效切换推算的建议值（切换仍可能被取消，期间也可能有其他裁决/撤销发生），
  实际结果仍以再次裁决为准。
- 策略影响预演（`POST /policies/impact-preview`）的额外约定：
  - 目标策略必须已存在（404）；候选仅替换该策略的容量与速率，其余层级不变；
  - 所有涉及桶在同一只读快照内按现行策略补充到预演起点，之后两侧完全在
    内存中演算：不改动策略、桶、裁决与事件数据，也不产生低余额事件；
  - 目标策略或任一请求命中的策略存在 `pending` 定时变更时返回 409，
    请先取消或等其生效后再预演；
  - 未命中任何已配置策略层的请求两侧均为准入、`buckets` 为空；
  - 预演是基于「窗口内策略不变、无其他流量」假设的演算，实际裁决仍以
    `POST /decide` 为准。

## 本地开发（不用 Docker）

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
ADMIN_KEY_ID=dev-key \
ADMIN_HMAC_SECRET=dev-secret \
QUOTA_DB_PATH=./quota.db \
  .venv/bin/uvicorn app.main:app --reload --port 8000
```

> 不设置 `ADMIN_KEY_ID` / `ADMIN_HMAC_SECRET` 时，四个管理写接口返回 503；
> GET / 裁决 / 撤销仍可正常使用。

运行测试（另需 `pip install pytest httpx`）：

```bash
.venv/bin/pip install pytest httpx
.venv/bin/python -m pytest -q
```

测试覆盖：三级原子扣减/整组拒绝不扣、按时间补充、整组重试时间、
拒绝时重试预测纳入待生效切换（切换使不可能变可能、容量放大允许超大 cost、
到点按比例换算、切换前旧率补充后接新率、切换缩小他桶导致永不同时足额、
预测不提前应用切换且重放原样返回存档结果）、
幂等重放、载荷冲突 409、撤销补回与幂等、补回不超容量、容量更新截断、
低余额事件的越线触发/拒绝与重放不触发/补充、撤销、阈值调低后重新武装、
多级同时越线各产一条、events 稳定分页、老库迁移补列，
策略定时切换的提交约束（404/409/422）、pending 期间 PUT 冲突、
生效前取消与到期不可取消、生效前后裁决的策略可见性、
余额按旧率补充再按比例缩放再走新率、旧容量 0 归零、
新阈值到期生效、多级变更在同一事务内应用、两阶段并发下新旧状态不串且不超发，
以及 20+ 线程并发与双进程共享同一数据库文件均不超发；
策略版本审计覆盖 PUT/定时生效/回滚三个来源的版本号单调递增、
按策略键新到旧查询、老库 baseline 补登（含幂等）、回滚恢复参数并追加
rollback 版本、桶先按当前策略补充再按目标容量截断、pending 409 与
未知策略/版本 404；管理写接口 HMAC 认证覆盖：未签名/缺头/错 key/错密钥
/错签名格式（非小写 hex）/篡改方法路径查询串或请求体一律 401、
时间戳非 Unix 秒与 ±300 秒窗口、空 body（DELETE）取空串摘要、
nonce 同 key 重用 409 与过期清理后可复用、按 key 隔离、
业务失败（422/404）回滚不占用 nonce、nonce 冲突先于业务校验、
查询串与百分号编码纳入签名、凭据未配置 fail-closed 503、
以及 GET/裁决（含 /decide-batches）/撤销保持匿名；
批量裁决覆盖：全部获准时按数组顺序演算共享桶（含多级）、同一时刻到期切换
在批事务内应用、仅全获准才落库桶余额/裁决/低余额事件、不足与 request_id
已存在（单笔存档/先前批次/批内重复）整批回滚且失败快照含前项模拟扣减、
失败批次存档并可按 batch_id 重放、成功/失败同键异载荷 409、
成功批次单笔可经 /decide 重放与 /revoke 撤销、低余额事件按项归属且失败不产事件、
失败回滚后到期切换保持 pending、422/404 校验与不存档、免认证、
以及 20 线程并发批次不超发；
策略影响预演覆盖：双侧逐条准入与余额差异、起点余额截断到候选容量、
按 at_seconds 分侧补充、拒绝不扣减且前项影响后项、多级共享桶发散、
只读不改策略/桶/裁决/事件、目标策略 404、命中 pending 变更 409、
at_seconds 越界与递减等 422、未命中策略层的请求两侧准入、免认证。

## 项目结构

```
app/
  auth.py       # 管理写接口 HMAC-SHA256 防重放：签名校验（常量时间比较）、时间窗与 nonce 登记
  database.py   # SQLite 连接、WAL/busy_timeout、BEGIN IMMEDIATE 写事务 / 只读快照事务、建表（含 admin_nonces、decide_batches）与老库迁移（含 baseline 版本补登）
  quota.py      # 策略 upsert、版本审计/回滚、定时切换登记/取消/到期应用、惰性补充、整组裁决、批量裁决（同刻切换+按序共享桶+全获准才落库+批次幂等存档）、策略影响预演（只读快照+现行/候选双侧内存演算）、幂等存档、撤销与低余额事件
  schemas.py    # Pydantic 请求/响应模型（含批量裁决与影响预演）
  main.py       # FastAPI 路由（4 个管理写接口挂载签名依赖，其余匿名，含 POST /decide-batches 与 POST /policies/impact-preview）
tests/
  test_api.py   # 行为、并发与 HMAC 认证测试（含批量裁决与策略影响预演）
Dockerfile
docker-compose.yml
```
