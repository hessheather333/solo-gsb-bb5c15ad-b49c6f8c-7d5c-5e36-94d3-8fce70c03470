"""请求 / 响应模型。"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


class PolicyIn(BaseModel):
    scope: Literal["global", "tenant", "route"]
    tenant_id: Optional[str] = Field(default=None, description="scope=tenant/route 时必填")
    route_id: Optional[str] = Field(default=None, description="scope=route 时必填")
    capacity: float = Field(..., ge=0, description="桶容量（令牌数上限）")
    refill_rate: float = Field(..., ge=0, description="每秒补充的令牌数（令牌/秒）")
    low_balance_threshold: Optional[float] = Field(
        default=None,
        description="低余额阈值：null 关闭；否则须在 0 到 capacity 之间。"
        "获准裁决令桶从阈值之上降至不高于阈值时产生 low_balance 事件",
    )


class PolicyOut(BaseModel):
    scope: str
    tenant_id: Optional[str]
    route_id: Optional[str]
    capacity: float
    refill_rate: float
    low_balance_threshold: Optional[float]
    updated_at: str


class PolicyRollbackIn(BaseModel):
    scope: Literal["global", "tenant", "route"]
    tenant_id: Optional[str] = Field(default=None, description="scope=tenant/route 时必填")
    route_id: Optional[str] = Field(default=None, description="scope=route 时必填")
    version: int = Field(..., ge=1, description="要恢复到的历史版本号")


class PolicyVersionOut(BaseModel):
    scope: str
    tenant_id: Optional[str]
    route_id: Optional[str]
    version: int
    capacity: float
    refill_rate: float
    low_balance_threshold: Optional[float]
    source: Literal["put", "scheduled", "rollback", "baseline"]
    change_id: Optional[str] = None
    restored_from_version: Optional[int] = None
    created_at: str


class PolicyChangeIn(BaseModel):
    change_id: str = Field(..., min_length=1, description="变更幂等键，全局唯一")
    scope: Literal["global", "tenant", "route"]
    tenant_id: Optional[str] = Field(default=None, description="scope=tenant/route 时必填")
    route_id: Optional[str] = Field(default=None, description="scope=route 时必填")
    capacity: float = Field(..., ge=0, description="生效后的新桶容量")
    refill_rate: float = Field(..., ge=0, description="生效后的新补充速率（令牌/秒）")
    low_balance_threshold: Optional[float] = Field(
        default=None,
        description="生效后的新低余额阈值：null 关闭；否则须在 0 到 capacity 之间",
    )
    effective_at: datetime = Field(
        ...,
        description="生效时刻（UTC），必须晚于当前时间；支持带偏移的 ISO 8601 时间",
    )

    @field_validator("effective_at")
    @classmethod
    def _effective_must_be_utc(cls, v: datetime) -> datetime:
        # 不带时区的时间无法可靠解释为 UTC，拒绝并提示显式带 Z / +00:00
        if v.tzinfo is None:
            raise ValueError("effective_at 必须显式带时区（UTC，例如 2026-10-01T00:00:00Z）")
        return v.astimezone(timezone.utc)


class PolicyChangeOut(BaseModel):
    change_id: str
    scope: str
    tenant_id: Optional[str]
    route_id: Optional[str]
    capacity: float
    refill_rate: float
    low_balance_threshold: Optional[float]
    effective_at: str
    status: Literal["pending", "applied", "cancelled"]
    created_at: str
    applied_at: Optional[str] = None
    cancelled_at: Optional[str] = None


class DecideIn(BaseModel):
    request_id: str = Field(..., min_length=1, description="幂等键，相同 request_id 重放原结果")
    tenant_id: Optional[str] = None
    route_id: Optional[str] = Field(default=None, description="提供 route_id 时必须带 tenant_id")
    cost: float = Field(..., gt=0, description="本次请求需要的令牌数，所有命中桶统一扣减")


class BucketOut(BaseModel):
    scope: str
    tenant_id: Optional[str]
    route_id: Optional[str]
    capacity: float
    refill_rate: float
    balance: float


class DecisionOut(BaseModel):
    request_id: str
    allowed: bool
    cost: float
    tenant_id: Optional[str]
    route_id: Optional[str]
    decided_at: str
    retry_at: Optional[str]
    retry_after_seconds: Optional[float]
    retry_possible: bool
    replayed: bool = False
    revoked: bool = False
    revoked_at: Optional[str] = None
    buckets: list[BucketOut]


class DecideBatchItemIn(BaseModel):
    request_id: str = Field(..., min_length=1, description="单笔裁决幂等键，写入 decisions 表，可由 /decide 重放、/revoke 撤销")
    tenant_id: Optional[str] = None
    route_id: Optional[str] = Field(default=None, description="提供 route_id 时必须带 tenant_id")
    cost: float = Field(..., gt=0, description="本次请求需要的令牌数，所有命中桶统一扣减")


class DecideBatchIn(BaseModel):
    batch_id: str = Field(..., min_length=1, description="批次幂等键：相同 batch_id + 相同完整载荷重放原结果；同键异载荷返回 409")
    requests: list[DecideBatchItemIn] = Field(
        ..., min_length=1, max_length=50, description="1～50 个裁决请求，按数组顺序演算共享桶"
    )


class BatchDecisionOut(BaseModel):
    """成功批次中的单笔裁决（结构与 POST /decide 的结果一致，replayed 恒为 false）。"""
    index: int
    request_id: str
    allowed: bool
    cost: float
    tenant_id: Optional[str]
    route_id: Optional[str]
    decided_at: str
    buckets: list[BucketOut]


class BatchFailureOut(BaseModel):
    index: int = Field(..., description="数组中首个令整批失败的项下标（从 0 开始）")
    request_id: str
    reason: Literal["insufficient_balance", "request_id_exists"]
    cost: float
    tenant_id: Optional[str]
    route_id: Optional[str]
    buckets: list[BucketOut] = Field(
        ..., description="失败那一刻该条目命中桶的状态（前序条目已模拟扣减，余额未持久化）"
    )


class DecideBatchOut(BaseModel):
    batch_id: str
    committed: bool
    replayed: bool = False
    decided_at: str
    results: Optional[list[BatchDecisionOut]] = Field(
        default=None, description="committed=true：按请求顺序的各单笔裁决"
    )
    failed_index: Optional[int] = None
    failure: Optional[BatchFailureOut] = Field(
        default=None, description="committed=false：首个失败条目及其当时桶状态"
    )


class RevokeOut(BaseModel):
    request_id: str
    allowed: bool
    revoked: bool
    revoked_at: Optional[str]
    replayed: bool
    cost: float
    buckets: list[BucketOut]


class ImpactPreviewItemIn(BaseModel):
    tenant_id: Optional[str] = None
    route_id: Optional[str] = Field(default=None, description="提供 route_id 时必须带 tenant_id")
    cost: float = Field(..., gt=0, description="本次请求需要的令牌数，所有命中桶统一扣减")
    at_seconds: float = Field(
        ..., ge=0, le=3600,
        description="相对预演起点的秒数（0～3600）；多条请求必须按非递减顺序提交",
    )


class ImpactPreviewIn(BaseModel):
    scope: Literal["global", "tenant", "route"]
    tenant_id: Optional[str] = Field(default=None, description="scope=tenant/route 时必填")
    route_id: Optional[str] = Field(default=None, description="scope=route 时必填")
    capacity: float = Field(..., ge=0, description="候选桶容量（仅替换指定策略）")
    refill_rate: float = Field(..., ge=0, description="候选补充速率（令牌/秒）")
    requests: list[ImpactPreviewItemIn] = Field(
        ..., min_length=1, max_length=50,
        description="1～50 条预演请求，按 at_seconds 非递减顺序",
    )


class ImpactPreviewSideOut(BaseModel):
    """预演单侧（现行/候选）对一条请求的裁决结果与命中桶余额。"""
    allowed: bool
    buckets: list[BucketOut]


class ImpactPreviewBucketDiffOut(BaseModel):
    scope: str
    tenant_id: Optional[str]
    route_id: Optional[str]
    current_balance: float
    candidate_balance: float
    balance_delta: float = Field(..., description="候选侧余额 - 现行侧余额")


class ImpactPreviewItemOut(BaseModel):
    index: int
    at_seconds: float
    tenant_id: Optional[str]
    route_id: Optional[str]
    cost: float
    current: ImpactPreviewSideOut
    candidate: ImpactPreviewSideOut
    allowed_changed: bool = Field(..., description="两侧准入结果是否不同")
    bucket_diffs: list[ImpactPreviewBucketDiffOut] = Field(
        ..., description="逐项命中桶的两侧余额对比（与 buckets 同序）"
    )


class ImpactPreviewSummaryOut(BaseModel):
    total_items: int
    current_allowed: int = Field(..., description="现行策略下获准的条数")
    candidate_allowed: int = Field(..., description="候选策略下获准的条数")
    allowed_changed_items: int = Field(..., description="两侧准入结果不同的条数")


class ImpactPreviewOut(BaseModel):
    scope: str
    tenant_id: Optional[str]
    route_id: Optional[str]
    current_capacity: float
    current_refill_rate: float
    candidate_capacity: float
    candidate_refill_rate: float
    started_at: str = Field(..., description="预演起点（at_seconds=0 对应的 UTC 时刻）")
    items: list[ImpactPreviewItemOut]
    summary: ImpactPreviewSummaryOut


class ReservationIn(BaseModel):
    reservation_id: str = Field(
        ..., min_length=1, description="预占幂等键：相同 ID + 相同载荷重放原结果；异载荷 409"
    )
    tenant_id: Optional[str] = None
    route_id: Optional[str] = Field(default=None, description="提供 route_id 时必须带 tenant_id")
    cost: float = Field(..., gt=0, description="预占令牌数（正数），全部命中桶统一预扣")
    ttl_seconds: int = Field(
        ..., ge=1, le=300, description="预占有效期（1～300 秒）；到期未确认自动失效并返还"
    )


class ReservationOut(BaseModel):
    reservation_id: str
    status: Literal["pending", "confirmed", "cancelled", "expired", "rejected"]
    allowed: bool = Field(
        ..., description="预占是否成功（status != rejected）；rejected 表示创建时桶不足，未扣余额"
    )
    tenant_id: Optional[str]
    route_id: Optional[str]
    cost: float
    ttl_seconds: int
    created_at: str
    expire_at: str = Field(..., description="到期时刻（ISO 8601 UTC）；到期未确认自动 expired 并返还")
    confirmed_at: Optional[str] = None
    cancelled_at: Optional[str] = None
    expired_at: Optional[str] = None
    replayed: bool = False
    buckets: list[BucketOut] = Field(
        ..., description="原命中桶按当前策略补充后的实时余额（只读快照）"
    )


class LowBalanceEventOut(BaseModel):
    id: int = Field(..., description="单调递增的事件 id，用作分页游标")
    scope: str
    tenant_id: Optional[str]
    route_id: Optional[str]
    balance_before: float = Field(..., description="扣减前（时间补充后）的余额")
    balance_after: float = Field(..., description="扣减后的余额")
    threshold: float = Field(..., description="触发本事件时的低余额阈值")
    request_id: str = Field(..., description="触发本事件的裁决 request_id")
    created_at: str
