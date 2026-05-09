# Develop 计费设计 v2(已更新真实 OpenAI 价格)

> 状态:草稿 v2.1 — 加了 cached input、真实 OpenAI 报价、用户级请求频次限制
> 作者:Claude(Develop dev session,2026-05-09)
> v1 用 credits + 月度,已废弃,以本版为准

## 0. TL;DR

- **四档:**
  - **Free** — 注册送 $2 终身体验金,不过期
  - **Basic ($5/月)** — 每天 $2 额度,过日清零
  - **Pro ($10/月)** — 每天 $5 额度,过日清零
  - **Premium ($20/月)** — 每天 $12 额度,过日清零
- **不用积分。** USD 直接记账,精确到 micro-USD(整数,避浮点)
- **按真实 token 实算成本:**
  - `成本 = (uncached_input × input_rate + cached_input × cached_input_rate + output × output_rate) × 折扣系数`
  - 折扣系数当前 **0.8**,后台一个值,可改成 0.5
- **OpenAI 单价表 / 折扣系数 / 各档参数 / 体验金额 全部后台可改**
- **防高刷:** 单用户 **20 req/min**,**chatbot 内存里的 sliding window**(不持久化),env var 可配
- **前端展示双价:** OpenAI 官方价 + 你的折扣价
- **底层数据:** 复用 user-service 现有 5 张表 + 新加 `model_pricing` 一张表 + system_config 三个 key
- **Phase A 1 周** 本地闭环(无 Stripe)→ **Phase B 3-4 天** 接 Stripe 自助下单

---

## 1. 四档参数(初始值,全部后台可改)

| | Free | Basic | Pro | Premium |
|---|---|---|---|---|
| 月费 | 0 | $5 | $10 | $20 |
| 日额度 | — | **$2 / 日** | **$5 / 日** | **$12 / 日** |
| 体验金 | **$2 终身** | — | — | — |
| 重置 | 不重置 | 每日 UTC 0 点 | 每日 UTC 0 点 | 每日 UTC 0 点 |
| 视觉理解上传图 | ❌ | ✓ | ✓ | ✓ |
| 模型范围 | 所有 | 所有 | 所有 | 所有 |
| 并发 AI 调用 | 1 | 1 | 2 | 4 |
| 历史对话保留 | 30 天 | 1 年 | 永久 | 永久 |
| API key | ❌ | 1 | 5 | 10 |
| 优先队列 | ❌ | ❌ | ✓ | ✓ |
| 客服 | community | 邮件 | 邮件 + 优先 | 邮件 + 优先 |

**Free 体验金:** 一次性 $2,不过期。用户后续付费,体验金继续保留;付费过期降回 Free,继续从体验金扣。

**所有档共享同一套模型** — 区别只在日额度大小;同等额度下贵模型(GPT-5.5)用得少,自然形成档位差异,无需硬锁。

---

## 2. 计量模型

### 2.1 单次扣费公式

```
对话(token-based):
  cost_micros = uncached_input_tokens × input_rate_micros_per_1m
              + cached_input_tokens × cached_input_rate_micros_per_1m
              + output_tokens × output_rate_micros_per_1m
  charged_micros = cost_micros × discount_factor
  charged_cents = round(charged_micros / 10000)   # micro → cent
```

`xxx_rate_micros_per_1m` = 该模型每 1M tokens 的费用,以 micro-USD(10⁻⁶ USD)整数表示。例:OpenAI gpt-5.4 input = $1.25/1M = `1_250_000` micro-USD/1M。

`discount_factor` = `system_config.billing.discount_factor`,小数,默认 0.8。

**为什么有 cached_input_tokens 这一项:** OpenAI 的 prompt caching 命中时,**input token 单价大幅降低**(通常 1/10)。OpenAI API 返回的 `usage` 字段会区分 `prompt_tokens`(全部输入) 和 `cached_tokens`(命中缓存的)。我们要在前端结算和展示时正确算上这部分折扣,否则会高估自身成本、对用户多扣钱。

### 2.2 OpenAI 真实单价(初始 seed,2026-05 抓取)

数据来自 https://developers.openai.com/api/docs/pricing(Standard tier,short context)。

**对话/推理模型(per 1M tokens, USD):**

| 模型 | Input | Cached input | Output |
|---|---|---|---|
| gpt-5.5 | $5.00 | $0.50 | $30.00 |
| gpt-5.5-pro | $30.00 | — | $180.00 |
| gpt-5.4 | $2.50 | $0.25 | $15.00 |
| gpt-5.4-mini | $0.75 | $0.075 | $4.50 |
| gpt-5.4-nano | $0.20 | $0.02 | $1.25 |
| gpt-5.4-pro | $30.00 | — | $180.00 |
| chat-latest | $5.00 | $0.50 | $30.00 |
| gpt-5.3-codex | $1.75 | $0.175 | $14.00 |

**多模态(per 1M tokens):**

| 模型 | Modality | Input | Cached input | Output |
|---|---|---|---|---|
| gpt-realtime-1.5 | Audio | $32.00 | $0.40 | $64.00 |
| gpt-realtime-1.5 | Text | $4.00 | $0.40 | $16.00 |
| gpt-realtime-1.5 | Image | $5.00 | $0.50 | — |
| gpt-realtime-mini | Audio | $10.00 | $0.30 | $20.00 |
| gpt-image-2 | Image | $8.00 | $2.00 | $30.00 |
| gpt-image-2 | Text | $5.00 | $1.25 | — |
| gpt-image-1.5 | Image | $8.00 | $2.00 | $32.00 |
| gpt-image-1.5 | Text | $5.00 | $1.25 | $10.00 |
| gpt-image-1-mini | Image | $2.50 | $0.25 | $8.00 |

**音频转写(per 1M tokens 或 per minute):**

| 模型 | Input | Output | Estimated |
|---|---|---|---|
| gpt-4o-transcribe | $2.50 | $10.00 | $0.006/min |
| gpt-4o-mini-transcribe | $1.25 | $5.00 | $0.003/min |

**视频生成(per second):**

| 模型 | Size | Price/sec |
|---|---|---|
| sora-2 | 720p | $0.10 |
| sora-2-pro | 720p | $0.30 |
| sora-2-pro | 1024p | $0.50 |
| sora-2-pro | 1080p | $0.70 |

⚠️ 这张表后台 admin SPA 直接编辑;每行都要带"上次更新于"和"备注"字段(比如 "OpenAI 官方报价 2026-05-09 抓取")。**OpenAI 调价是常态,要养成定期对账习惯。**

⚠️ Regional processing(数据驻留 endpoint)有 10% 加价 — 我们当前用的是 api.develop.cc 中转,不需要管这个。但 model_pricing 表预留 `regional_uplift_pct` 字段,Phase C 用。

### 2.3 折扣展示规则

前端两个地方对用户呈现:
- **chatbot 模型选择器** hover 时显示双行小字:
  ```
  GPT-5.5
  OpenAI: $5.00 in / $0.50 cached / $30.00 out 每 1M tokens
  你的折扣价: $4.00 in / $0.40 cached / $24.00 out (8 折)
  ```
- **/center/billing 模型价格表** 完整对照所有 active 模型

后台改了 discount_factor 后**实时生效**,正在进行的会话不锁定老折扣,简单。

---

## 3. 防高刷(per-user rate limit)

### 3.1 设计

- **限速放 chatbot,不放 user-service。** 入口就拦,滥用请求根本不打到下游。
- **每用户每分钟 20 次请求**(env 可配,改值重启 chatbot 生效)
- **chatbot 进程内一个全局 dict + sliding window**,不持久化
- **触发上限返 429**,前端 toast "请稍候,X 秒后再试"

### 3.2 实现(TypeScript,chatbot 一侧)

```typescript
// chatbot/lib/billing/rate-limit.ts(新文件)
const buckets = new Map<string, number[]>();
const LIMIT = Number(process.env.RATE_LIMIT_PER_MINUTE ?? "20");

export function checkAndRecord(userId: string): { allowed: boolean; retryAfter: number } {
  const now = Date.now();
  const cutoff = now - 60_000;
  let bucket = buckets.get(userId);
  if (!bucket) { bucket = []; buckets.set(userId, bucket); }
  // 删 60s 之前的
  while (bucket.length && bucket[0] < cutoff) bucket.shift();
  if (bucket.length >= LIMIT) {
    return { allowed: false, retryAfter: Math.ceil((bucket[0] + 60_000 - now) / 1000) };
  }
  bucket.push(now);
  // GC:防止 dict 无限增长
  if (buckets.size > 10_000) gc();
  return { allowed: true, retryAfter: 0 };
}

function gc() {
  const cutoff = Date.now() - 5 * 60_000;
  for (const [uid, b] of buckets) {
    if (b.length === 0 || b[b.length - 1] < cutoff) buckets.delete(uid);
  }
}
```

### 3.3 钩子位置

在 chatbot `/api/chat` 和 `/api/images` 的入口,**比 OpenAI 调用早**:

```typescript
// app/(chat)/api/chat/route.ts 入口
const { allowed, retryAfter } = checkAndRecord(session.user.id);
if (!allowed) {
  return new Response(
    JSON.stringify({ error: "rate_limit", retry_after: retryAfter }),
    { status: 429, headers: { "content-type": "application/json" } }
  );
}
// ... 走 streamText 等
```

### 3.4 何时升级

- chatbot 单容器:本方案够用
- chatbot 多副本(HA / 蓝绿):in-memory 窗口不共享,**最坏 2x 突发**;改 Redis-backed
- 当前 chatbot 单容器跑在 xcenter:**MVP 够用**

### 3.5 配置

- env var `RATE_LIMIT_PER_MINUTE`(默认 "20"),改值重启 chatbot 生效
- 紧急 kill switch:`RATE_LIMIT_PER_MINUTE=999999` 等于事实上关掉

---

## 4. 经济性测算

按 OpenAI 实价 + 折扣 0.8 算:

| 场景 | OpenAI 实成本 | 用户额度内最多花 | 平台净支出 |
|---|---|---|---|
| Free 用户用满 $2 体验金 | $2.50 (= 2 ÷ 0.8) | $2 折扣价 | -$2.50 |
| Basic $5,每天 $2 折扣价用满,按整月 30 天 | $75 (= 60 ÷ 0.8) | $60 | **-$70 / 月** ⚠️ |
| Pro $10,每天 $5 用满 30 天 | $187.5 | $150 | **-$177.5 / 月** ⚠️ |
| Premium $20,每天 $12 用满 30 天 | $450 | $360 | **-$430 / 月** ⚠️ |

**继续提醒:这个模型对重度用户深度亏损,盈利点在"绝大多数用户用不满日额度"。**

但配合:
- 折扣 0.8 vs OpenAI 实价 → 用户感知有便宜,但平台抽成空间有限
- 日额度而非月额度 → 重度用户最坏单日伤害可控
- **每分钟 20 req 限速** → 阻止脚本化高刷,但善意用户察觉不到

**真实估算需要看上线后 ARPU vs ARPC。** 推荐 Phase A 上线后 2 周必看一次:
```sql
SELECT
  AVG(monthly_revenue) AS arpu_usd,
  AVG(monthly_openai_cost) AS arpc_usd,
  AVG(monthly_openai_cost / monthly_revenue) AS cost_ratio
FROM ... (按 user_id 聚合 payments 和 usage_events 反算)
```

如果 cost_ratio > 0.7 就要开始紧张,> 1.0 就是亏。

---

## 5. 数据模型

### 5.1 复用现有表

**`products`** seed 4 行:

```python
products:
  - code: "tier_free"
    kind: "subscription", price_cents: 0, period_days: 0, stripe_price_id: NULL
    name: { en: "Free", zh: "免费", ja: "無料", ko: "무료", de: "Kostenlos" }
    metadata: {
      tier_rank: 0,
      lifetime_trial_cents: 200,        # $2
      perks: { vision: false, max_concurrency: 1, history_days: 30, api_keys: 0 }
    }

  - code: "tier_basic"
    kind: "subscription", price_cents: 500, period_days: 30
    name: { en: "Basic", zh: "基础", ... }
    metadata: {
      tier_rank: 1,
      daily_allowance_cents: 200,       # $2/日
      perks: { vision: true, max_concurrency: 1, history_days: 365, api_keys: 1 }
    }

  - code: "tier_pro"
    kind: "subscription", price_cents: 1000, period_days: 30
    metadata: {
      tier_rank: 2,
      daily_allowance_cents: 500,       # $5/日
      perks: { vision: true, max_concurrency: 2, history_days: -1, api_keys: 5, priority_queue: true }
    }

  - code: "tier_premium"
    kind: "subscription", price_cents: 2000, period_days: 30
    metadata: {
      tier_rank: 3,
      daily_allowance_cents: 1200,      # $12/日
      perks: { vision: true, max_concurrency: 4, history_days: -1, api_keys: 10, priority_queue: true }
    }
```

**`subscriptions`** 现有结构不动,语义:每用户一条 active subscription(highest tier_rank 决定档位),source ∈ {manual, stripe, grant}。Free 档在注册时自动 grant。

**`usage_quotas`** 字段语义:
- `limit_qty` = **当日额度上限,单位 cents**
- `current_period_consumed` = **今日已扣 cents**
- `reset_kind` = 新增 `"daily"` 枚举值
- 一行 / (user_id, product_id) = (user, 当前档位 product)
- Free 档特殊:`reset_kind = "never"`, `limit_qty = lifetime_trial_cents` (= 200)

**`usage_events`** 字段语义:
- `qty` = 本次扣费 cents(整数)
- `metadata` = `{ resource_id, model, input_tokens, cached_input_tokens, output_tokens, raw_cost_micros, openai_cost_micros, discount }`
- 唯一索引 `(user_id, event, metadata->>'resource_id')` 做幂等

**`payments`** 不动。

### 5.2 新表 `model_pricing`

```sql
CREATE TABLE model_pricing (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  model_id text NOT NULL,                      -- "gpt-5.4", "gpt-image-2-image", etc
  display_name jsonb NOT NULL,                 -- { en: "GPT-5.4", zh: "GPT-5.4" }
  pricing_kind text NOT NULL,                  -- "tokens" | "per_call" | "per_second"
  modality text DEFAULT 'text',                -- "text" | "image" | "audio" | "video"

  -- token-based 字段(per 1M tokens, 以 micro-USD 整数表示)
  input_rate_micros bigint,                    -- 例:gpt-5.4 input = $2.50/1M = 2_500_000
  cached_input_rate_micros bigint,             -- 例:gpt-5.4 cached = $0.25/1M = 250_000
  output_rate_micros bigint,                   -- 例:gpt-5.4 output = $15.00/1M = 15_000_000

  -- per_call / per_second 字段(单位 micro-USD)
  per_unit_micros bigint,                      -- 例:sora-2 720p = $0.10/sec = 100_000
  per_unit_label text,                         -- "call" | "second" | "image"

  effective_from timestamptz DEFAULT now(),
  active boolean DEFAULT true,
  notes text,                                  -- "OpenAI standard tier, 2026-05-09 抓取"
  source_url text,                             -- "https://developers.openai.com/api/docs/pricing"
  updated_by_admin text,
  updated_at timestamptz DEFAULT now()
);
CREATE INDEX ON model_pricing (model_id, active);
```

**为什么 micro-USD 整数:** $0.0025/1K = $2.50/1M = 2_500_000 micro-USD/1M。一次小请求几千 token,算出的金额经常 0.01 micro 量级。整数算精度足,不怕浮点。

### 5.3 system_config 新增三 key

```
billing.discount_factor           # 默认 "0.8"
billing.daily_reset_timezone      # 默认 "UTC"
billing.rate_limit_per_minute     # 默认 "20"
```

**可选第四个**(Phase C 加):
```
billing.rate_limit_disabled       # "false",紧急 kill switch
```

### 5.4 Free 体验金

在 `usage_quotas` 一行特殊配置:
```
user_id = U
product_id = tier_free
limit_qty = 200          # $2 = 200 cents
reset_kind = "never"
current_period_consumed = 累积扣费(只增,不重置)
```

**升级到付费档:** tier_free 行**保留**,但 charge 走最高档(即付费档)。Free 体验金留作未来降级时的"安全网"。

---

## 6. 计费流程

### 6.1 注册时

```python
# /api/auth/signup 成功后,同事务:
grant_subscription(user, "tier_free", source="grant")
upsert_quota(user, tier_free,
             limit_qty=product.metadata.lifetime_trial_cents,
             reset_kind="never",
             current_period_consumed=0,
             current_period_start=now())
```

### 6.2 升级 / 降级 / 取消

(同 v1 §4.2,Stripe webhook 触发)

新增逻辑:webhook handler 在写 subscription 同事务里 upsert quota:
- `limit_qty = product.metadata.daily_allowance_cents`
- `reset_kind = "daily"`
- `current_period_start = today_utc_midnight`
- `current_period_consumed = 0`

### 6.3 chatbot 端扣费(每次 AI 调用)

```typescript
// chatbot/api/chat/route.ts
const result = await streamText({...});

result.onFinish(async ({ usage }) => {
  // usage 是 AI SDK 给的 { inputTokens, outputTokens, ... }
  // OpenAI 流式返回最后会有 prompt_tokens_details.cached_tokens
  await fetch(`${USER_SERVICE_URL}/api/usage/charge`, {
    method: "POST",
    headers: {
      "X-Service-Token": process.env.USER_SERVICE_TOKEN!,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      user_id: session.user.id,
      model: "gpt-5.4",
      input_tokens: usage.inputTokens,
      cached_input_tokens: usage.cachedInputTokens ?? 0,
      output_tokens: usage.outputTokens,
      resource_id: messageId,  // 幂等
    }),
  });
});
```

如果 chatbot 没拿到 cached_tokens(模型不支持或 SDK 没透传),fallback 走 `cached_input_tokens=0`,按全量 input 价格扣 — 我们多扣自己一些,不会对用户不公。

### 6.4 user-service /api/usage/charge 内部

```python
@router.post("/usage/charge")
def charge_usage(req: ChargeReq, _ = Depends(require_service_token)):
    # 1. 限流(进 §3 的内存 sliding window)
    limit = int(get_setting("billing.rate_limit_per_minute") or "20")
    if get_setting("billing.rate_limit_disabled") != "true":
        ok, retry = check_and_record(req.user_id, limit)
        if not ok:
            return JSONResponse(429, {"error": "rate_limit", "retry_after": retry})

    with db.transaction():
        # 2. 找最高档 active subscription
        active = sql("""
          SELECT s.*, p.id AS product_id, p.metadata
          FROM subscriptions s JOIN products p ON s.product_id = p.id
          WHERE s.user_id = :uid AND s.status = 'active'
            AND (s.expires_at IS NULL OR s.expires_at > now())
          ORDER BY (p.metadata->>'tier_rank')::int DESC LIMIT 1
        """).fetch_one(uid=req.user_id)

        # 3. 找模型价格
        pricing = sql("""
          SELECT * FROM model_pricing
          WHERE model_id = :m AND active = true
          ORDER BY effective_from DESC LIMIT 1
        """).fetch_one(m=req.model)
        if not pricing:
            return error(500, "unknown_model")

        # 4. 算 cost(integer arithmetic)
        discount = float(get_setting("billing.discount_factor") or "0.8")
        if pricing.pricing_kind == "tokens":
            uncached = req.input_tokens - req.cached_input_tokens
            raw = (uncached * pricing.input_rate_micros
                 + req.cached_input_tokens * pricing.cached_input_rate_micros
                 + req.output_tokens * pricing.output_rate_micros) // 1_000_000
        elif pricing.pricing_kind == "per_call":
            raw = pricing.per_unit_micros
        elif pricing.pricing_kind == "per_second":
            raw = pricing.per_unit_micros * req.duration_seconds

        charged_micros = int(raw * discount)
        charged_cents = (charged_micros + 5000) // 10000  # 四舍五入到 cent,不足 1 cent 也算 1 cent
        if charged_cents < 1: charged_cents = 1

        # 5. 锁 quota 检查 + 惰性 daily reset
        quota = sql("SELECT * FROM usage_quotas WHERE user_id=:u AND product_id=:p FOR UPDATE")
                .fetch_one(u=req.user_id, p=active.product_id)
        if quota.reset_kind == "daily":
            today = today_utc_midnight()
            if quota.current_period_start < today:
                quota.current_period_start = today
                quota.current_period_consumed = 0

        # 6. 扣或拒
        remaining = quota.limit_qty - quota.current_period_consumed
        if charged_cents > remaining:
            return JSONResponse(429, {
                "error": "quota_exhausted",
                "tier": active.code,
                "remaining_cents": remaining,
                "needed_cents": charged_cents,
                "upgrade_url": "https://user.develop.cc/center/billing",
            })

        quota.current_period_consumed += charged_cents
        sql_update(quota)

        # 7. 写 usage_events(幂等)
        sql_insert("usage_events", {
            "user_id": req.user_id,
            "product_id": active.product_id,
            "event": req.model,
            "qty": charged_cents,
            "metadata": {
                "resource_id": req.resource_id,
                "model": req.model,
                "input_tokens": req.input_tokens,
                "cached_input_tokens": req.cached_input_tokens,
                "output_tokens": req.output_tokens,
                "raw_cost_micros": raw,
                "openai_cost_micros": raw,
                "discount": discount,
            }
        }, conflict="(user_id, event, (metadata->>'resource_id')) DO NOTHING")

        return {
            "ok": True,
            "charged_cents": charged_cents,
            "remaining_cents": remaining - charged_cents,
            "limit_cents": quota.limit_qty,
            "tier": active.code,
        }
```

### 6.5 daily reset

惰性,无需 cron。每次 charge 前看一眼。

---

## 7. 后台可配置项一览

admin SPA 加一个 "Billing" 区块,所有这些字段可改:

| 项 | 存哪 | 修改 | 何时生效 |
|---|---|---|---|
| 各档售价 | products.price_cents | admin POST /api/admin/products/{code} | 立即,但已订阅用户走完当周期才换价 |
| 各档日额度 | products.metadata.daily_allowance_cents | 同上 | 下次 daily reset 后生效 |
| Free 体验金额 | products.tier_free.metadata.lifetime_trial_cents | 同上 | 仅影响新注册用户 |
| 折扣系数 | system_config.billing.discount_factor | admin POST /api/admin/settings | 立即,下一次 charge 用新值 |
| 模型单价表 | model_pricing 表 | admin CRUD /api/admin/pricing | 立即 |
| 每分钟限速 | chatbot env var `RATE_LIMIT_PER_MINUTE` | 改 .env + 重启 chatbot | 重启后立即 |
| Tier 增删 | products + tier_rank | 加新 product | 立即 |
| perks(并发/历史天数等) | products.metadata.perks | UI 表单 | 立即,但需要 chatbot 重新读 perks(目前 chatbot 不读 perks,Phase C 加) |

**admin SPA 大概长这样:**

```
┌─ Billing settings ────────────────────────┐
│                                            │
│ Global                                     │
│ [Discount factor: 0.8____] [Save]         │
│ [Rate limit / min: 20____] [Save]         │
│ [☐ Disable rate limit kill switch]        │
│                                            │
│ Tiers                                      │
│ ┌────────┬──────┬──────────┬──────────┐  │
│ │ tier   │ /mo  │ /day     │ trial    │  │
│ │ free   │ —    │ —        │ $2       │  │
│ │ basic  │ $5   │ $2       │ —        │  │
│ │ pro    │ $10  │ $5       │ —        │  │
│ │ premium│ $20  │ $12      │ —        │  │
│ └────────┴──────┴──────────┴──────────┘  │
│ [+ Add tier]                               │
│                                            │
│ Model pricing (USD per 1M tokens)         │
│ ┌─────────────────┬───────┬──────┬──────┐ │
│ │ model           │ input │cache │output│ │
│ │ gpt-5.4         │ 2.50  │ 0.25 │15.00 │ │
│ │ gpt-5.5         │ 5.00  │ 0.50 │30.00 │ │
│ │ gpt-image-2 img │ 8.00  │ 2.00 │30.00 │ │
│ │ ...             │       │      │      │ │
│ └─────────────────┴───────┴──────┴──────┘ │
│ [+ Add model]                              │
│                                            │
│ KPIs (last 7 days)                         │
│  Active payers: 0                          │
│  ARPU: $0  ARPC: $0                       │
│  cost_ratio: —                             │
└────────────────────────────────────────────┘
```

---

## 8. 前端用户体验

### 8.1 chatbot 内

**Header 右上角**(用户菜单旁):
```
💎 Pro · $3.21 / $5.00 today
[████░░░░░] 64%
```
hover 显示 "Resets at UTC 0:00 (in 8h 12m)"。

**chat 输入框右下小字**(消息发送后):
```
GPT-5.4 · 2,341 tokens · -$0.024 (0.8× of $0.030 list)
```

**生图前** 按钮显示预估成本 "Generate (-$0.064)"。

**429 quota_exhausted modal**:
```
今日额度已用完
你的 Basic 额度 $2 已经消耗完。
8 小时后(UTC 0:00)自动重置。
或者升级到 Pro($10/月,每日 $5)→ [立即升级]
```

**429 rate_limit toast**(短提示,不打断):
```
请求过于频繁,15 秒后再试一次
```

### 8.2 user-center /center/billing

七块:
1. **当前订阅** — 档位徽章 + "下次续费 2026-06-09" + Manage(跳 Stripe Portal)
2. **今日用量** — 大数字 `$3.21 / $5.00`,横向 progress bar
3. **月度统计** — 折线图,近 30 天每天用量
4. **模型价格表** — 表格列出所有 active 模型的 OpenAI 价 vs 你的折扣价,**强调"折扣 0.8 倍由 BitsFactor 提供"**
5. **升级面板** — 三档卡片墙,点 → Stripe Checkout
6. **加油包**(Phase B)— 4-5 种规格的购买按钮
7. **历史账单** — 近 12 个月 payments + 下载发票

### 8.3 home(develop.cc 落地页,Phase 2 一起做)

定价区从 user-service `/api/products` + `/api/pricing` 实时拉,不在前端硬编码。

---

## 9. 边缘场景

| 场景 | 处理 |
|---|---|
| 流式响应中途用户关闭页面 | OpenAI 已经计费,token usage 在 onFinish 拿到 → 仍然扣费(用户后续登录看到余额变化即可) |
| OpenAI 调用失败 | onFinish 不触发 → 不扣费 |
| 流式调用拿不到 cached_tokens | 视为 0,按全 uncached 算(平台微微吃亏不重要) |
| 用户已升级但 webhook 还没到 | 前端轮询 `/api/me/usage` 30s 内出现新 plan |
| 折扣系数中途变化 | in-flight 不锁,下一次 charge 用新值 |
| OpenAI 单价中途变化 | 同上 |
| 多账号薅羊毛 $2 体验金 | signup 已有 advisory lock + 加 IP / 邮箱域 / device-fingerprint 限制(Phase C) |
| 用户连续 7 天用满日额度 | 后台 alert 通知运营 review |
| 退款 | Stripe webhook `charge.refunded` → 把对应 subscription expires_at 提前 + email |
| chatbot 重试 charge | resource_id 幂等,重复请求 ON CONFLICT DO NOTHING |
| 时区:中国用户 UTC+8,UTC 重置 = 北京早 8 点 | MVP 接受。Phase C 改成"按用户 TZ"。 |
| 限速触发后用户连点 | 前端 toast 自动 disable submit 按钮 retry_after 秒 |
| user-service 重启 → 限速窗口清空 | 接受。最坏只是给一个用户重启那一刻多发 20 次。 |

---

## 10. 实施分期

### Phase A — 本地闭环(估 1.5 周,无 Stripe)

- [ ] user-service 加 `model_pricing` 表 + admin CRUD(/api/admin/pricing GET/POST/DELETE)
- [ ] user-service seed 初始 OpenAI 单价(本文档 §2.2 填进去)
- [ ] user-service 加 `system_config` 三 key(discount_factor, rate_limit_per_minute, daily_reset_timezone)
- [ ] user-service seed 4 个 tier products
- [ ] user-service 加 `POST /api/usage/charge`(token-based 计费 + 限流)
- [ ] user-service 加 `GET /api/me/usage` 返回今日 + 体验金 + 档位
- [ ] user-service 加 `GET /api/pricing`(公开 — 列模型 + 折扣)
- [ ] user-service admin SPA 加 Billing 配置页(§7 草图)
- [ ] chatbot 改 /api/chat 在 onFinish 调 charge
- [ ] chatbot 改 /api/images 在生图成功后调 charge
- [ ] chatbot 加 429 拦截:quota_exhausted → 升级 modal;rate_limit → toast
- [ ] chatbot header 显示今日用量(进度条 + 余额)
- [ ] 管理员手动 grant Basic / Pro / Premium 给测试用户

Phase A 验收:
- 四档逻辑全通,token + cached_tokens 实算扣对
- 折扣 0.8 写进去, admin 改成 0.5 立即全站生效
- 单用户 21 次/分钟立即拒,UI 友好提示
- 没 Stripe 也能完整跑

### Phase B — Stripe 接入(估 4 天)

- [ ] Stripe 后台建 3 个 monthly subscription price
- [ ] 把 stripe_price_id 填到 products
- [ ] 扩 stripe webhook 处理 sub create/update/delete 同步 quota
- [ ] /center/billing 接通 Stripe Checkout 跳转
- [ ] 接通 Stripe Customer Portal
- [ ] /center/billing 渲染模型价格表(读 /api/pricing)
- [ ] home 页定价区接 /api/products + /api/pricing

### Phase C — 打磨(估 1-2 周)

- [ ] 加油包(top-up)产品
- [ ] 用户 TZ-aware daily reset
- [ ] 失败 op 退款路径
- [ ] 邮件通知(余额低 / 续费失败 / 退款成功)
- [ ] 月度账单导出 PDF
- [ ] 重度用户 alert + 自动 throttle
- [ ] 多账号薅羊毛 fingerprint 检测
- [ ] tiktoken fallback(无 usage 字段时)
- [ ] Alipay / WeChat Pay
- [ ] 团队 plan(seats)
- [ ] user-service 多副本时换 Redis-backed rate limit
- [ ] chatbot 读 perks 强制约束(并发数、历史天数等)

---

## 11. 开放问题(等你拍板)

1. **OpenAI 单价 §2.2 是否就用这一版?** 我从官网刚抓的 standard tier。如果你有 enterprise tier 折扣或区域定价不同,我得调整。
2. **折扣 0.8 是否首发?** 文档里我警告过 0.5 会贴大成本;0.8 仍然在重度用户身上亏。
3. **Free 体验金 $2 是否够?** 太多薅羊毛风险高,太少新用户不爽。
4. **限速 20/min 是否合适?** 普通 chat 用户每分钟最多 5-10 次,20 给了一倍空间;脚本化批量请求会卡。可以先 20,看埋点再调。
5. **多模态(audio / video / sora)** — Phase A 不上,但 model_pricing 表预留字段。第一批正式接入哪个?
6. **管理员看板** 数据指标除了 ARPU/ARPC/cost_ratio,还要看哪些?(转化漏斗?)
7. **退款 / 争议** SLA 政策细节:7 天 vs 14 天 vs 30 天?
8. **OpenAI 单价定期同步** — 由人工维护表(月度 review)还是写脚本去爬?爬的话有 ToS 风险。

---

## 12. 一句话总结

复用 user-service 5 张表 + 接通的 Stripe,**新加 1 张 model_pricing 表 + 3 个全局 setting key + 一段内存级 rate limiter**,扣费按真实 token × 折扣后单价(含 cached input 优惠),日额度过日清零,Free 一次性 $2 终身体验金,所有参数管理员实时可改。**Phase A 1.5 周内能做出无 Stripe 的完整闭环**。

---

## Sources

- [OpenAI API Pricing](https://developers.openai.com/api/docs/pricing) — §2.2 单价表数据来源
- [OpenAI Pricing(根)](https://openai.com/api/pricing/)
- [Prompt caching guide](https://developers.openai.com/api/docs/guides/prompt-caching) — cached_input 概念出处
