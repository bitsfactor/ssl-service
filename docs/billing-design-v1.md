# Develop 计费设计 v1

> 状态:草稿,等用户审 → 落地 Phase A
> 作者:Claude(Develop dev session,2026-05-09)

## 0. TL;DR

- **三档:** Free / Basic ($5/月) / Pro ($10/月)
- **计量单位:** "credits"——一种统一的虚拟单位,一次 chat 消息 = 1 credit、生成一张高清图片 = 10 credits 这样
- **每月发放,过期清零**(下个周期归 0,不结转)
- **追加:** 免费档以外可以买"加油包"(one-time top-up,$5 = 1000 credits 这种,不与订阅绑定)
- **底层数据:** 完全复用 user-service 现有的 `products` + `subscriptions` + `usage_quotas` + `usage_events` + `payments`,**不新建表**
- **支付:** Stripe(已接通),Alipay/WeChat 留 Phase C
- **强制点:** 在 chatbot 的 chat / image API,POST `/api/usage/charge` 到 user-service 做扣费,扣不动就返 429,前端弹升级

---

## 1. 三档参数

| | Free | Basic ($5) | Pro ($10) |
|---|---|---|---|
| 月度 credits | **30** | **300** | **700** |
| 一次 GPT-5.4 对话 | 1 cr | 1 cr | 1 cr |
| 一次 GPT-5.5 对话 | 3 cr | 3 cr | 3 cr |
| 中等画质生图 | 5 cr | 5 cr | 5 cr |
| 高清画质生图 | 10 cr | 10 cr | 10 cr |
| 图片编辑(/edits) | 8 cr | 8 cr | 8 cr |
| 视觉理解上传图 | ❌ | ✓ | ✓ |
| 并发生图 | 1 | 1 | 3 |
| 灵感库收藏数上限 | 50 | 无限 | 无限 |
| 历史对话保留 | 30 天 | 1 年 | 永久 |
| API key | ❌ | 1 个 | 5 个 |
| 优先队列 | ❌ | ❌ | ✓ |
| 客服 | community | 邮件 | 邮件 + 优先 |

**为什么是这些数字?** 见 §2 经济性测算。

**Credits 不结转,周期一过归零。** 这是行业惯例(Midjourney/Replit/早期 ChatGPT 都这么干),理由:
1. 鼓励月度续费而不是囤
2. 避免长期休眠用户突然回来榨干一次
3. 数据模型最简单,`usage_quotas.current_period_consumed` 一个数字就够

---

## 2. 经济性测算

按当前 api.develop.cc/v1 代理的实际成本估算:

| 操作 | 单次成本估算 | Credits 价格 | 1 credit ≈ |
|---|---|---|---|
| GPT-5.4 对话(2k in + 500 out tokens) | $0.005 | 1 cr | $0.005 |
| GPT-5.5 对话 | $0.015 | 3 cr | 同上 |
| 中等画质生图 | $0.04 | 5 cr | $0.008 |
| 高清画质生图 | $0.08 | 10 cr | $0.008 |
| 图片编辑 | $0.06 | 8 cr | $0.0075 |

**1 credit ≈ $0.005 ~ $0.008 平台成本**。

| 档 | 售价 | Credits | 平台成本上限 | 毛利 | 毛利率 |
|---|---|---|---|---|---|
| Free | $0 | 30 | ~$0.20 | -$0.20 | acquisition cost |
| Basic | $5 | 300 | ~$2.40 | $2.60 | 52% |
| Pro | $10 | 700 | ~$5.60 | $4.40 | 44% |

**前提是 Stripe 抽成 ~3% + 运营成本不算大头。**

⚠️ **重大风险:** 如果 Pro 用户清一色刷高清图,700 cr ÷ 10 = 70 张高清图 = $5.60,**贴近成本线**。需要 §6 防滥用。

⚠️ **如果售价偏低:** ChatGPT Plus $20、Midjourney Basic $10、Claude Pro $20。$5/$10 在国际市场属于"激进"。建议:
- $5 档可以是"入门",作为转化漏斗的钩子
- 后续视用户行为加 $20 档(比如"Premium" 1500cr)
- 或者考虑年付折扣(年付 $50 = 月均 $4.17 锁定 Basic 用户)

---

## 3. 数据模型(复用现有表)

### 3.1 products 表上加三行

```python
# user-service 启动时上行 seed 数据(idempotent on code)
products:
  - code: "tier_free"
    kind: "subscription"
    price_cents: 0
    currency: "USD"
    period_days: 30
    stripe_price_id: NULL
    name: { en: "Free", zh: "免费", ja: "無料", ko: "무료", de: "Kostenlos" }
    metadata: { tier_rank: 0, monthly_credits: 30 }
    active: true

  - code: "tier_basic"
    kind: "subscription"
    price_cents: 500
    currency: "USD"
    period_days: 30
    stripe_price_id: "price_xxx"  # 在 Stripe 后台先建,同步过来
    name: { en: "Basic", zh: "基础版", ja: "ベーシック", ko: "기본", de: "Basis" }
    metadata: { tier_rank: 1, monthly_credits: 300 }
    active: true

  - code: "tier_pro"
    kind: "subscription"
    price_cents: 1000
    currency: "USD"
    period_days: 30
    stripe_price_id: "price_yyy"
    name: { en: "Pro", zh: "高级版", ja: "プロ", ko: "프로", de: "Pro" }
    metadata: { tier_rank: 2, monthly_credits: 700, perks: { priority_queue: true, concurrency: 3, api_keys: 5 } }
    active: true
```

**`metadata.tier_rank`** 用来比较档位高低(高档覆盖低档)。
**`metadata.monthly_credits`** 是当订阅生效时,自动 upsert 到 `usage_quotas.limit_qty` 的值。

### 3.2 subscriptions 表的语义

每个用户在任意时刻**可能持有多条 subscription**:
- 一条永远存在的 `tier_free`(注册时自动 grant,`expires_at = NULL` 永不过期)
- 可选一条 `tier_basic` 或 `tier_pro`(Stripe 同步,`expires_at = current_period_end`)

**有效档位 = 用户持有的所有 active subscription 中 `tier_rank` 最高的那个**。

### 3.3 usage_quotas 表的语义

每个用户每档**只有一条**(user_id, product_id) quota:
```
user_id = U
product_id = tier_basic
limit_qty = 300
reset_kind = "monthly_anchor"   # 按订阅锚点
reset_anchor_day = subscription.starts_at.day
current_period_start = 周期起点
current_period_consumed = 已扣的 credits 数
```

降级/升级时,quota 行同步上 metadata 的 monthly_credits。

### 3.4 usage_events 表

每次 charge 写一行:
```
user_id, product_id (扣的是哪一档的额度),
event = "chat_message" | "image_medium" | ... ,
qty = credits 数 (正整数),
metadata = { resource_id, model, ... }
```

唯一索引 `(user_id, event, metadata->>'resource_id')` 做幂等(防止 chatbot 重试时重复扣)。

### 3.5 加油包(top-up,Phase B 引入)

复用 `products` 表:
```
products:
  - code: "topup_1000cr", kind: "one_time", price_cents: 500, metadata: { credits: 1000 }
  - code: "topup_3000cr", kind: "one_time", price_cents: 1200, metadata: { credits: 3000 }
```

加油包不创 subscription,而是**给当前激活档位的 quota 临时 +N 到 limit_qty,周期内消费完不退**。或者新增一列 `topup_balance` 表示"附加余额,优先扣这个"。

实现选 B:加 `usage_quotas.topup_balance int default 0`,charge 时先扣 topup_balance,扣完再扣 current_period_consumed→limit_qty。这样 top-up 跨周期保留。

---

## 4. 计费与扣费流程

### 4.1 注册时

1. user-service POST /api/auth/signup 成功
2. 同事务里:`grant(user_id, "tier_free")` → 写 subscription + 写 usage_quotas(user, tier_free, limit=30, period_start=now)
3. 用户立刻有 30 credits 可用

### 4.2 升级到 Basic / Pro

1. 用户在 user-center /center/billing 点 "Upgrade to Basic"
2. 前端 → user-service POST /api/checkout/create-session(已有)
3. Stripe Checkout → 用户付款
4. Stripe webhook → user-service 写 payments + 写 subscription(`source = "stripe"`, `expires_at = period_end`)
5. **新增逻辑:** webhook handler 在写 subscription 的同事务里,upsert usage_quotas:
   - 老的 tier_free quota 留着(用户可能降级回去)
   - 新的 tier_basic/pro quota 写入 limit_qty
6. 接下来 charge 时,user-service 选 tier_rank 最高的有效档去扣

### 4.3 chatbot 扣费(每次 AI 调用)

```
chatbot/api/chat/route.ts(用户发消息时):
  1. 调 user-service: POST /api/usage/charge
     Headers: X-Service-Token: <secret>
     Body: {
       user_id: <session.user.id>,
       op: "chat_message" | "chat_message_pro",   // 5.4 vs 5.5
       qty: 1,
       resource_id: <messageId>,
       metadata: { model: "gpt-5.4" }
     }

  2. user-service 内部:
     a. 查 user 的 active subscriptions,选 tier_rank 最高的
     b. 查这一档对应的 usage_quotas
     c. 用 SELECT ... FOR UPDATE 读 quota,算 (limit + topup) - consumed
     d. 计算 credits_cost = COST_TABLE[op]  -- 配置写在 user-service 启动时
     e. 如果余额够: consumed += cost, INSERT usage_events, COMMIT, return 200 { balance, tier }
     f. 不够: ROLLBACK, return 429 { current_tier, upgrade_url }

  3. chatbot 收到 200 → 继续往 OpenAI 发请求 → 返回流给用户
     chatbot 收到 429 → 直接返 SSE 错误 + upgrade 提示 → 前端弹升级 modal

  4. 流式失败/超时:
     可选 — 调 POST /api/usage/refund 退回 (resource_id 幂等)
     MVP 不做,小额损失先吃掉
```

### 4.4 周期重置

user-service 后台 cron(或惰性):每分钟扫一次有 quota 到期的用户,把 `current_period_start` 推进到下一锚点,`current_period_consumed = 0`。

惰性方案:每次 charge 时先检查 `now >= current_period_start + period_days`,是的话先 reset 再扣。**MVP 用惰性,无需 cron**。

### 4.5 降级 / 取消

- 用户在 Stripe Customer Portal(已有)操作
- Stripe webhook `customer.subscription.deleted` → user-service 把对应 subscription 标 expired
- 下个周期到期 → 自动回落到 tier_free quota
- 用户已付的本周期不退,subscription 在 expires_at 之前都还有效

---

## 5. 前端体验

### 5.1 chatbot 内

- **header 右上角用户菜单**新增一行小字:`Basic · 287/300` 之类的实时 credits 计数
- **生图前**先看 credits 够不够,不够直接禁掉提交按钮 + 浮 tooltip "需要 5 credits,当前 3 credits"
- **chat 输入框** AI 回复完后右下角小字 `-1 cr · 286 left`(轻量,不打扰)
- **429 弹窗**:不打断当前页面,弹个 modal:`本月额度用完 · 升级到 Basic 还剩 X 天 / 买 1000 credits 加油包($5)`

### 5.2 user-center /center/billing

四块卡片:
1. **当前订阅:** 档位 + 下次续费日期 + Manage(跳 Stripe Portal)
2. **本月用量:** 已用 / 总额 进度条 + 周期内每天柱状图(读 usage_events)
3. **升级:** 卡片墙列 Free / Basic / Pro,按钮 → Stripe Checkout
4. **加油包:** 4-5 种规格的购买按钮(Phase B)
5. **历史账单:** 最近 12 个月 payments 列表 + 下载发票链接

### 5.3 home(develop.cc 落地页,Phase 2)

不在本设计范围,但提一句:home 页定价区直接读 user-service /api/products 渲染,不要硬编码,免得改价时漏掉。

---

## 6. 边缘场景与防滥用

| 场景 | 处理 |
|---|---|
| 用户重试 charge | resource_id 幂等,409 already_charged |
| 并发扣费(用户 5 个 tab 同时发消息) | SELECT FOR UPDATE 串行化 |
| Stripe webhook 丢失 | 用户付了款没生效 → 提供"刷新订阅状态"按钮调 `/api/me/billing/sync`(主动拉 Stripe API 对账) |
| 用户付完款立刻刷新页面 webhook 还没到 | 前端轮询 /api/me/usage 直到看到新 plan(最多 30s) |
| 多账号薅羊毛 | signup 限制 1 IP / 1 邮箱域 / 24h(已有 first-signup advisory lock) + 加 IP 黑名单 + 邀请制可选 |
| 高频小额 charge(机器人) | chatbot 已有 10 req/min 全局限速,够 |
| Pro 用户刷高清图把成本线穿了 | metadata.perks.high_image_cap 限制每周期高清最多 N 张 + 软提示 |
| 退款 | Stripe 后台退,webhook `charge.refunded` → user-service 把 quota 减回去(可选,MVP 不做)|
| 服务降级中(失败的 API call) | charge 已扣 → 不退(MVP);Phase C 加 refund 路径 |

---

## 7. 实施分期

### Phase A:基础闭环(估 1 周)

只做"能跑通"的部分,**不接 Stripe**:

- [ ] user-service seed 三档 product(stripe_price_id 留空)
- [ ] user-service 加 charge 端点 + 成本配置表
- [ ] user-service 加 active-tier 解析逻辑
- [ ] user-service 加惰性 quota reset
- [ ] chatbot /api/chat 和 /api/images 前置 charge
- [ ] chatbot 加 429 处理 + 升级 modal
- [ ] header 显示 credits 余额
- [ ] **管理员**通过 admin grant 手动给测试用户分配 Basic / Pro 档(暂时没法买)

Phase A 结束:三档逻辑全通,扣费正确,只是没法自助付钱。

### Phase B:Stripe 接入(估 3-4 天)

复用现有的 stripe webhook + checkout-session,加:

- [ ] Stripe 后台建 3 个 price(月度订阅)
- [ ] 把 stripe_price_id 填到 products 表
- [ ] 在 user-service stripe webhook 里加"subscription 事件 → 同步档位 quota"
- [ ] /center/billing 页接通 Stripe Checkout 跳转
- [ ] 接通 Stripe Customer Portal 自助管理
- [ ] 加油包 product + checkout 流(可推 Phase C)

Phase B 结束:用户能自己买/取消订阅。

### Phase C:打磨(估 1 周)

- [ ] 加油包(top-up)功能
- [ ] 失败 op 的 refund 路径
- [ ] 年付折扣
- [ ] 团队订阅(seats)
- [ ] Alipay / WeChat Pay(via Stripe support 或 第三方)
- [ ] 邮件提醒(余额低 / 即将续费 / 续费失败)

---

## 8. 开放问题(等你拍板)

1. **价格档:** $5 / $10 是否最终?或者要不要做 $5 / $15 / $30?$10 在国际市场比 ChatGPT 便宜很多,可能 underpriced。
2. **Free 档 30 credits** 够吓不跑人?要不要更慷慨(50?100?)? 慷慨能放大漏斗但贴更多钱。
3. **是否做"年付"折扣** 比如 $50/年 = 月均 $4.17 Basic?锁单率高但管理 prorate 复杂。
4. **加油包要不要做?** 加复杂度但 ARPU 上限高。
5. **Pro 的"优先队列"** 怎么实现?今天我们的 OpenAI 代理对所有用户一视同仁,要做的话需要 chatbot 端按 tier 排队 / 队列分流。这件事可能超 MVP 范围。
6. **未来加新服务**(home 之外比如 docs / agents) 时,是 share credits 还是各服务独立 quota?现在的模型是各产品独立,但用户可能希望 "我买了一档 Pro 通用"。
7. **退款策略:** 7 天无理由?14 天?Stripe 支持自动 dispute,但我们 policy 要明确。
8. **企业 / 团队 plan** 在 v1 是否考虑?如果是,subscription model 需要加 organizations 表(目前只有 user)。

---

## 9. 一句话总结

复用 user-service 现有 5 张表 + Stripe 集成,加 3 行 product + 1 个 charge 端点 + chatbot 前置扣费,**Phase A 1 周内能让管理员手动发档跑通,Phase B 3 天接 Stripe 自助下单**。
