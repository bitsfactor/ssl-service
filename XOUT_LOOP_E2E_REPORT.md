# xout 产品闭环端到端测试报告

测试时间: 2026-05-04
测试目标: xout.develop.cc 产品从「运营建产品」到「用户拿订阅」到「流量计费」到「配额超限」到「撤销」每一步是否打通

## 结论:闭环已打通

14 个端到端检查全部通过 (`outputs/xe2e.sh`):

| # | 步骤 | 结果 |
|---|---|---|
| T0 | 用户 signup | ✓ |
| T1 | `GET /api/admin/xout/inbounds` 返回 `is_user_facing` 标志 | ✓ (修复) |
| T2 | 后台建 xout 产品 | ✓ |
| T3 | 给用户开通订阅,grant 返回 `subscription_token` | ✓ (新增) |
| T4 | `GET /sub/{token}?format=raw` 返回真实 vless URI | ✓ |
| T5 | `GET /sub-qr/{token}.svg` | ✓ |
| T6 | `/api/internal/xout/active-users` 包含该用户 | ✓ |
| T7 | report-traffic 累加 → 配额变 over | ✓ |
| T8 | 超额时 `/sub/{token}` 返回 **410 Gone** | ✓ (修复) |
| T9 | 超额用户从 active-users 中消失 | ✓ |
| T10 | 重置配额后 `/sub` 恢复 200 | ✓ |
| T11 | `POST /api/admin/users/{user_id}/revoke` | ✓ (新增) |
| T11b | revoke 后 `/sub` 返回 404 | ✓ |
| T11c | revoke 后 active-users 移除该用户 | ✓ |

## 这一轮闭环的修复点

1. **超额时 `/sub/{token}` 仍发 vless URI** → 现在返回 410,客户端订阅更新器知道该断
2. **/api/admin/xout/inbounds 没标 vless 还是 socks** → 现在每条 inbound 多 `is_user_facing` 字段;SPA 把非 vless 行灰禁
3. **没办法撤销已开通的订阅** → 加 `POST /api/admin/users/{user_id}/revoke`、admin proxy 路由、Users 页 Revoke 按钮
4. **grant 不返回 token** → 现在直接返回,后台开通完不用再二次查询
5. **遗留测试数据** → `xout-default` / `xe2e-*` / `xout-test-*` 产品已 deactivate;`qa%@example.com` 测试用户 + 关联数据已删

## 还存在的产品空缺(非阻塞,但用户应知道)

1. **us-he 还没装 user-agent**
   - 反映:`xout_node_inbounds` 里 us-he 一行都没有 reality 密钥
   - 后果:任何把 us-he 选进 `inbound_selector` 的产品,/sub 都不会含 us-he 的 URI
   - 选项:给 us-he 部署 user-agent sidecar,或把它从产品 selector 中拿掉

2. **us01 上 13 个 inbound 只有「美国」一条 reality 密钥**
   - 其他 12 个 tag (us01-香港 / us01-日本 / ...) reality 字段全 NULL
   - 反映:agent 上报覆盖不全,只覆盖了第一条 12001 端口
   - 后果:同上 — 选了其他 tag 的产品,那条 URI 不出现
   - 修复方向:debug 或扩展 user_agent_xout 的 report-preset 路径

3. **本次 SPA + admin.py 改动尚未 commit / push**
   - `/Users/leo-m-a/projects/ssl-service/src/ssl_proxy_controller/admin.py` 加了 1 条 USER_SERVICE_PROXY_ROUTES
   - `/Users/leo-m-a/projects/ssl-service/src/ssl_proxy_controller/static/index.html` 加了 Revoke modal + non-vless dim
   - `/Users/leo-m-a/projects/ssl-service/examples/user-service/app/main.py` 已直接 scp 到 us01 + 容器重建,生效
   - 操作建议:本机执行 `dev-push.command` 走正常 commit + restart 流程

## 端到端脚本

复用脚本: `outputs/xe2e.sh` (沙箱里 `/sessions/.../outputs/xe2e.sh`)

```
ADMIN_TOKEN=… INTERNAL_TOKEN=… ./xe2e.sh
```

完整测试在 ~25 秒内跑完 14 个检查。
