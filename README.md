# ssl-server

一个基于 Caddy 的前置代理服务：

- 监听 `80/443`
- 按域名转发到后端
- 自动管理 HTTPS 证书

## 安装

执行：

```bash
sudo bash setup.sh install
```

安装时会要求输入：

- 模式：`readonly` 或 `readwrite`
- PostgreSQL DSN
- ACME 邮箱

模式说明：

- `readonly`：只读取数据库中的域名和证书，不申请证书
- `readwrite`：负责申请和续签证书，并写回数据库

安装完成后可用命令：

- `ssl-proxy`
- `domain-manage`

## 添加第一个域名

先做 DNS：

- 先把域名解析到 `readwrite` 节点
- 当前使用 `HTTP-01` 验证，所以公网必须能访问这台机器的 `80` 端口

例如把 `api.example.com` 转发到本机 `6111`：

```bash
sudo domain-manage add api.example.com 6111 --sync-now
sudo domain-manage issue-now api.example.com
```

如果是转发到其他服务器：

```bash
sudo domain-manage add api.example.com 10.0.0.25:8080 --sync-now
sudo domain-manage issue-now api.example.com
```

如果只是先申请证书，不接后端：

```bash
sudo domain-manage add api.example.com --sync-now
sudo domain-manage issue-now api.example.com
```

申请前可先检查：

```bash
domain-manage check api.example.com
```

## 查看结果

查看域名状态：

```bash
domain-manage status api.example.com
```

查看服务状态：

```bash
sudo ssl-proxy status
```

直接访问：

```bash
curl -I https://api.example.com
```

## 常用命令

服务管理：

```bash
sudo ssl-proxy start
sudo ssl-proxy stop
sudo ssl-proxy restart
sudo ssl-proxy status
sudo ssl-proxy logs
sudo ssl-proxy update
sudo ssl-proxy uninstall
```

域名管理：

```bash
domain-manage list
domain-manage get <domain>
domain-manage status <domain>
domain-manage check <domain>
domain-manage logs <domain>
sudo domain-manage add <domain> [target] --sync-now
sudo domain-manage set-target <domain> <target> --sync-now
sudo domain-manage clear-target <domain> --sync-now
sudo domain-manage issue-now <domain>
sudo domain-manage sync-now
```

## 说明

- 不支持通配符证书，例如 `*.example.com`
- 支持的回源格式：`6111`、`127.0.0.1:6111`、`10.0.0.25:6111`、`backend.internal:6111`、`[2001:db8::10]:6111`
- 配置文件：`/etc/ssl-proxy/config.yaml`
