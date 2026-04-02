# ssl-server

`ssl-server` 是一个基于 Caddy 的前置代理服务。

它做三件事：

- 监听服务器的 `80` 和 `443`
- 按域名把请求转发到本机或其他服务器的后端服务
- 自动管理 HTTPS 证书

如果你把它部署在服务器最前面，后端业务服务通常只需要监听普通 HTTP 端口，不需要自己再配置 TLS。

## 一、如何安装

安装命令：

```bash
sudo bash setup.sh install
```

安装脚本会自动：

- 安装依赖
- 创建运行目录
- 安装 `systemd` 服务
- 安装命令行工具
- 启动 Caddy 和 controller

安装完成后，系统里会有两个主要命令：

- `ssl-proxy`
- `domain-manage`

### 两种模式

安装时你需要选择一种运行模式。

#### `readonly`

只读模式不会申请证书。

它会：

- 从 PostgreSQL 读取域名配置
- 从 PostgreSQL 读取证书
- 把证书缓存到本地
- 渲染并热加载 Caddy 配置
- 提供 `80/443` 的访问入口

适合放在只负责转发流量的节点上。

#### `readwrite`

读写模式会负责证书申请和续签。

它会：

- 做 `readonly` 模式的全部事情
- 自动申请新证书
- 自动续签证书
- 把证书写回 PostgreSQL

通常你至少需要一台 `readwrite` 节点。

### 安装过程中需要输入什么

安装时会要求你输入下面这些信息：

#### 1. 节点模式

可选：

- `readonly`
- `readwrite`

#### 2. PostgreSQL DSN

例如：

```text
postgresql://postgres:password@db.example.com:5432/postgres
```

这个连接串用于连接远程 PostgreSQL。

安装脚本会先验证 DSN 是否真的能连通，验证通过才会继续安装。

#### 3. ACME 邮箱

例如：

```text
ops@example.com
```

这个邮箱主要用于 ACME 账号注册和接收证书相关通知。

说明：

- `readwrite` 模式下必须填写
- `readonly` 模式下也会写入配置，但该节点不会实际执行签发

### 安装完成后会生成哪些内容

默认会使用这些目录：

- 程序目录：`/opt/ssl-proxy`
- 配置文件：`/etc/ssl-proxy/config.yaml`
- 运行数据：`/var/lib/ssl-proxy`
- 日志目录：`/var/log/ssl-proxy`

安装后会创建这些 `systemd` 服务：

- `caddy.service`
- `ssl-proxy-controller.service`
- `ssl-proxy-update.service`
- `ssl-proxy-update.timer`

## 二、如何添加第一个域名

建议第一次使用时，按下面顺序操作。

### 第一步：先修改域名 DNS

先去你的 DNS 服务商后台，把域名解析到这台负责签发证书的机器。

也就是：

- 如果你要申请证书，域名必须先指向 `readwrite` 节点
- 因为当前项目使用的是 `HTTP-01` 验证
- 所以公网必须能访问到这台机器的 `80` 端口

例如你要添加：

```text
api.example.com
```

那就先把它解析到当前 `readwrite` 节点的公网 IP。

### 第二步：运行域名配置命令

最常见的情况，是把域名转发到本机某个服务端口。

例如把：

- `api.example.com`

转发到本机：

- `6111`

执行：

```bash
sudo domain-manage add api.example.com 6111 --sync-now
```

这条命令会做两件事：

- 把域名和回源目标写入数据库
- 立即触发当前机器同步配置

### 其他常见例子

#### 转发到其他服务器

```bash
sudo domain-manage add api.example.com 10.0.0.25:8080 --sync-now
```

#### 使用内网域名回源

```bash
sudo domain-manage add api.example.com backend.internal:8443 --sync-now
```

#### 先不接后端，只先申请证书

```bash
sudo domain-manage add api.example.com --sync-now
```

这种情况下，域名会先纳入证书管理，但暂时不会反代到业务服务。

### 第三步：手动触发签发

如果这是一个新域名，通常还需要在 `readwrite` 节点手动触发一次证书申请：

```bash
sudo domain-manage issue-now api.example.com
```

如果域名还没有解析到当前机器，这条命令会拒绝执行。

你也可以先检查：

```bash
domain-manage check api.example.com
```

## 三、如何查看最终效果

添加完域名后，你通常需要确认三件事：

- 域名配置是否已经写进去
- 证书是否已经成功签发
- 浏览器访问是否已经正常

### 1. 查看域名状态

执行：

```bash
domain-manage status api.example.com
```

重点看这些字段：

- `enabled`
- `upstream_target`
- `certificate_status`
- `certificate_not_after`
- `dns_ipv4`
- `dns_ipv6`
- `points_to_this_host`
- `acme_http_reachable`

如果一切正常，你通常会看到：

- 域名已启用
- 回源目标正确
- DNS 已经指向当前机器
- ACME HTTP 探测可达
- 证书状态正常

### 2. 查看整体服务状态

执行：

```bash
sudo ssl-proxy status
```

这个命令会告诉你：

- Caddy 是否正常运行
- controller 是否正常运行
- 当前节点模式
- 当前机器是否在监听 `80/443`

### 3. 直接访问域名

最终你可以直接在浏览器里打开：

```text
https://api.example.com
```

或者用命令行检查：

```bash
curl -I https://api.example.com
```

如果配置正确，你应该能看到：

- HTTPS 可以正常握手
- 返回的是你的后端服务响应

## 四、最常用命令

### 服务管理

```bash
sudo ssl-proxy install
sudo ssl-proxy start
sudo ssl-proxy stop
sudo ssl-proxy restart
sudo ssl-proxy status
sudo ssl-proxy logs
sudo ssl-proxy update
sudo ssl-proxy timer-status
sudo ssl-proxy uninstall
```

### 域名管理

```bash
domain-manage list
domain-manage get <domain>
domain-manage status <domain>
domain-manage check <domain>
domain-manage logs <domain>
domain-manage add <domain> [upstream_target]
domain-manage set-target <domain> <upstream_target>
domain-manage clear-target <domain>
domain-manage enable <domain>
domain-manage disable <domain>
domain-manage delete <domain>
domain-manage purge <domain>
sudo domain-manage issue-now <domain> [--force]
sudo domain-manage sync-now
```

说明：

- 查询类命令一般不需要 `sudo`
- `issue-now` 和 `sync-now` 需要 `sudo`
- 带 `--sync-now` 的写入命令也需要 `sudo`

## 五、一些重要说明

### 1. 当前不支持通配符证书

也就是不支持：

```text
*.example.com
```

因为当前实现使用的是 `HTTP-01` 验证。

### 2. 回源目标支持哪些格式

支持：

- `6111`
- `127.0.0.1:6111`
- `10.0.0.25:6111`
- `backend.internal:6111`
- `[2001:db8::10]:6111`

其中：

- `6111` 会自动转换为 `127.0.0.1:6111`
- 回源目标也可以留空

### 3. 证书多久检查一次

默认每 `30` 秒同步一次数据库内容。

在 `readwrite` 模式下：

- 距离过期少于 `30` 天时会尝试续签
- 如果签发失败，默认 `3600` 秒后再重试

## 六、排障

### 域名状态不对

先执行：

```bash
domain-manage status <domain>
domain-manage check <domain>
```

### 服务没起来

执行：

```bash
sudo ssl-proxy status
sudo ssl-proxy logs
```

### 查看某个域名相关日志

```bash
domain-manage logs <domain>
```

## 七、项目内部使用了哪些核心表

当前主要使用两张表：

- `routes`
- `certificates`

数据库初始化脚本在：

- `sql/schema.sql`

## 八、一句话总结

最简单的使用方式就是：

1. `sudo bash setup.sh install`
2. 选择 `readwrite` 或 `readonly`
3. 输入 PostgreSQL DSN 和 ACME 邮箱
4. 先把域名 DNS 指向 `readwrite` 节点
5. 执行 `sudo domain-manage add <domain> <target> --sync-now`
6. 执行 `sudo domain-manage issue-now <domain>`
7. 用 `domain-manage status <domain>` 和浏览器访问结果确认最终生效
```
