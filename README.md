# sspanel-ssr-rust-backend

用 Rust 重写的 SSPanel **Mod_Mu ShadowsocksR manyuser** 节点后端，替代老的
`Tyrant-2017/shadowsocks`（Python manyuser）运行时，主要为解决其长期运行的内存膨胀问题。

单进程、静态/原生二进制、systemd 托管、无定时重启、无感运维。

## 支持的 profile

当前聚焦一个明确的节点 profile（其余 method/protocol/obfs 组合在配置或用户同步时直接拒绝，不假装支持完整 SSR 矩阵）：

```toml
method   = "rc4-md5"
protocol = "auth_aes128_md5"
obfs     = "plain"
```

支持 **单端口多用户**：carrier 行（`is_multi_user != 0`）提供监听端口与外层
password/method/protocol/obfs；普通用户行（`is_multi_user = 0`）组成鉴权表，
`auth_aes128_md5` 头部里的 uid 识别真实用户，流量 / 在线IP / 审计日志按真实用户上报。

## 已实现的功能（对齐 Python manyuser 运行时）

- SSR wire codec：`rc4-md5` / `auth_aes128_md5` / `plain`
- TCP / UDP 转发（remote relay）
- Mod_Mu webapi 对接：拉取用户、上报流量、心跳、在线IP、审计日志、detect/relay 规则
- 每用户 `forbidden_ip` / `forbidden_port` 阻断（`enforce_forbidden` 开关）
- 每用户 `node_connector` 并发连接数上限（`enforce_conn_limit` 开关）
- 每用户 `node_speedlimit` 限速（令牌桶，面板改多少就限多少，实时生效无需重启；`enforce_speed` 开关）
- detect_rules 审计：命中上报，可选断开（`audit_block` 开关）
- 监听器指纹化热更新：仅当用户/策略真正变化时才重建监听器；纯限速变更不触发重建（无感）
- 流量计数原子化，按 ACK 推进 checkpoint；UDP 关联、在线IP、审计缓冲均带 TTL + 容量上限

## Mod_Mu API

```
GET  /mod_mu/func/ping
GET  /mod_mu/nodes/{id}/info
POST /mod_mu/nodes/{id}/info
GET  /mod_mu/users?node_id=...
POST /mod_mu/users/traffic?node_id=...
POST /mod_mu/users/aliveip?node_id=...
POST /mod_mu/users/detectlog?node_id=...
GET  /mod_mu/func/detect_rules
GET  /mod_mu/func/relay_rules?node_id=...
```

鉴权统一用 query 参数 `key`（对应面板 `muKey` / `muKeyList`）。

## 一键安装 / 对接面板（A 层）

在一台全新机器（root）上执行，会自动装依赖+Rust、拉源码本地编译、交互式录入
面板域名/muKey/节点ID、装 systemd 托管、可选 NAT 端口重定向、设置 journald 磁盘上限并启动：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/junjuntian/sspanel-ssr-rust-backend/main/install.sh)
```

或先克隆再跑：

```bash
git clone https://github.com/junjuntian/sspanel-ssr-rust-backend.git
cd sspanel-ssr-rust-backend
bash install.sh
```

脚本幂等：重复执行只更新代码/配置，**不清空 iptables、不影响其他业务**。

## 常用运维

```bash
systemctl status sspanel-ssr-rust-backend --no-pager
journalctl -u sspanel-ssr-rust-backend -f
systemctl restart sspanel-ssr-rust-backend   # 改 config.toml 后
```

## 手动构建（开发）

```bash
cargo build --release          # 原生二进制
cargo test                     # 单元测试
# 静态可移植二进制(在构建机产出、拷到其他机器跑):
cargo build --release --target x86_64-unknown-linux-musl
```

## 配置

见 `config.example.toml`，字段含义见其中注释。`[node]` 下的 4 个 `enforce_*` /
`audit_block` 是各管控功能的逃生开关，默认全开。

## License

MIT
