#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# sspanel-ssr-rust-backend 一键安装/对接脚本 (A 层)
#
# 在一台全新机器上执行本脚本即可：
#   1) 安装基础依赖 (git / curl / jq / iptables)
#   2) 拉取源码并【优先下载 GitHub Releases 的预编译二进制 (musl 静态, 秒装)】;
#      下载失败或 BUILD_FROM_SOURCE=1 时, 自动安装 Rust 工具链回退本地编译
#   3) 交互式录入 面板域名 / muKey / 节点ID(只此 3 项)，生成 config.toml
#   4) 自动从面板节点列表(GET /mod_mu/nodes)读取本节点 server 字段，
#      解析出 监听端口(port=NN) 与 对外端口(#MM)，无需手动输入端口
#   5) 安装 systemd 服务托管(保活) + 对外端口->监听端口 NAT 重定向
#      (单端口多用户策略必须重定向，否则客户端连不上)
#   6) 给 journald 设置磁盘上限(替代 logrotate)，启动并对接面板
#
# 复跑安全(幂等)：重复执行只会更新代码/配置，不会清空 iptables，不动其他业务。
#
# 用法：
#   bash <(curl -fsSL https://raw.githubusercontent.com/junjuntian/sspanel-ssr-rust-backend/main/install.sh)
# 或：
#   git clone https://github.com/junjuntian/sspanel-ssr-rust-backend.git && cd sspanel-ssr-rust-backend && bash install.sh
#
# 可用环境变量覆盖默认值(非交互场景)：
#   REPO_URL  PANEL_BASE_URL  PANEL_KEY  NODE_ID  ASSUME_YES=1
#   (端口默认自动从面板读取；如需强制可另传 SERVER_PORT / REDIRECT_PORT 覆盖)
#   BUILD_FROM_SOURCE=1  强制本地编译, 不下载预编译二进制
#   RELEASE_TAG=v0.1.0   指定下载的 Release 版本(默认 latest)
# ---------------------------------------------------------------------------
set -Eeuo pipefail

REPO_URL="${REPO_URL:-https://github.com/junjuntian/sspanel-ssr-rust-backend.git}"
REPO_SLUG="${REPO_SLUG:-junjuntian/sspanel-ssr-rust-backend}"   # 用于拼 Releases 下载地址
RELEASE_TAG="${RELEASE_TAG:-latest}"                            # latest 或具体 tag (如 v0.1.0)
ASSET_TARGET="${ASSET_TARGET:-x86_64-unknown-linux-musl}"       # 预编译产物的目标三元组
BUILD_FROM_SOURCE="${BUILD_FROM_SOURCE:-0}"                     # 1 = 跳过预编译下载, 强制本地编译
INSTALL_DIR="${INSTALL_DIR:-/root/sspanel-ssr-rust-backend}"
SERVICE_NAME="sspanel-ssr-rust-backend"
SYSTEMD_UNIT="/etc/systemd/system/${SERVICE_NAME}.service"
REDIRECT_SCRIPT="/usr/local/sbin/ssr-portredirect.sh"
REDIRECT_UNIT="/etc/systemd/system/ssr-portredirect.service"
JOURNALD_CONF="/etc/systemd/journald.conf"
JOURNALD_MAX="${JOURNALD_MAX:-200M}"

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; NC='\033[0m'
log()  { echo -e "${BLUE}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERR ]${NC} $*" >&2; }
ok()   { echo -e "${GREEN}[ OK ]${NC} $*"; }

trap 'err "脚本在第 $LINENO 行失败 (exit $?). 请检查上方输出与 systemd 日志。"' ERR

[ "$(id -u)" = "0" ] || { err "必须用 root 执行。"; exit 1; }

# --- 1. 系统依赖 -----------------------------------------------------------
detect_pkg_mgr() {
  if   command -v apt-get >/dev/null 2>&1; then echo apt
  elif command -v dnf     >/dev/null 2>&1; then echo dnf
  elif command -v yum     >/dev/null 2>&1; then echo yum
  else echo unknown; fi
}

# 基础依赖：无论是否本地编译都需要 (拉源码 / 下载二进制 / 解析面板 / NAT)。
install_base_deps() {
  local mgr; mgr="$(detect_pkg_mgr)"
  log "安装基础依赖 (包管理器: ${mgr}) ..."
  case "$mgr" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get install -y git curl ca-certificates iptables jq
      ;;
    dnf) dnf install -y git curl ca-certificates iptables jq || true ;;
    yum) yum install -y git curl ca-certificates iptables jq || true ;;
    *)   warn "未识别的包管理器，跳过依赖安装。请自行确保 git/curl/jq 已就绪。" ;;
  esac
  ok "基础依赖就绪"
}

# 编译器依赖：仅在需要本地编译(回退路径)时安装。
install_compiler_deps() {
  local mgr; mgr="$(detect_pkg_mgr)"
  log "安装编译器依赖 (包管理器: ${mgr}) ..."
  case "$mgr" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get install -y gcc make pkg-config
      ;;
    dnf)
      dnf install -y gcc make pkgconf-pkg-config || dnf groupinstall -y "Development Tools"
      ;;
    yum)
      yum install -y gcc make pkgconfig || yum groupinstall -y "Development Tools"
      ;;
    *)
      warn "未识别的包管理器，跳过编译器依赖。请自行确保 gcc/make 已就绪。"
      ;;
  esac
  ok "编译器依赖就绪"
}

# --- 2. Rust 工具链 --------------------------------------------------------
ensure_rust() {
  # shellcheck disable=SC1090
  [ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
  if command -v cargo >/dev/null 2>&1; then
    ok "检测到 cargo: $(cargo --version)"
    return 0
  fi
  log "未检测到 Rust，安装 rustup (最小化 profile) ..."
  curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
  ok "Rust 安装完成: $(cargo --version)"
}

# --- 3a. 拉取源码 (确定 INSTALL_DIR; 提供 config 位置与编译回退) -----------
fetch_source() {
  if [ -d "${INSTALL_DIR}/.git" ]; then
    log "更新已存在的仓库 ${INSTALL_DIR} ..."
    git -C "${INSTALL_DIR}" fetch --all --prune
    git -C "${INSTALL_DIR}" reset --hard origin/main
  elif [ -f "$(pwd)/Cargo.toml" ] && grep -q 'sspanel-ssr-rust-backend' "$(pwd)/Cargo.toml" 2>/dev/null; then
    log "使用当前源码目录：$(pwd)"
    INSTALL_DIR="$(pwd)"
  else
    log "克隆 ${REPO_URL} -> ${INSTALL_DIR} ..."
    rm -rf "${INSTALL_DIR}"
    git clone "${REPO_URL}" "${INSTALL_DIR}"
  fi
}

# --- 3b. 优先下载 GitHub Releases 预编译二进制 (musl 静态, 任意 x86_64 可跑) -
# 成功则把二进制放到 ${INSTALL_DIR}/target/release/ 并返回 0；否则返回 1 由调用方回退编译。
try_download_prebuilt() {
  local arch asset url_bin url_sha tmp_bin tmp_sha
  arch="$(uname -m)"
  if [ "$arch" != "x86_64" ]; then
    warn "当前架构 ${arch} 无预编译产物(仅提供 x86_64)，将本地编译。"
    return 1
  fi
  asset="${SERVICE_NAME}-${ASSET_TARGET}"
  if [ "${RELEASE_TAG}" = "latest" ]; then
    url_bin="https://github.com/${REPO_SLUG}/releases/latest/download/${asset}"
  else
    url_bin="https://github.com/${REPO_SLUG}/releases/download/${RELEASE_TAG}/${asset}"
  fi
  url_sha="${url_bin}.sha256"

  tmp_bin="$(mktemp)"; tmp_sha="$(mktemp)"
  log "尝试下载预编译二进制 (${RELEASE_TAG}): ${url_bin}"
  if ! curl -fL --retry 3 --connect-timeout 15 -o "${tmp_bin}" "${url_bin}"; then
    rm -f "${tmp_bin}" "${tmp_sha}"
    warn "未找到预编译二进制(可能该版本尚未发布)。"
    return 1
  fi
  # ELF 魔数校验，避免把 404 HTML 当成二进制。
  if [ "$(head -c 4 "${tmp_bin}" | od -An -tx1 | tr -d ' \n')" != "7f454c46" ]; then
    rm -f "${tmp_bin}" "${tmp_sha}"
    warn "下载内容不是 ELF 可执行文件，放弃预编译。"
    return 1
  fi
  # sha256 校验（best-effort：有则必须通过，没有则告警继续）。
  if curl -fL --retry 2 --connect-timeout 15 -o "${tmp_sha}" "${url_sha}" 2>/dev/null; then
    local want got
    want="$(awk '{print $1}' "${tmp_sha}" | head -1)"
    got="$(sha256sum "${tmp_bin}" | awk '{print $1}')"
    if [ -n "${want}" ] && [ "${want}" != "${got}" ]; then
      err "预编译二进制 sha256 校验失败 (期望 ${want} 实际 ${got})，放弃预编译。"
      rm -f "${tmp_bin}" "${tmp_sha}"
      return 1
    fi
    ok "sha256 校验通过"
  else
    warn "未取到 .sha256 校验文件，跳过完整性校验。"
  fi

  mkdir -p "${INSTALL_DIR}/target/release"
  install -m 0755 "${tmp_bin}" "${INSTALL_DIR}/target/release/${SERVICE_NAME}"
  rm -f "${tmp_bin}" "${tmp_sha}"
  return 0
}

# 本地编译回退路径。
build_from_source() {
  install_compiler_deps
  ensure_rust
  log "本地编译 release 二进制 (首次干净编译约 5-10 分钟，视机器性能；之后增量很快) ..."
  ( cd "${INSTALL_DIR}" && cargo build --release )
}

# 取得二进制：优先预编译下载，失败/强制时本地编译。
obtain_binary() {
  BIN_PATH="${INSTALL_DIR}/target/release/${SERVICE_NAME}"
  if [ "${BUILD_FROM_SOURCE}" = "1" ]; then
    log "BUILD_FROM_SOURCE=1，跳过预编译下载，直接本地编译。"
    build_from_source
  elif try_download_prebuilt; then
    ok "已使用 GitHub 预编译二进制（跳过本地编译，秒装）。"
  else
    warn "回退到本地编译。"
    build_from_source
  fi
  [ -x "${BIN_PATH}" ] || { err "二进制缺失: ${BIN_PATH}"; exit 1; }
  ok "二进制就绪: ${BIN_PATH}"
}

# --- 4. 交互式录入并写 config.toml ----------------------------------------
prompt() {  # prompt VAR "提示" "默认值"
  local __var="$1" __msg="$2" __def="${3:-}" __in=""
  if [ -n "${!__var:-}" ]; then return 0; fi          # 已由环境变量提供
  if [ "${ASSUME_YES:-0}" = "1" ]; then printf -v "$__var" '%s' "$__def"; return 0; fi
  if [ -n "$__def" ]; then read -r -p "$__msg [$__def]: " __in || true; else read -r -p "$__msg: " __in || true; fi
  printf -v "$__var" '%s' "${__in:-$__def}"
}

# 从面板节点列表自动解析监听端口/对外端口（只用 域名/muKey/节点ID 三项）。
# 面板 server 字段格式: "IP[;server=域名][|;]port=<监听>#<对外>"
#   node 62 示例:  172.236.156.205;port=558#33033  -> 监听 558, 对外 33033
derive_ports() {
  # 已用环境变量显式指定端口则不覆盖
  if [ -n "${SERVER_PORT:-}" ] && [ -n "${REDIRECT_PORT:-}" ]; then
    log "使用环境变量指定的端口: 监听=${SERVER_PORT} 对外=${REDIRECT_PORT}"
    return 0
  fi
  log "从面板节点列表读取端口 (GET ${PANEL_BASE_URL}/mod_mu/nodes) ..."
  local json server p_listen p_out
  json="$(curl -4 -fsS --max-time 15 "${PANEL_BASE_URL}/mod_mu/nodes?key=${PANEL_KEY}" 2>/dev/null || true)"
  [ -n "$json" ] || { err "无法读取面板节点列表，请检查 面板域名/muKey/网络 是否正确。"; exit 1; }
  server="$(printf '%s' "$json" | jq -r --arg id "${NODE_ID}" '.data[]? | select((.id|tostring)==$id) | .server' 2>/dev/null | head -1)"
  [ -n "$server" ] && [ "$server" != "null" ] || {
    err "节点列表里找不到 node_id=${NODE_ID}（请核对 节点ID 是否属于该 muKey）。"; exit 1; }
  log "节点 ${NODE_ID} 的 server 字段: ${server}"
  p_listen="$(printf '%s' "$server" | grep -oE 'port=[0-9]+'  | head -1 | cut -d= -f2)"
  p_out="$(printf '%s'   "$server" | grep -oE '#[0-9]+'        | head -1 | tr -d '#')"
  [ -n "$p_listen" ] || { err "无法从 server 字段解析监听端口(port=NN): ${server}"; exit 1; }
  SERVER_PORT="${SERVER_PORT:-$p_listen}"
  REDIRECT_PORT="${REDIRECT_PORT:-$p_out}"
  if [ -n "${REDIRECT_PORT}" ]; then
    ok "解析得到: 监听端口=${SERVER_PORT}  对外端口=${REDIRECT_PORT}  (将自动配置 ${REDIRECT_PORT}->${SERVER_PORT} NAT 重定向)"
  else
    warn "server 字段只解析到监听端口=${SERVER_PORT}，未发现对外端口(#MM)，跳过 NAT 重定向。"
    warn "若该节点为单端口多用户且客户端连不上，请确认面板节点端口配置为 port=<监听>#<对外>。"
  fi
}

configure() {
  echo
  log "===== 录入面板对接信息 (只需 3 项) ====="
  prompt PANEL_BASE_URL "面板域名/地址 (例: https://panel.example.com)" ""
  prompt PANEL_KEY      "面板 muKey" ""
  prompt NODE_ID        "节点 ID" ""

  [ -n "${PANEL_BASE_URL}" ] || { err "面板域名不能为空"; exit 1; }
  [ -n "${PANEL_KEY}" ]      || { err "muKey 不能为空"; exit 1; }
  [ -n "${NODE_ID}" ]        || { err "节点 ID 不能为空"; exit 1; }
  PANEL_BASE_URL="${PANEL_BASE_URL%/}"   # 去掉结尾斜杠

  derive_ports

  local cfg="${INSTALL_DIR}/config.toml"
  if [ -f "$cfg" ]; then cp -a "$cfg" "${cfg}.bak.$(date +%Y%m%d%H%M%S)"; fi
  cat > "$cfg" <<EOF
[panel]
base_url = "${PANEL_BASE_URL}"
key = "${PANEL_KEY}"
node_id = ${NODE_ID}
request_timeout_secs = 10
poll_interval_secs = 60
traffic_report_interval_secs = 60
heartbeat_interval_secs = 60
ipv4_only = true

[node]
listen_host = "0.0.0.0"
method = "rc4-md5"
protocol = "auth_aes128_md5"
obfs = "plain"
server_port = ${SERVER_PORT}
timeout_secs = 300
workers = 1
tcp_enabled = true
udp_enabled = true
enforce_forbidden = true
enforce_conn_limit = true
audit_block = true
enforce_speed = true

[limits]
max_users = 4096
max_sessions = 65536
session_ttl_secs = 600
max_udp_associations = 32768
udp_association_ttl_secs = 180
max_alive_ips = 65536
alive_ip_ttl_secs = 600
max_detect_logs = 8192
detect_log_ttl_secs = 3600
max_accepts_per_port = 2048
EOF
  chmod 600 "$cfg"
  ok "已写入 ${cfg}"
}

# --- 5. systemd 服务 -------------------------------------------------------
install_service() {
  log "写入 systemd 服务 ${SYSTEMD_UNIT} ..."
  cat > "${SYSTEMD_UNIT}" <<EOF
[Unit]
Description=SSPanel SSR Rust Backend (node ${NODE_ID})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${BIN_PATH} --config config.toml
Environment=RUST_LOG=info
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
  ok "systemd 服务已安装"
}

# --- 6. 可选 NAT 端口重定向 ------------------------------------------------
install_redirect() {
  [ -n "${REDIRECT_PORT}" ] || { log "未配置 NAT 重定向，跳过。"; return 0; }
  log "安装 ${REDIRECT_PORT} -> ${SERVER_PORT} NAT 重定向 (幂等) ..."
  cat > "${REDIRECT_SCRIPT}" <<EOF
#!/bin/sh
# 幂等确保 ${REDIRECT_PORT} -> ${SERVER_PORT} REDIRECT 规则存在(nat 表)。重复执行安全。
ensure() { iptables -t nat -C "\$@" 2>/dev/null || iptables -t nat -A "\$@"; }
ensure PREROUTING -p tcp --dport ${REDIRECT_PORT} -j REDIRECT --to-ports ${SERVER_PORT}
ensure PREROUTING -p udp --dport ${REDIRECT_PORT} -j REDIRECT --to-ports ${SERVER_PORT}
ensure OUTPUT -p tcp --dport ${REDIRECT_PORT} -j REDIRECT --to-ports ${SERVER_PORT}
ensure OUTPUT -p udp --dport ${REDIRECT_PORT} -j REDIRECT --to-ports ${SERVER_PORT}
EOF
  chmod +x "${REDIRECT_SCRIPT}"
  cat > "${REDIRECT_UNIT}" <<EOF
[Unit]
Description=SSR ${REDIRECT_PORT}->${SERVER_PORT} nat REDIRECT rules
After=network.target

[Service]
Type=oneshot
ExecStart=${REDIRECT_SCRIPT}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now ssr-portredirect >/dev/null 2>&1 || systemctl restart ssr-portredirect
  ok "NAT 重定向已生效"
}

# --- 7. journald 磁盘上限 (替代 logrotate) --------------------------------
cap_journald() {
  log "为 journald 设置磁盘上限 ${JOURNALD_MAX} ..."
  [ -f "${JOURNALD_CONF}" ] && cp -a "${JOURNALD_CONF}" "${JOURNALD_CONF}.bak.$(date +%Y%m%d%H%M%S)"
  sed -i '/# >>> sspanel-ssr managed >>>/,/# <<< sspanel-ssr managed <<</d' "${JOURNALD_CONF}" 2>/dev/null || true
  grep -q '^\[Journal\]' "${JOURNALD_CONF}" 2>/dev/null || echo '[Journal]' >> "${JOURNALD_CONF}"
  cat >> "${JOURNALD_CONF}" <<EOF
# >>> sspanel-ssr managed >>>
SystemMaxUse=${JOURNALD_MAX}
SystemMaxFileSize=20M
# <<< sspanel-ssr managed <<<
EOF
  systemctl restart systemd-journald || warn "journald 重启失败，可忽略(配置已写入，下次重启生效)"
  ok "journald 上限已设置"
}

# --- 8. 启动并校验 ---------------------------------------------------------
start_and_verify() {
  log "启动 ${SERVICE_NAME} ..."
  systemctl restart "${SERVICE_NAME}"
  sleep 3
  echo
  if systemctl is-active --quiet "${SERVICE_NAME}"; then
    ok "服务已启动 (active)"
  else
    err "服务未能启动，最近日志："
    journalctl -u "${SERVICE_NAME}" -n 30 --no-pager || true
    exit 1
  fi
  echo "----------------------------------------"
  echo "安装目录:   ${INSTALL_DIR}"
  echo "二进制:     ${BIN_PATH}"
  echo "配置文件:   ${INSTALL_DIR}/config.toml"
  echo "面板:       ${PANEL_BASE_URL}  (node_id=${NODE_ID})"
  echo "监听端口:   ${SERVER_PORT}${REDIRECT_PORT:+   (NAT ${REDIRECT_PORT}->${SERVER_PORT})}"
  echo "----------------------------------------"
  echo "常用命令:"
  echo "  systemctl status ${SERVICE_NAME} --no-pager"
  echo "  journalctl -u ${SERVICE_NAME} -f"
  echo "  (改配置后) systemctl restart ${SERVICE_NAME}"
  echo "----------------------------------------"
  log "观察最近日志确认已对接面板："
  journalctl -u "${SERVICE_NAME}" -n 12 --no-pager || true
}

main() {
  install_base_deps
  fetch_source
  obtain_binary
  configure
  install_service
  install_redirect
  cap_journald
  start_and_verify
  echo
  ok "全部完成。"
}

main "$@"
