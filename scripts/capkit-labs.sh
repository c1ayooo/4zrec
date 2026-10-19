#!/usr/bin/env bash
# capkit 传输靶场：为会话类型起可复跑的 Docker 靶机，并打印对应测试环境变量。
#
#   ./scripts/capkit-labs.sh up       启动 SSH / SMB 靶机（WebShell 复用 capkit-lab）
#   ./scripts/capkit-labs.sh down     停止并删除本脚本创建的容器
#   ./scripts/capkit-labs.sh status   查看容器与端口
#
# 所有靶机只绑定 127.0.0.1，口令仅用于本地靶场。
set -euo pipefail

SSH_NAME=capkit-ssh-lab
SSH_PORT=12222
SMB_NAME=capkit-smb-lab
SMB_PORT=445
SMB_USER=capkit
SMB_PASS=capkit
SMB_SHARE=public
MYSQL_NAME=capkit-mysql-lab
MYSQL_PORT=13306
PG_NAME=capkit-pg-lab
PG_PORT=15432
DB_USER=capkit
DB_PASS=capkit
DB_NAME=app

info() { printf '[*] %s\n' "$*"; }
ok() { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }

require_docker() {
  command -v docker >/dev/null 2>&1 || {
    warn "未检测到 docker"
    exit 1
  }
}

up_ssh() {
  if docker ps --format '{{.Names}}' | grep -qx "$SSH_NAME"; then
    ok "$SSH_NAME 已在运行"
    return
  fi
  docker rm -f "$SSH_NAME" >/dev/null 2>&1 || true
  info "启动 SSH 靶机（alpine + openssh，127.0.0.1:${SSH_PORT}）"
  docker run -d --name "$SSH_NAME" -p "127.0.0.1:${SSH_PORT}:22" alpine:latest sh -c '
    apk add --no-cache openssh >/dev/null &&
    ssh-keygen -A >/dev/null &&
    echo "root:capkit" | chpasswd &&
    printf "\nPermitRootLogin yes\nPasswordAuthentication yes\n" >> /etc/ssh/sshd_config &&
    exec /usr/sbin/sshd -D -e'
  # sshd 需要一两秒才监听；端口通了再返回，避免测试抢跑。
  for _ in $(seq 1 30); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${SSH_PORT}") 2>/dev/null; then
      exec 3>&- 3<&- || true
      ok "$SSH_NAME 就绪"
      return
    fi
    sleep 1
  done
  warn "$SSH_NAME 未在 30s 内监听 ${SSH_PORT}"
  return 1
}

up_smb() {
  # capkit 的 SMB 传输调用 smbclient，而 smbclient 只连默认 445 端口，
  # 所以这里必须占用宿主 445；被占用时直接说明，不偷偷换端口。
  if ! python3 - <<'PY' 2>/dev/null
import socket, sys
s = socket.socket()
try:
    s.bind(("127.0.0.1", 445))
except OSError:
    sys.exit(1)
finally:
    s.close()
PY
  then
    warn "宿主 445 端口已被占用（WSL 下通常是 Windows SMB），SMB 靶场无法启动"
    warn "可在 445 空闲的 Linux 主机上重跑；或让 capkit 的 SMBOpener 增加 -p 支持后换端口"
    return 0
  fi
  if docker ps --format '{{.Names}}' | grep -qx "$SMB_NAME"; then
    ok "$SMB_NAME 已在运行"
    return
  fi
  docker rm -f "$SMB_NAME" >/dev/null 2>&1 || true
  info "启动 SMB 靶机（dperson/samba，127.0.0.1:${SMB_PORT}，共享 ${SMB_SHARE}）"
  docker run -d --name "$SMB_NAME" -p "127.0.0.1:${SMB_PORT}:445" dperson/samba \
    -u "${SMB_USER};${SMB_PASS}" -s "${SMB_SHARE};/share;yes;no;no;${SMB_USER}" >/dev/null
  sleep 8
  ok "$SMB_NAME 就绪"
}

up_webshell() {
  if docker ps --format '{{.Names}}' | grep -qx capkit-lab; then
    ok "capkit-lab 已在运行（WebShell 链）"
  else
    info "WebShell 靶机未运行；按 capkit_e2e_test.go 头部的命令构建并启动 capkit-lab:latest"
  fi
}

up_databases() {
  if ! docker ps --format '{{.Names}}' | grep -qx "$MYSQL_NAME"; then
    docker rm -f "$MYSQL_NAME" >/dev/null 2>&1 || true
    info "启动 MySQL 靶机（mysql:8.0，127.0.0.1:${MYSQL_PORT}）"
    docker run -d --name "$MYSQL_NAME" -p "127.0.0.1:${MYSQL_PORT}:3306" \
      -e MYSQL_ROOT_PASSWORD="$DB_PASS" -e MYSQL_DATABASE="$DB_NAME" mysql:8.0 >/dev/null
  fi
  if ! docker ps --format '{{.Names}}' | grep -qx "$PG_NAME"; then
    docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
    info "启动 PostgreSQL 靶机（postgres:16-alpine，127.0.0.1:${PG_PORT}）"
    docker run -d --name "$PG_NAME" -p "127.0.0.1:${PG_PORT}:5432" \
      -e POSTGRES_PASSWORD="$DB_PASS" -e POSTGRES_USER="$DB_USER" -e POSTGRES_DB="$DB_NAME" \
      postgres:16-alpine >/dev/null
  fi
  # 数据库镜像初始化要十几秒，端口通了才算就绪。
  for spec in "${MYSQL_NAME}:${MYSQL_PORT}" "${PG_NAME}:${PG_PORT}"; do
    name="${spec%%:*}"
    port="${spec##*:}"
    for _ in $(seq 1 40); do
      if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
        exec 3>&- 3<&- || true
        ok "$name 就绪"
        break
      fi
      sleep 1
    done
  done
}

down() {
  docker rm -f "$SSH_NAME" "$SMB_NAME" "$MYSQL_NAME" "$PG_NAME" >/dev/null 2>&1 || true
  ok "已删除 $SSH_NAME / $SMB_NAME / $MYSQL_NAME / $PG_NAME"
}

status() {
  docker ps -a --filter "name=${SSH_NAME}" --filter "name=${SMB_NAME}" --filter "name=${MYSQL_NAME}" \
    --filter "name=${PG_NAME}" --filter "name=capkit-lab" \
    --format '{{.Names}}\t{{.Status}}\t{{.Ports}}'
}

case "${1:-up}" in
  up)
    require_docker
    up_ssh
    up_smb
    up_databases
    up_webshell
    cat <<EOF

[*] 跑真实链路测试：
  CAPKIT_LABS=1 CAPKIT_SSH_LAB=127.0.0.1:${SSH_PORT} \\
    go test ./internal/platform/server/ -run 'TestLab|TestSessionAPISSHLab' -v
  CAPKIT_LABS=1 CAPKIT_SMB_LAB=127.0.0.1:${SMB_PORT} \\
    CAPKIT_SMB_USER=${SMB_USER} CAPKIT_SMB_PASS=${SMB_PASS} CAPKIT_SMB_SHARE=${SMB_SHARE} \\
    go test ./internal/platform/server/ -run TestLabSMBSession -v
  CAPKIT_LAB_URL=http://127.0.0.1:18080 CAPKIT_LAB_WEBROOT=/var/www/html \\
    go test ./internal/platform/server/ -run TestCapkitDeployChainAgainstRealTarget -v
  CAPKIT_LABS=1 CAPKIT_MYSQL_LAB=127.0.0.1:${MYSQL_PORT} CAPKIT_PG_LAB=127.0.0.1:${PG_PORT} \\
    CAPKIT_MYSQL_USER=root CAPKIT_MYSQL_PASS=${DB_PASS} CAPKIT_MYSQL_DB=${DB_NAME} \\
    CAPKIT_PG_USER=${DB_USER} CAPKIT_PG_PASS=${DB_PASS} CAPKIT_PG_DB=${DB_NAME} \\
    go test ./internal/platform/server/ -run 'TestLabMySQLSession|TestLabPostgresSession|TestLabDBWriteIsLabelled' -v
  CAPKIT_MYSQL_LAB=127.0.0.1:${MYSQL_PORT} \\
    go test ./internal/platform/server/ -run TestSessionAPIDBLab -v

[!] WinRM 没有可用靶场：真实 WinRM 需要 Windows 目标，Linux 上的 Docker 起不了；
    传输已注册，目前只有单元级覆盖。
EOF
    ;;
  down) require_docker; down ;;
  status) require_docker; status ;;
  *)
    echo "用法: $0 [up|down|status]" >&2
    exit 2
    ;;
esac
