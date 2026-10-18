#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
# This installer manages only the independent yueti-shanshui application.
VERSION='1.4.1'
SCHEMA=3
EXPECTED_SHA256='5f22a549be640c86011ccf1c348461a2ac29d19f6e40ae0f2e0aeec9914b1b3d'
SERVICE='yueti-shanshui'
APP_ROOT='/opt/shanshui'
DATA_DIR='/opt/shanshui/data'
CONFIG_DIR='/opt/shanshui/config'
BACKUP_ROOT='/opt/shanshui/backups'
ENV_FILE="$CONFIG_DIR/.env"
UNIT='/etc/systemd/system/yueti-shanshui.service'
PACKAGE="${1:-$(dirname "$(readlink -f "$0")")/YuetiShanShui-1.4.1-server.tar.gz}"
STAGE=''
BACKUP=''
PREVIOUS=''
TRANSACTION=0
DATABASE_BACKUP_READY=0
WAS_ACTIVE=0
die() { printf '\n错误：%s\n' "$*" >&2; exit 1; }
info() { printf '\n%s\n' "$*"; }
# The Caddy Docker connector binds to a host bridge address. Check that address
# on subsequent updates too, while keeping wildcard binds checked via loopback.
check_health() {
  "$1" -e 'const fs=require("node:fs");let h=(fs.readFileSync(process.argv[2],"utf8").match(/^HOST=([^\r\n]*)/m)||[])[1]||"127.0.0.1";if(h==="0.0.0.0"||h==="::")h="127.0.0.1";if(h.includes(":"))h="["+h+"]";fetch("http://"+h+":"+process.argv[1]+"/api/health",{signal:AbortSignal.timeout(1500)}).then(async r=>{const x=await r.json();if(!r.ok||x.ok!==true||(process.argv[3]&&x.version!==process.argv[3]))process.exit(1)}).catch(()=>process.exit(1))' "$PORT_VALUE" "$ENV_FILE" "${2:-}"
}
[[ $EUID -eq 0 ]] || die '请使用 sudo bash deploy-shanshui-opt.sh 服务器包.tar.gz 运行。'
[[ $# -le 1 ]] || die '用法：sudo bash deploy-shanshui-opt.sh [服务器包.tar.gz]'
for cmd in tar sha256sum systemctl useradd getent install cp mv readlink mktemp awk grep find chmod chown ln date sort tail flock; do command -v "$cmd" >/dev/null || die "缺少系统工具：$cmd"; done
[[ -d /run/systemd/system ]] || die '需要启用 systemd 的 Linux 服务器（推荐 Ubuntu 22.04/24.04、Debian 12/13）。'
[[ -f "$PACKAGE" ]] || die "找不到服务器包：$PACKAGE"
# A different existing installation needs a separate migration, not a fresh install.
if [[ -f "$UNIT" ]] && ! grep -Fxq "WorkingDirectory=$APP_ROOT/current" "$UNIT"; then
  die '发现山水通讯已安装在其他目录，请先确认迁移方案；本脚本未改动现有服务。'
fi
# Refuse downgrades before modifying or stopping an existing installation.
if [[ -f "$DATA_DIR/minimum-compatible-schema" ]]; then
  MIN_SCHEMA=$(cat "$DATA_DIR/minimum-compatible-schema")
  [[ "$MIN_SCHEMA" =~ ^[0-9]+$ && "$MIN_SCHEMA" -le "$SCHEMA" ]] || die '现有数据需要更新版本的服务器；禁止降级部署。'
fi
[[ "$EXPECTED_SHA256" =~ ^[a-f0-9]{64}$ ]] || die '这是源码模板；请使用交付目录中的部署脚本。'
ACTUAL_SHA256=$(sha256sum -- "$PACKAGE" | awk '{print $1}')
[[ "$ACTUAL_SHA256" == "$EXPECTED_SHA256" ]] || die '服务器包校验不匹配，请将同一次交付的 tar.gz 和 sh 放在一起。'
case "$(uname -m)" in x86_64) ARCH=x64 ;; aarch64|arm64) ARCH=arm64 ;; *) die '本包支持 Linux x86_64 和 ARM64。' ;; esac
PORT_VALUE="${SHANSHUI_PORT:-}"
[[ -z "$PORT_VALUE" || ( "$PORT_VALUE" =~ ^[0-9]{1,5}$ && "$PORT_VALUE" -ge 1024 && "$PORT_VALUE" -le 65535 ) ]] || die 'SHANSHUI_PORT 需为 1024–65535。'
mkdir -p "$APP_ROOT/releases" "$BACKUP_ROOT"
chmod 755 "$APP_ROOT" "$APP_ROOT/releases"
chmod 700 "$BACKUP_ROOT"
# A second installer must not interleave its stop/swap/rollback transaction.
exec 9> "$APP_ROOT/.deploy-lock"
flock -n 9 || die '另一个部署正在进行，请等待它完成后重试。'
STAGE=$(mktemp -d "$APP_ROOT/releases/.staging-XXXXXXXX")
cleanup() { if [[ -n "$STAGE" && "$STAGE" == "$APP_ROOT/releases/.staging-"* && -d "$STAGE" ]]; then rm -rf -- "$STAGE"; fi; }
trap cleanup EXIT
tar -tzf "$PACKAGE" | awk '/^\// || /(^|\/)\.\.(\/|$)/ {bad=1} END {exit bad}' || die '包内存在不安全路径。'
tar -tvzf "$PACKAGE" | awk 'substr($0,1,1)!="-" && substr($0,1,1)!="d" {bad=1} END {exit bad}' || die '包内不允许符号链接、硬链接或设备文件。'
tar -xzf "$PACKAGE" --no-same-owner --no-same-permissions -C "$STAGE"
[[ -f "$STAGE/server/main.js" && -f "$STAGE/public/index.html" && -f "$STAGE/runtimes/linux-$ARCH/bin/node" && -f "$STAGE/SHA256SUMS" ]] || die '包内缺少必要文件。'
[[ -f "$STAGE/public/e2ee.mjs" && -f "$STAGE/public/vendor/openpgp.min.mjs" ]] || die '服务器包缺少端到端加密组件。'
( cd "$STAGE"; sha256sum -c SHA256SUMS >/dev/null ) || die '包内文件校验失败。'
find "$STAGE" -type d -exec chmod 755 {} +
find "$STAGE" -type f -exec chmod 644 {} +
chmod 755 "$STAGE/runtimes/linux-$ARCH/bin/node"
ln -s "runtimes/linux-$ARCH/bin/node" "$STAGE/node"
"$STAGE/node" -e 'const {DatabaseSync}=require("node:sqlite");const d=new DatabaseSync(":memory:");d.exec("CREATE TABLE ok(id INTEGER)");d.close()' 2>/dev/null || die '运行时不能在此系统启动。需 glibc 2.28+，请使用现代 Ubuntu / Debian / RHEL 系统。'
"$STAGE/node" -e 'const r=require(process.argv[1]);if(r.version!=="1.4.1"||r.schema!==3)process.exit(1)' "$STAGE/release.json" || die '版本或数据库格式不匹配。'
if [[ -L "$APP_ROOT/current" ]]; then PREVIOUS=$(readlink -f "$APP_ROOT/current"); [[ "$PREVIOUS" == "$APP_ROOT/releases/"* ]] || die 'current 指向了山水版本目录之外，已停止。'; fi
if [[ -e "$APP_ROOT/current" && ! -L "$APP_ROOT/current" ]]; then die 'current 已存在且不是版本链接，已停止。'; fi
if systemctl is-active --quiet "$SERVICE"; then WAS_ACTIVE=1; fi
if [[ -f "$ENV_FILE" ]]; then
  EXISTING_PORT=$(awk -F= '$1=="PORT" {print $2}' "$ENV_FILE" | tail -n1)
  PORT_VALUE="${PORT_VALUE:-${EXISTING_PORT:-18088}}"
else PORT_VALUE="${PORT_VALUE:-18088}"; fi
[[ "$PORT_VALUE" =~ ^[0-9]{1,5}$ && "$PORT_VALUE" -ge 1024 && "$PORT_VALUE" -le 65535 ]] || die '配置文件 PORT 无效。'
STAMP=$(date -u +%Y%m%dT%H%M%SZ)-$$
RELEASE="$APP_ROOT/releases/$VERSION-$STAMP"
BACKUP="$BACKUP_ROOT/deploy-$STAMP"
mkdir -p "$BACKUP"
[[ -f "$ENV_FILE" ]] && cp -a "$ENV_FILE" "$BACKUP/config.env"
[[ -f "$UNIT" ]] && cp -a "$UNIT" "$BACKUP/service.unit"
printf '%s\n' "$PREVIOUS" > "$BACKUP/previous-release.txt"
rollback() {
  local code="${1:-1}"
  trap - ERR
  if [[ "$TRANSACTION" == 1 ]]; then
    info '部署未通过，正在恢复部署前版本与数据……'
    systemctl stop "$SERVICE" >/dev/null 2>&1 || true
    if [[ "$DATABASE_BACKUP_READY" == 1 ]]; then
      # Immutable attachments are not duplicated or removed. Restore only the
      # database and its journals after the service has stopped.
      for dbfile in shanshui.sqlite shanshui.sqlite-wal shanshui.sqlite-shm minimum-compatible-schema; do
        [[ ! -f "$DATA_DIR/$dbfile" ]] || rm -f -- "$DATA_DIR/$dbfile"
        [[ ! -f "$BACKUP/database/$dbfile" ]] || cp -a -- "$BACKUP/database/$dbfile" "$DATA_DIR/$dbfile"
      done
    fi
    if [[ -f "$BACKUP/config.env" ]]; then cp -a "$BACKUP/config.env" "$ENV_FILE"; fi
    if [[ -n "$PREVIOUS" ]]; then ln -sfn "$PREVIOUS" "$APP_ROOT/current"; else [[ ! -L "$APP_ROOT/current" ]] || rm "$APP_ROOT/current"; fi
    if [[ -f "$BACKUP/service.unit" ]]; then cp -a "$BACKUP/service.unit" "$UNIT"; else [[ ! -f "$UNIT" ]] || rm "$UNIT"; fi
    systemctl daemon-reload || true
    if [[ "$WAS_ACTIVE" == 1 && -n "$PREVIOUS" ]]; then
      systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
      systemctl start "$SERVICE" || true
      local restored=0
      for attempt in {1..30}; do
        if check_health "$PREVIOUS/node" >/dev/null 2>&1; then restored=1; break; fi
        sleep 1
      done
      [[ "$restored" == 1 ]] || printf '旧版数据已恢复，但服务尚未健康，请检查日志。\n' >&2
    fi
    printf '备份和失败现场：%s\n' "$BACKUP" >&2
  fi
  exit "$code"
}
trap 'rollback "$?"' ERR
trap 'rollback 130' INT
trap 'rollback 143' TERM
info "开始部署山水通讯 $VERSION（Linux $ARCH，端口 $PORT_VALUE）"
if ! getent passwd "$SERVICE" >/dev/null; then useradd --system --user-group --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin "$SERVICE"; fi
install -d -m 700 "$CONFIG_DIR"
install -d -m 750 -o "$SERVICE" -g "$SERVICE" "$DATA_DIR"
TRANSACTION=1
if [[ "$WAS_ACTIVE" == 1 ]]; then systemctl stop "$SERVICE"; fi
mkdir -p "$BACKUP/database"
for dbfile in shanshui.sqlite shanshui.sqlite-wal shanshui.sqlite-shm minimum-compatible-schema; do
  [[ ! -f "$DATA_DIR/$dbfile" ]] || cp -a -- "$DATA_DIR/$dbfile" "$BACKUP/database/$dbfile"
done
DATABASE_BACKUP_READY=1
"$STAGE/node" -e 'const net=require("node:net");const s=net.createServer();s.on("error",()=>process.exit(1));s.listen(Number(process.argv[1]),"0.0.0.0",()=>s.close())' "$PORT_VALUE" || { printf '端口 %s 已被其他服务占用。\n' "$PORT_VALUE" >&2; rollback 1; }
if [[ ! -f "$ENV_FILE" ]]; then
  SETUP_TOKEN=$("$STAGE/node" -e 'process.stdout.write(require("node:crypto").randomBytes(24).toString("hex"))')
  printf 'HOST=127.0.0.1\nPORT=%s\nDATA_DIR=%s\nSETUP_TOKEN=%s\nTRUST_PROXY=1\n' "$PORT_VALUE" "$DATA_DIR" "$SETUP_TOKEN" > "$ENV_FILE"
else
  # Preserve secrets, AI configuration, and every unrelated setting across upgrades.
  awk -v port="$PORT_VALUE" -v data="$DATA_DIR" 'BEGIN{p=0;d=0} /^PORT=/{print "PORT="port;p=1;next} /^DATA_DIR=/{print "DATA_DIR="data;d=1;next} {print} END{if(!p)print "PORT="port;if(!d)print "DATA_DIR="data}' "$ENV_FILE" > "$CONFIG_DIR/.env.new"
  mv "$CONFIG_DIR/.env.new" "$ENV_FILE"
  if ! grep -Eq '^SETUP_TOKEN=.+$' "$ENV_FILE"; then printf '\nSETUP_TOKEN=%s\n' "$("$STAGE/node" -e 'process.stdout.write(require("node:crypto").randomBytes(24).toString("hex"))')" >> "$ENV_FILE"; fi
fi
chmod 600 "$ENV_FILE"
chown root:root "$ENV_FILE"
chown -R "$SERVICE:$SERVICE" "$DATA_DIR"
mv "$STAGE" "$RELEASE"
STAGE=''
ln -sfn "$RELEASE" "$APP_ROOT/current"
cat > "$UNIT" <<'UNIT'
[Unit]
Description=Yueti Shanshui Chat
After=network.target

[Service]
Type=simple
User=yueti-shanshui
Group=yueti-shanshui
WorkingDirectory=/opt/shanshui/current
EnvironmentFile=/opt/shanshui/config/.env
ExecStart=/opt/shanshui/current/node /opt/shanshui/current/server/main.js
Restart=on-failure
RestartSec=3
TimeoutStopSec=30
KillSignal=SIGTERM
UMask=0027
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/shanshui/data
RestrictSUIDSGID=true
LockPersonality=true
SyslogIdentifier=yueti-shanshui

[Install]
WantedBy=multi-user.target
UNIT
chmod 644 "$UNIT"
systemctl daemon-reload
systemctl start "$SERVICE"
HEALTHY=0
for attempt in {1..30}; do
  if check_health "$RELEASE/node" "$VERSION" >/dev/null 2>&1; then HEALTHY=1; break; fi
  sleep 1
done
if [[ "$HEALTHY" != 1 ]] || ! systemctl is-active --quiet "$SERVICE"; then
  journalctl -u "$SERVICE" -n 15 --no-pager >&2 || true
  rollback 1
fi
systemctl enable "$SERVICE" >/dev/null
TRANSACTION=0
trap - ERR
# Bound only backups created by this installer. Domain backups and unrelated
# directories are left alone. Keep the latest rollback database/config pair.
find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -name 'deploy-*' -print | sort -r | tail -n +2 | while IFS= read -r old_backup; do
  if [[ "$old_backup" == "$BACKUP_ROOT/deploy-"* && "$old_backup" != "$BACKUP" ]]; then rm -rf -- "$old_backup"; fi
done
info '部署成功。'
HEALTH_HOST=$(awk -F= '$1=="HOST" {print $2}' "$ENV_FILE" | tail -n1)
printf '本机健康检查：http://%s:%s/api/health\n' "${HEALTH_HOST:-127.0.0.1}" "$PORT_VALUE"
SETUP_STATE=$("$RELEASE/node" -e 'const fs=require("node:fs");let h=(fs.readFileSync(process.argv[2],"utf8").match(/^HOST=([^\r\n]*)/m)||[])[1]||"127.0.0.1";if(h==="0.0.0.0"||h==="::")h="127.0.0.1";if(h.includes(":"))h="["+h+"]";fetch("http://"+h+":"+process.argv[1]+"/api/bootstrap",{signal:AbortSignal.timeout(3000)}).then(async r=>{const b=await r.json();if(!r.ok||typeof b.needsSetup!=="boolean")process.exit(1);process.stdout.write(b.needsSetup?"new":"existing")}).catch(()=>process.exit(1))' "$PORT_VALUE" "$ENV_FILE" 2>/dev/null || true)
if [[ "$SETUP_STATE" == new ]]; then
  printf '首次创建管理员所需的部署口令：'
  awk -F= '$1=="SETUP_TOKEN" {print substr($0,index($0,"=")+1)}' "$ENV_FILE"
elif [[ "$SETUP_STATE" == existing ]]; then
  printf '升级完成，请使用原账号登录；账号与聊天数据已保留。\n'
else
  printf '请打开网站确认登录状态；未打印初始化口令，可在配置文件中查看。\n'
fi
printf '\n配置：%s\n数据：%s\n本次备份：%s\n日志：journalctl -u %s -f\n' "$ENV_FILE" "$DATA_DIR" "$BACKUP" "$SERVICE"
printf '\n请配置域名与 HTTPS 反向代理后连接。端到端加密客户端要求 HTTPS。\n代理上传上限设为 26m 或更大；不要公开数据库或备份目录。\n'
