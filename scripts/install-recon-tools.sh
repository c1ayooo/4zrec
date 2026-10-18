#!/bin/sh
# 安装 4zrec 容器/主机常用的预编译 recon CLI。
#
# 由 Dockerfile 调用；也可以在 Linux 主机上直接运行（需要 curl、unzip、tar、find）。
# 目标架构通过 TARGETARCH 指定：amd64 / arm64。
# 版本通过同名环境变量覆盖（Dockerfile 里集中声明）。
set -eu

PREFIX="${PREFIX:-/usr/local/bin}"
TMPDIR="${TMPDIR:-/tmp/4zrec-tools}"
TARGETARCH="${TARGETARCH:-amd64}"

case "$TARGETARCH" in
  amd64) PD_ARCH=amd64; FEROX_ARCH=x86_64 ;;
  arm64) PD_ARCH=arm64; FEROX_ARCH=aarch64 ;;
  *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;;
esac

SUBFINDER_VERSION="${SUBFINDER_VERSION:-2.17.0}"
HTTPX_VERSION="${HTTPX_VERSION:-1.12.0}"
DNSX_VERSION="${DNSX_VERSION:-1.3.1}"
KATANA_VERSION="${KATANA_VERSION:-1.8.0}"
NAABU_VERSION="${NAABU_VERSION:-2.6.1}"
AMASS_VERSION="${AMASS_VERSION:-5.1.1}"
FEROXBUSTER_VERSION="${FEROXBUSTER_VERSION:-2.13.1}"
PUREDNS_VERSION="${PUREDNS_VERSION:-2.1.1}"
SHUFFLEDNS_VERSION="${SHUFFLEDNS_VERSION:-1.2.1}"

mkdir -p "$TMPDIR" "$PREFIX"
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT INT TERM

fetch_pd() {
  name="$1"
  ver="$2"
  curl -fsSL --retry 3 -o "$TMPDIR/$name.zip" \
    "https://github.com/projectdiscovery/$name/releases/download/v${ver}/${name}_${ver}_linux_${PD_ARCH}.zip"
  mkdir -p "$TMPDIR/$name"
  unzip -oq "$TMPDIR/$name.zip" -d "$TMPDIR/$name"
  bin=$(find "$TMPDIR/$name" -type f -name "$name" | head -n 1)
  [ -n "$bin" ] || { echo "missing $name binary in release archive" >&2; exit 1; }
  install -m 0755 "$bin" "$PREFIX/$name"
}

fetch_pd subfinder "$SUBFINDER_VERSION"
fetch_pd httpx "$HTTPX_VERSION"
fetch_pd dnsx "$DNSX_VERSION"
fetch_pd katana "$KATANA_VERSION"
fetch_pd naabu "$NAABU_VERSION"

curl -fsSL --retry 3 -o "$TMPDIR/amass.tgz" \
  "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_linux_${PD_ARCH}.tar.gz"
mkdir -p "$TMPDIR/amass"
tar -xzf "$TMPDIR/amass.tgz" -C "$TMPDIR/amass"
bin=$(find "$TMPDIR/amass" -type f -name amass | head -n 1)
[ -n "$bin" ] || { echo "missing amass binary in release archive" >&2; exit 1; }
install -m 0755 "$bin" "$PREFIX/amass"

curl -fsSL --retry 3 -o "$TMPDIR/ferox.zip" \
  "https://github.com/epi052/feroxbuster/releases/download/v${FEROXBUSTER_VERSION}/${FEROX_ARCH}-linux-feroxbuster.zip"
mkdir -p "$TMPDIR/ferox"
unzip -oq "$TMPDIR/ferox.zip" -d "$TMPDIR/ferox"
bin=$(find "$TMPDIR/ferox" -type f -name feroxbuster | head -n 1)
[ -n "$bin" ] || { echo "missing feroxbuster binary in release archive" >&2; exit 1; }
install -m 0755 "$bin" "$PREFIX/feroxbuster"

curl -fsSL --retry 3 -o "$TMPDIR/puredns.tgz" \
  "https://github.com/d3mondev/puredns/releases/download/v${PUREDNS_VERSION}/puredns-Linux-${PD_ARCH}.tgz"
mkdir -p "$TMPDIR/puredns"
tar -xzf "$TMPDIR/puredns.tgz" -C "$TMPDIR/puredns"
bin=$(find "$TMPDIR/puredns" -type f -name puredns | head -n 1)
[ -n "$bin" ] || { echo "missing puredns binary in release archive" >&2; exit 1; }
install -m 0755 "$bin" "$PREFIX/puredns"

curl -fsSL --retry 3 -o "$TMPDIR/shuffledns.zip" \
  "https://github.com/projectdiscovery/shuffledns/releases/download/v${SHUFFLEDNS_VERSION}/shuffledns_${SHUFFLEDNS_VERSION}_linux_${PD_ARCH}.zip"
mkdir -p "$TMPDIR/shuffledns"
unzip -oq "$TMPDIR/shuffledns.zip" -d "$TMPDIR/shuffledns"
bin=$(find "$TMPDIR/shuffledns" -type f -name shuffledns | head -n 1)
[ -n "$bin" ] || { echo "missing shuffledns binary in release archive" >&2; exit 1; }
install -m 0755 "$bin" "$PREFIX/shuffledns"
