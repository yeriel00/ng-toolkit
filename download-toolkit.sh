#!/bin/bash
# download-toolkit.sh — Run on Pi (or any Linux box with internet)
# Downloads static mipsel binaries, packs them into toolkit.tar.gz,
# and optionally serves everything via HTTP for the router to pull.
#
# Two files get served to the router:
#   1. busybox        — standalone bootstrap binary (router needs this first)
#   2. toolkit.tar.gz — everything else packed up (extracted with busybox tar)
#
# Usage:
#   ./download-toolkit.sh              # download + pack only
#   ./download-toolkit.sh --serve      # download + pack + start HTTP server
#   ./download-toolkit.sh --serve 8080 # custom port
#   ./download-toolkit.sh --pack       # just re-pack bin/ into toolkit.tar.gz

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$SCRIPT_DIR/bin"
SERVE_DIR="$SCRIPT_DIR/serve"
mkdir -p "$BIN_DIR" "$SERVE_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; }

# ─── GitHub repo URL (set this to your repo) ───
GITHUB_REPO_RAW="https://raw.githubusercontent.com/CHANGEME/netgearworking/main/toolkit"

# ─── Binary manifest ───
# Format: filename|URL|description
# All must be static mipsel ELF binaries for Linux 2.6+
BINARIES=(
    # BusyBox 1.31.0 — static mipsel, 396 applets (BOOTSTRAP — always standalone)
    "busybox|https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-mipsel|BusyBox 1.31.0 bootstrap"

    # Uncomment as you build/find static mipsel binaries:
    # "dropbearmulti|${GITHUB_REPO_RAW}/bin/dropbearmulti|Dropbear SSH multi-call"
    # "micropython|${GITHUB_REPO_RAW}/bin/micropython|MicroPython interpreter"
    # "socat|${GITHUB_REPO_RAW}/bin/socat|socat network relay"
    # "tcpdump|${GITHUB_REPO_RAW}/bin/tcpdump|tcpdump packet capture"
    # "strace|${GITHUB_REPO_RAW}/bin/strace|strace syscall tracer"
)

# ─── Pack-only mode ───
do_pack() {
    echo "=== Packing toolkit.tar.gz ==="
    cp "$BIN_DIR/busybox" "$SERVE_DIR/busybox" 2>/dev/null && chmod 755 "$SERVE_DIR/busybox"
    ok "busybox → serve/busybox (standalone bootstrap)"

    # Copy deploy script into bin/ for inclusion
    [ -f "$SCRIPT_DIR/scripts/deploy.sh" ] && cp "$SCRIPT_DIR/scripts/deploy.sh" "$BIN_DIR/_deploy.sh"

    pack_files=()
    for f in "$BIN_DIR"/*; do
        [ -f "$f" ] || continue
        name=$(basename "$f")
        [ "$name" = "busybox" ] && continue  # stays standalone
        pack_files+=("$name")
    done

    if [ ${#pack_files[@]} -gt 0 ]; then
        cd "$BIN_DIR"
        tar czf "$SERVE_DIR/toolkit.tar.gz" "${pack_files[@]}"
        size=$(wc -c < "$SERVE_DIR/toolkit.tar.gz" | tr -d ' ')
        ok "Packed ${#pack_files[@]} files → serve/toolkit.tar.gz ($size bytes)"
    else
        warn "No extra binaries — toolkit.tar.gz will only have deploy script"
        [ -f "$BIN_DIR/_deploy.sh" ] && { cd "$BIN_DIR"; tar czf "$SERVE_DIR/toolkit.tar.gz" "_deploy.sh"; }
    fi

    # Also keep deploy script standalone (router can grab before busybox)
    cp "$SCRIPT_DIR/scripts/deploy.sh" "$SERVE_DIR/_deploy.sh" 2>/dev/null

    echo ""
    echo "=== serve/ contents ==="
    ls -lh "$SERVE_DIR"
}

if [[ "$1" == "--pack" ]]; then
    do_pack
    exit 0
fi

echo "========================================"
echo "  Netgear Router Toolkit Downloader"
echo "========================================"
echo "Target: MIPS little-endian (mipsel), Linux 2.6.22, uClibc"
echo "Bin dir: $BIN_DIR"
echo ""

# ─── Download binaries ───
download_count=0
skip_count=0

for entry in "${BINARIES[@]}"; do
    [[ "$entry" == \#* ]] && continue
    IFS='|' read -r name url desc <<< "$entry"

    if [[ "$url" == *"CHANGEME"* ]]; then
        warn "Skipping $name — set GITHUB_REPO_RAW first ($desc)"
        skip_count=$((skip_count + 1))
        continue
    fi

    dest="$BIN_DIR/$name"
    if [ -f "$dest" ]; then
        ok "$name exists ($(wc -c < "$dest" | tr -d ' ') bytes) — $desc"
        skip_count=$((skip_count + 1))
        continue
    fi

    echo -n "  Downloading $name ($desc)... "
    if curl -sL --fail -o "$dest" "$url" 2>/dev/null || wget -q -O "$dest" "$url" 2>/dev/null; then
        chmod 755 "$dest"
        ok "done ($(wc -c < "$dest" | tr -d ' ') bytes)"
        download_count=$((download_count + 1))
    else
        err "FAILED"
        rm -f "$dest"
    fi
done

echo ""
ok "Downloaded: $download_count | Cached: $skip_count"
echo ""

# ─── Verify ELF ───
echo "=== Verifying binaries ==="
for f in "$BIN_DIR"/*; do
    [ -f "$f" ] || continue
    name=$(basename "$f")
    [[ "$name" == _* ]] && continue  # skip scripts
    header=$(xxd -l 6 "$f" 2>/dev/null | head -1)
    if echo "$header" | grep -q "7f45 4c46 0101"; then
        ok "$name — valid mipsel ELF"
    elif echo "$header" | grep -q "7f45 4c46"; then
        warn "$name — ELF but check arch"
    else
        err "$name — NOT an ELF binary"
    fi
done
echo ""

# ─── Pack ───
do_pack

# ─── Serve ───
if [[ "$1" == "--serve" ]]; then
    PORT="${2:-8080}"
    MY_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || ifconfig | grep 'inet ' | grep -v 127 | head -1 | awk '{print $2}')

    echo ""
    echo "========================================"
    echo "  Serving on http://${MY_IP}:${PORT}"
    echo "========================================"
    echo ""
    echo "  Router bootstrap (paste into shell):"
    echo "  ────────────────────────────────────"
    echo "    wget http://${MY_IP}:${PORT}/busybox -O /tmp/busybox && chmod 755 /tmp/busybox"
    echo "    mkdir -p /tmp/bin && /tmp/busybox --install -s /tmp/bin"
    echo "    export PATH=/tmp/bin:\$PATH"
    echo "    wget http://${MY_IP}:${PORT}/toolkit.tar.gz -O /tmp/tk.tar.gz"
    echo "    tar xzf /tmp/tk.tar.gz -C /tmp/bin/ && rm /tmp/tk.tar.gz"
    echo ""
    echo "  Or one-shot deploy:"
    echo "    wget http://${MY_IP}:${PORT}/_deploy.sh -O /tmp/d.sh && sh /tmp/d.sh ${MY_IP} ${PORT}"
    echo ""
    echo "  Press Ctrl+C to stop"
    echo ""

    cd "$SERVE_DIR"
    if command -v python3 &>/dev/null; then
        python3 -m http.server "$PORT"
    elif command -v python &>/dev/null; then
        python -m SimpleHTTPServer "$PORT"
    else
        err "No python found"
    fi
fi
