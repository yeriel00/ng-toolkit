#!/bin/sh
# deploy.sh — Run ON THE ROUTER after getting root shell
# Downloads busybox (bootstrap) + toolkit.tar.gz from Pi, extracts, sets up
#
# Usage: sh deploy.sh <PI_IP> [PORT]
# Example: sh deploy.sh 172.16.0.3 8080

PI_IP="${1:-172.16.0.3}"
PORT="${2:-8080}"
BASE="http://${PI_IP}:${PORT}"
INSTALL_DIR="/tmp/bin"
USB_CACHE="/tmp/mnt/usb0/part1/toolkit"

echo "================================"
echo "  Router Toolkit Installer"
echo "================================"
echo "Source: $BASE"
echo ""

mkdir -p "$INSTALL_DIR"
mkdir -p "$USB_CACHE" 2>/dev/null

# ─── Step 1: Bootstrap BusyBox ───
echo "=== [1] BusyBox bootstrap ==="
if [ -x "/tmp/busybox" ] && /tmp/busybox --help >/dev/null 2>&1; then
    echo "[+] BusyBox already at /tmp/busybox"
elif [ -f "$USB_CACHE/busybox" ]; then
    echo "[+] Loading BusyBox from USB cache"
    cp "$USB_CACHE/busybox" /tmp/busybox
    chmod 755 /tmp/busybox
else
    echo "    Downloading busybox..."
    wget -O /tmp/busybox "${BASE}/busybox" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "[-] FAILED — can't bootstrap without busybox"
        exit 1
    fi
    chmod 755 /tmp/busybox
    # Cache to USB
    cp /tmp/busybox "$USB_CACHE/busybox" 2>/dev/null
fi

# Install applets
/tmp/busybox --install -s "$INSTALL_DIR" 2>/dev/null
export PATH="$INSTALL_DIR:/bin:/sbin:/usr/bin:/usr/sbin"
count=$(/tmp/busybox --list 2>/dev/null | wc -l)
echo "[+] BusyBox installed — $count applets in $INSTALL_DIR"
echo ""

# ─── Step 2: Download and extract toolkit.tar.gz ───
echo "=== [2] Toolkit archive ==="
TARBALL="/tmp/toolkit.tar.gz"

if [ -f "$USB_CACHE/toolkit.tar.gz" ]; then
    echo "[+] Loading toolkit.tar.gz from USB cache"
    cp "$USB_CACHE/toolkit.tar.gz" "$TARBALL"
else
    echo "    Downloading toolkit.tar.gz..."
    wget -O "$TARBALL" "${BASE}/toolkit.tar.gz" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "[!] No toolkit.tar.gz available — running with BusyBox only"
        TARBALL=""
    else
        # Cache to USB
        cp "$TARBALL" "$USB_CACHE/toolkit.tar.gz" 2>/dev/null
    fi
fi

if [ -n "$TARBALL" ] && [ -f "$TARBALL" ]; then
    echo "    Extracting..."
    tar xzf "$TARBALL" -C "$INSTALL_DIR/" 2>/dev/null
    chmod 755 "$INSTALL_DIR"/* 2>/dev/null
    rm -f "$TARBALL"
    echo "[+] Toolkit extracted to $INSTALL_DIR/"

    # List what we got
    echo "    Contents:"
    for f in "$INSTALL_DIR"/*; do
        [ -f "$f" ] || continue
        name=$(basename "$f")
        # Skip busybox symlinks (hundreds of them)
        [ -L "$f" ] && continue
        size=$(wc -c < "$f" | tr -d ' ')
        echo "      $name ($size bytes)"
    done
fi
echo ""

# ─── Step 3: Create PTY devices ───
echo "=== [3] PTY devices ==="
i=0
while [ $i -le 15 ]; do
    mknod /dev/ptyp$i c 2 $i 2>/dev/null
    mknod /dev/ttyp$i c 3 $i 2>/dev/null
    i=$((i + 1))
done
echo "[+] PTY devices 0-15 created"
echo ""

# ─── Step 4: Enhanced shell wrapper ───
echo "=== [4] Enhanced shell ==="
cat > /tmp/shell << 'SHELLEOF'
#!/bin/sh
export PATH=/tmp/bin:/bin:/sbin:/usr/bin:/usr/sbin
export HOME=/tmp
export TERM=xterm
export PS1='router# '
exec /tmp/bin/ash
SHELLEOF
chmod 755 /tmp/shell

# Start enhanced telnetd on 8889 if not running
if ! netstat -tlnp 2>/dev/null | grep -q ':8889'; then
    telnetd -p 8889 -l /tmp/shell 2>/dev/null && echo "[+] Enhanced shell → port 8889"
else
    echo "[+] Port 8889 already running"
fi
echo ""

# ─── Step 5: Optional services ───

# Dropbear SSH
if [ -x "$INSTALL_DIR/dropbearmulti" ]; then
    echo "=== [5] SSH server ==="
    mkdir -p /tmp/etc/dropbear
    "$INSTALL_DIR/dropbearmulti" dropbearkey -t rsa -f /tmp/etc/dropbear/dropbear_rsa_host_key 2>/dev/null
    "$INSTALL_DIR/dropbearmulti" dropbearkey -t ecdsa -f /tmp/etc/dropbear/dropbear_ecdsa_host_key 2>/dev/null
    ln -sf "$INSTALL_DIR/dropbearmulti" "$INSTALL_DIR/dropbear" 2>/dev/null
    ln -sf "$INSTALL_DIR/dropbearmulti" "$INSTALL_DIR/dbclient" 2>/dev/null
    ln -sf "$INSTALL_DIR/dropbearmulti" "$INSTALL_DIR/scp" 2>/dev/null
    "$INSTALL_DIR/dropbear" -r /tmp/etc/dropbear/dropbear_rsa_host_key \
        -r /tmp/etc/dropbear/dropbear_ecdsa_host_key \
        -p 2222 -B 2>/dev/null && echo "[+] SSH server → port 2222"
    echo ""
fi

# MicroPython test
if [ -x "$INSTALL_DIR/micropython" ]; then
    echo "=== [5] MicroPython ==="
    result=$("$INSTALL_DIR/micropython" -c 'print("works")' 2>&1)
    if [ "$result" = "works" ]; then
        echo "[+] MicroPython working"
    else
        echo "[-] MicroPython failed: $result"
    fi
    echo ""
fi

# ─── Summary ───
ROUTER_IP=$(ifconfig br0 2>/dev/null | grep 'inet addr' | sed 's/.*addr://;s/ .*//')

echo "================================"
echo "  Installation Complete"
echo "================================"
echo ""
echo "Tools:"
for tool in busybox micropython dropbearmulti socat tcpdump strace; do
    if [ -x "$INSTALL_DIR/$tool" ]; then
        echo "  [x] $tool"
    fi
done
echo ""
echo "Ports:"
echo "  8888 — telnet (basic /bin/sh)"
echo "  8889 — telnet (enhanced ash + PATH)"
[ -x "$INSTALL_DIR/dropbearmulti" ] && echo "  2222 — SSH (dropbear)"
echo ""
echo "USB cache: $USB_CACHE"
echo "  (next deploy loads from USB — no Pi needed)"
echo ""
