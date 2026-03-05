# Modernization Plan: oschameleon → Python 3 / Current Linux Kernels

**Decisions made:**
- `gevent` → `asyncio`
- `python-nfqueue` → `netfilterqueue>=1.1.0`
- `netifaces` → `psutil`
- iptables: auto-detect `iptables` vs `nftables` at runtime
- Tests: add unit tests for template parsing, session tracking, ext_ip, nfqueue callbacks
- Templates: add Windows 10/11 and Ubuntu 22.04 LTS fingerprint files

**Implementation status (2026-03-05):**
- [x] Step 1 — `requirements.txt` updated
- [x] Step 2 — `setup.py` updated
- [x] Steps 3-7 — Phase 2 import refactor + `oschameleon/__main__.py`
- [x] Steps 8-9 — Phase 3 `netfilterqueue` migration in `helper.py` and `osfuscation.py`
- [x] Steps 10-11 — Phase 4 entrypoint migration (`gevent` → stdlib fork/sleep)
- [x] Steps 12-13 — Phase 5 Python 3 bytes/str fixes
- [x] Step 14 — Phase 6 `netifaces` → `psutil`
- [x] Step 15 — Phase 7 firewall hardening + iptables/nft auto-detect
- [x] Step 16 — Phase 8 external IP URL update (HTTPS endpoints)
- [x] Steps 17-18 — Phase 9 new templates (`windows_10.txt`, `ubuntu_2204.txt`)
- [x] Step 19 — Phase 10 test suite expansion
- [x] Step 20 — Phase 11 README modernization
- [x] Step 21 — Phase 11 changelog release entry
- [x] All planned steps (1-21) completed

---

## Phase 1 — Dependencies & Setup

### Step 1 — `requirements.txt` (Completed 2026-03-05)

Replace entire file contents:

```
netfilterqueue>=1.1.0
psutil>=5.9.0
scapy>=2.5.0
requests>=2.31.0
```

Removes: `netifaces==0.10.9`, `scapy==2.4.2` (pinned ancient version)  
Removes: `gevent` (never in file but imported everywhere — replaced by asyncio)  
Removes: `nfqueue` (was a system package, replaced by `netfilterqueue`)

### Step 2 — `setup.py` (Completed 2026-03-05)

- Add `find_packages()` to capture `oschameleon.session` and `oschameleon.stack_packet` sub-packages (currently missing from `packages=` list)
- Set `python_requires=">=3.8"`
- Update `Programming Language :: Python` classifier to `Programming Language :: Python :: 3`
- Replace `test_suite="nose.collector"` and `tests_require="nose"` with `tests_require=["pytest"]`
- Update `long_description` to use `encoding="utf-8"` in `open()`

---

## Phase 2 — Python 3 Import Structure

All `stack_packet/` and `session/` modules use bare absolute imports that work in Python 2 but fail as package imports in Python 3.

### Step 3 — `oschameleon/stack_packet/TCP_.py` (Completed 2026-03-05)

```python
# OLD
from IP_ import ReplyPacket
from IP_ import reverse_crc
from helper import drop_packet
from helper import forward_packet

# NEW
from .IP_ import ReplyPacket
from .IP_ import reverse_crc
from .helper import drop_packet
from .helper import forward_packet
```

### Step 4 — `oschameleon/stack_packet/ICMP_.py` (Completed 2026-03-05)

```python
# OLD
from IP_ import ReplyPacket
from helper import drop_packet
from helper import forward_packet

# NEW
from .IP_ import ReplyPacket
from .helper import drop_packet
from .helper import forward_packet
```

### Step 5 — `oschameleon/stack_packet/UDP_.py` (Completed 2026-03-05)

```python
# OLD
from ICMP_ import send_ICMP_reply
from helper import drop_packet
from helper import forward_packet

# NEW
from .ICMP_ import send_ICMP_reply
from .helper import drop_packet
from .helper import forward_packet
```

### Step 6 — `oschameleon/session/session.py` (Completed 2026-03-05)

```python
# OLD
from ext_ip import Ext_IP

# NEW
from .ext_ip import Ext_IP
```

### Step 7 — `oschameleon/osfuscation.py` and `oschameleon/oschameleonRun.py` (Completed 2026-03-05)

Convert to package-relative imports:

```python
# OLD (osfuscation.py)
from parse_fp import get_os_pattern
import session
from stack_packet.ICMP_ import check_ICMP_probes
from stack_packet.TCP_ import check_TCP_probes
from stack_packet.UDP_ import check_UDP_probe
from stack_packet.helper import flush_tables, forward_packet, rules

# NEW
from oschameleon.parse_fp import get_os_pattern
from oschameleon import session
from oschameleon.stack_packet.ICMP_ import check_ICMP_probes
from oschameleon.stack_packet.TCP_ import check_TCP_probes
from oschameleon.stack_packet.UDP_ import check_UDP_probe
from oschameleon.stack_packet.helper import flush_tables, forward_packet, rules
```

```python
# OLD (oschameleonRun.py)
from osfuscation import OSFuscation
from session.log import Log
import session
from stack_packet.helper import flush_tables

# NEW
from oschameleon.osfuscation import OSFuscation
from oschameleon.session.log import Log
from oschameleon import session
from oschameleon.stack_packet.helper import flush_tables
```

Also add `oschameleon/__main__.py` so the tool can be run as `python -m oschameleon` (Completed 2026-03-05):

```python
# oschameleon/__main__.py
from oschameleon.oschameleonRun import OSChameleon
if __name__ == "__main__":
    c = OSChameleon()
    c.start()
```

---

## Phase 3 — nfqueue → netfilterqueue API Migration

The `python-nfqueue` package is Python 2 only. The modern replacement is `netfilterqueue` (pip-installable, Python 3 native).

API differences:
| Old (nfqueue) | New (netfilterqueue) |
|---|---|
| `import nfqueue` | `from netfilterqueue import NetfilterQueue` |
| `nfq_packet.get_data()` | `nfq_packet.get_payload()` |
| `nfq_packet.set_verdict(nfqueue.NF_ACCEPT)` | `nfq_packet.accept()` |
| `nfq_packet.set_verdict(nfqueue.NF_DROP)` | `nfq_packet.drop()` |
| `q = nfqueue.queue(); q.set_callback(cb); q.fast_open(0, socket.AF_INET)` | `nfq = NetfilterQueue(); nfq.bind(0, cb)` |
| `q.process_pending(5)` | `nfq.run_socket(sock)` (with asyncio) |
| `q.unbind(socket.AF_INET); q.close()` | `nfq.unbind()` |
| No equivalent | `sock = nfq.get_socket()` (for asyncio fd integration) |

### Step 8 — `oschameleon/stack_packet/helper.py` (Completed 2026-03-05)

```python
# OLD
import nfqueue

def forward_packet(nfq_packet):
    nfq_packet.set_verdict(nfqueue.NF_ACCEPT)

def drop_packet(nfq_packet):
    nfq_packet.set_verdict(nfqueue.NF_DROP)

# NEW (remove nfqueue import entirely)
def forward_packet(nfq_packet):
    nfq_packet.accept()

def drop_packet(nfq_packet):
    nfq_packet.drop()
```

### Step 9 — `oschameleon/osfuscation.py` (callback + queue setup) (Completed 2026-03-05)

```python
# OLD
import nfqueue, socket, gevent

def callback(self, nfq_packet):
    pkt = IP(nfq_packet.get_data())
    ...

# In OSFuscation.run():
q = nfqueue.queue()
q.set_callback(ProcessPKT(...).callback)
q.fast_open(0, socket.AF_INET)
q.set_queue_maxlen(-1)
workers = [gevent.spawn(cls.worker, q) for _ in range(2)]
gevent.joinall(workers)

# NEW
from netfilterqueue import NetfilterQueue
import asyncio

def callback(self, nfq_packet):
    pkt = IP(nfq_packet.get_payload())   # get_payload() instead of get_data()
    ...

# In OSFuscation.run():
nfq = NetfilterQueue()
nfq.bind(0, ProcessPKT(os_pattern, session_, debug).callback)
sock = nfq.get_socket()
loop = asyncio.get_event_loop()
loop.add_reader(sock, nfq.run_socket, sock)
try:
    loop.run_forever()
except KeyboardInterrupt:
    loop.remove_reader(sock)
    nfq.unbind()
    flush_tables()
    print("Exiting...")
```

Also remove the `OSFuscation.worker()` classmethod — no longer needed.

---

## Phase 4 — gevent → asyncio (in entry point)

### Step 10 — `oschameleon/oschameleonRun.py` (Completed 2026-03-05)

Remove:
- `import gevent.monkey`
- `import nfqueue`
- `gevent.monkey.patch_all()`
- The `nfqueue` version check block

Replace fork/sleep logic:

```python
# OLD
import gevent.monkey
gevent.monkey.patch_all()

pid = gevent.fork()
if pid == 0:
    child_process = gevent.spawn(self.root_process)
    child_process.join()
    flush_tables()
else:
    os.setgid(wanted_gid)
    os.setuid(wanted_uid)
    while True:
        try:
            gevent.sleep(1)
        except KeyboardInterrupt:
            break

# NEW
import time

pid = os.fork()
if pid == 0:
    self.root_process()
    flush_tables()
else:
    os.setgid(wanted_gid)
    os.setuid(wanted_uid)
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            break
```

### Step 11 — `oschameleon/root_fork.py` (Completed 2026-03-05)

Apply same gevent removal / `os.fork` + `time.sleep` changes. This file duplicates most of `oschameleonRun.py` — it can be slimmed down or deprecated with a notice pointing to `oschameleonRun.py`.

---

## Phase 5 — Python 3 bytes/str Fixes

### Step 12 — `oschameleon/stack_packet/IP_.py` (crc32 functions) (Completed 2026-03-05)

In Python 3, iterating over a `bytes` object yields `int`, not `str`, so `ord(c)` raises `TypeError`.

```python
# OLD (lines ~96, ~109)
crc = (crc >> 8) ^ crc32_table[crc & 0xFF ^ ord(c)]
fwd_crc = (fwd_crc >> 8) ^ crc32_table[fwd_crc & 0xFF ^ ord(c)]

# NEW
byte_val = c if isinstance(c, int) else ord(c)
crc = (crc >> 8) ^ crc32_table[crc & 0xFF ^ byte_val]
# (same pattern for fwd_crc)
```

### Step 13 — `oschameleon/stack_packet/UDP_.py` (bytes comparison) (Completed 2026-03-05)

In Python 3, `bytes[index]` returns `int`, not a single-char `str`.

```python
# OLD (lines 21-24)
pkt[UDP].payload.load[0] == "C"
pkt[UDP].payload.load[1] == "C"
pkt[UDP].payload.load[2] == "C"

# NEW
pkt[UDP].payload.load[0] == ord("C")   # 67
pkt[UDP].payload.load[1] == ord("C")
pkt[UDP].payload.load[2] == ord("C")
```

---

## Phase 6 — netifaces → psutil

### Step 14 — `oschameleon/session/session.py` (Completed 2026-03-05)

```python
# OLD
from netifaces import AF_INET, AF_INET6, AF_LINK, AF_PACKET, AF_BRIDGE
import netifaces as ni

# in externalIP():
self.my_ip = ni.ifaddresses(interface)[AF_INET][0]["addr"]

# NEW
import socket as _socket
import psutil

# in externalIP():
addrs = psutil.net_if_addrs().get(interface, [])
for addr in addrs:
    if addr.family == _socket.AF_INET:
        self.my_ip = addr.address
        break
else:
    raise ValueError(f"No IPv4 address found on interface '{interface}'")
```

---

## Phase 7 — iptables / nftables Auto-detection + Security Fix

All `os.system("iptables " + server + ...)` calls have a **shell injection vulnerability** — if `server` contains shell metacharacters, arbitrary commands execute as root.

### Step 15 — `oschameleon/stack_packet/helper.py` (major rewrite) (Completed 2026-03-05)

```python
import shutil
import subprocess

def _get_ipt_tool():
    """Return the iptables binary to use, or None if nftables only."""
    for cmd in ("iptables", "iptables-legacy"):
        if shutil.which(cmd):
            return cmd
    return None   # caller must use nft path

def _run(*args):
    """Run a command safely (no shell=True), raise on failure."""
    subprocess.run(list(args), check=True)

def flush_tables():
    tool = _get_ipt_tool()
    if tool:
        _run(tool, "-F")
    else:
        _run("nft", "flush", "ruleset")

def rules(server):
    tool = _get_ipt_tool()
    if tool:
        # SSH allow rules (parameterized, no shell interpolation)
        _run(tool, "-A", "INPUT",  "-p", "tcp", "-s", server, "--dport", "63712",
             "-m", "state", "--state", "NEW,ESTABLISHED", "-j", "ACCEPT")
        _run(tool, "-A", "OUTPUT", "-p", "tcp", "-d", server, "--sport", "63712",
             "-m", "state", "--state", "ESTABLISHED", "-j", "ACCEPT")
        _run(tool, "-A", "OUTPUT", "-p", "tcp", "-d", server, "--sport", "63712",
             "-m", "state", "--state", "NEW,ESTABLISHED", "-j", "ACCEPT")
        _run(tool, "-A", "INPUT",  "-p", "tcp", "-s", server, "--dport", "63712",
             "-m", "state", "--state", "ESTABLISHED", "-j", "ACCEPT")
        _run(tool, "-A", "INPUT", "-j", "NFQUEUE", "--queue-num", "0")
    else:
        # nftables equivalent
        _run("nft", "add", "table", "inet", "oschameleon")
        _run("nft", "add", "chain", "inet", "oschameleon", "input",
             "{", "type", "filter", "hook", "input", "priority", "0", ";", "}")
        _run("nft", "add", "rule", "inet", "oschameleon", "input",
             "tcp", "sport", "63712", "ip", "saddr", server, "accept")
        _run("nft", "add", "rule", "inet", "oschameleon", "input",
             "queue", "num", "0")
```

> **Security note:** Using `subprocess.run(list(args), check=True)` (no `shell=True`) completely eliminates the injection surface. The `server` value is passed as a distinct argv element, never interpolated into a shell string.

---

## Phase 8 — External IP URL Updates

### Step 16 — `oschameleon/session/ext_ip.py` (Completed 2026-03-05)

The two original URLs (`queryip.net`, `ifconfig.me`) used plain HTTP and `queryip.net` is no longer active.

```python
# OLD
urls_ = ["http://queryip.net/ip/", "http://ifconfig.me/ip"]

# NEW
urls_ = ["https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"]
```

---

## Phase 9 — New OS Fingerprint Templates

### Step 17 — `oschameleon/template/windows_10.txt` (Completed 2026-03-05)

Add a Windows 10 / Windows 11 nmap fingerprint in the existing `PROBE_TYPE(field=value%...)` format, sourced from the public nmap-os-db. Key characteristics:
- TTL ~128, TS=7 (10ms granularity), responds to most probes
- Follows Windows TCP ISN generation (random, high variance)

### Step 18 — `oschameleon/template/ubuntu_2204.txt` (Completed 2026-03-05)

Add an Ubuntu 22.04 LTS (Linux 5.15 kernel) fingerprint. Key characteristics:
- TTL ~64, TS=A (1ms granularity), strong SEQ response

Both files must parse cleanly through `get_os_pattern()` in `parse_fp.py`.

---

## Phase 10 — Tests

### Step 19 — `tests/test_basic.py` (Completed 2026-03-05)

Expand significantly. New test classes:

**`TestTemplateParsing`** (no root required, no network)
- `test_load_simatic` — load `template/SIMATIC_300_PLC.txt`, assert `TTL == 0x20`, `PROBES_2_SEND["T2"] == False`
- `test_load_3com` — load `template/3com_superstack_3.txt`, assert TTL and GCD fields present
- `test_load_windows7` — assert `PROBES_2_SEND["T1"] == True`
- `test_load_windows10` — smoke-test the new template
- `test_load_ubuntu2204` — smoke-test the new template

**`TestSessionTracking`** (no root required)
- `test_new_session` — `Session.in_session()` with new IP creates a session entry
- `test_renew_session` — second call with same IP renews the timeout
- `test_session_timeout` — manually expire a session, verify it's treated as new

**`TestExtIP`** (mocked network)
- `test_valid_ip` — mock `requests.get` returning `"1.2.3.4"`, assert returned correctly
- `test_invalid_ip` — mock returning `"not-an-ip"`, assert falls through to next URL
- `test_all_fail` — mock all URLs failing, assert returns `None`

**`TestNFQueueCallbacks`** (mocked nfq_packet)
- `test_forward_packet` — mock object with `.accept()`, assert called
- `test_drop_packet` — mock object with `.drop()`, assert called

Keep original:
```python
def test_title(self):
    self.assertTrue(oschameleon.__title__ == 'oschameleon')
```

---

## Phase 11 — Documentation

### Step 20 — `README.md` (Completed 2026-03-05)

Update:
- Python 2.7 → Python 3.8+
- Remove `python-nfqueue` (system package), add `netfilterqueue` (pip)
- Replace `netifaces` with `psutil`
- Update `pip install` instructions
- Add note about iptables/nftables auto-detection
- Update usage example to show all new templates
- Update invocation to `python -m oschameleon` or `python oschameleonRun.py`

### Step 21 — `Changelog.txt` (Completed 2026-03-05)

Add entry:

```
v0.2.0 (2026-03-XX)
- Ported to Python 3.8+
- Replaced python-nfqueue with netfilterqueue
- Replaced gevent with asyncio
- Replaced netifaces with psutil
- Auto-detect iptables vs nftables
- Fixed shell injection vulnerability in helper.py (os.system → subprocess.run)
- Fixed Python 3 bytes/str incompatibilities in UDP_.py and IP_.py
- Added Windows 10/11 and Ubuntu 22.04 fingerprint templates
- Expanded test suite with pytest
```

---

## Relevant Files

| File | Phase | Change summary |
|---|---|---|
| `requirements.txt` | 1 | Full replacement |
| `setup.py` | 1 | find_packages, Py3, pytest |
| `stack_packet/helper.py` | 3, 7 | netfilterqueue API, subprocess security, iptables/nft |
| `stack_packet/IP_.py` | 2, 5 | relative imports, crc32 ord() fix |
| `stack_packet/TCP_.py` | 2 | relative imports |
| `stack_packet/UDP_.py` | 2, 5 | relative imports, bytes comparison fix |
| `stack_packet/ICMP_.py` | 2 | relative imports |
| `osfuscation.py` | 2, 3, 4 | package imports, netfilterqueue, asyncio |
| `oschameleonRun.py` | 2, 4 | package imports, os.fork, time.sleep |
| `root_fork.py` | 4 | gevent removal / deprecation notice |
| `session/session.py` | 2, 6 | relative import, psutil |
| `session/ext_ip.py` | 8 | HTTPS URLs |
| `oschameleon/__main__.py` | 2 | new file — `python -m oschameleon` entry point |
| `template/windows_10.txt` | 9 | new template |
| `template/ubuntu_2204.txt` | 9 | new template |
| `tests/test_basic.py` | 10 | expanded test suite |
| `README.md` | 11 | updated docs |
| `Changelog.txt` | 11 | v0.2.0 entry |

---

## Verification Checklist

1. `pip install -r requirements.txt` completes on Python 3.8+ without errors
2. `python -m pytest tests/ -v` — all tests pass (no root required, mocked)
3. `python -c "from oschameleon.osfuscation import OSFuscation"` — clean import
4. `python -c "from oschameleon.parse_fp import get_os_pattern; print(get_os_pattern('oschameleon/template/windows_10.txt').TTL)"` — parses new template
5. On a Linux host (root): `python -m oschameleon --template oschameleon/template/SIMATIC_300_PLC.txt --interface eth0` starts without error
6. From another machine: `nmap -O <host>` reports the spoofed OS
7. Verify nftables path: disable iptables legacy binary, re-run step 5 → should use `nft`

## Out of Scope

- IPv6 packet support
- systemd service unit file
- Docker / container packaging
- Windows or macOS support (Linux-only by design — requires netfilter)
- TLS/HTTPS for the honeypot listener itself
