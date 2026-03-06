# Linux Validation Recommendations for OSChameleon

## Goal
Validate that the modernized codebase works correctly on a real Linux kernel with netfilter/NFQUEUE, beyond unit tests.

## Preconditions
- Use a Linux host/VM (not native Windows).
- Run as root for runtime packet interception.
- Ensure the test scanner is a separate machine/network namespace.
- Install required system build dependencies for `netfilterqueue`:

```bash
sudo apt update
sudo apt install -y build-essential python3-dev libnetfilter-queue-dev libnfnetlink-dev
```

## Recommended Validation Sequence

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Install test dependencies:

```bash
pip install pytest
```

3. Run the Python test suite:

```bash
python -m pytest tests -q
```

4. Import smoke check:

```bash
python -c "from oschameleon.osfuscation import OSFuscation; print('ok')"
```

5. Run OSChameleon with one template (as root):

`<mgmt_ip>` is the remote management/peer host IP used for firewall allow rules on TCP port `63712` (the `--server` argument).
It is usually **not** the local interface IP. For local-only testing, you can keep `--server 127.0.0.1`.

```bash
sudo python -m oschameleon \
  --template oschameleon/template/SIMATIC_300_PLC.txt \
  --interface <iface> \
  --server <mgmt_ip> \
  --debug True
```
---
```bash
sudo python -m oschameleon \
  --template oschameleon/template/SIMATIC_300_PLC.txt \
  --interface eth0 \
  --server 127.0.0.1 \
  --debug True
```
---

6. From a different host, run OS detection:

```bash
nmap -O <target_ip>
```

7. Repeat runtime test with additional templates:
- `oschameleon/template/windows_10.txt`
- `oschameleon/template/ubuntu_2204.txt`

## What to Verify
- Process starts cleanly as root and continues running.
- Firewall/NFQUEUE rule setup succeeds.
- No crashes during packet handling.
- `nmap -O` output shifts toward selected spoofed template behavior.
- Logging is written under `/var/log/honeypot/`.

## Optional Extra Checks
- Validate behavior on systems using `iptables` and on systems using `nft` backend.
- Perform repeated scans to ensure session behavior remains stable.
- Confirm graceful shutdown cleans up firewall changes.

## Exit Criteria (Release Candidate Readiness)
- Dependency install succeeds on Linux.
- Test suite passes on Linux.
- Runtime spoofing works across at least 3 templates.
- No blocking runtime exceptions during repeated `nmap -O` scans.
