# Linux Validation Recommendations for OSChameleon

## Goal
Validate that the modernized codebase works correctly on a real Linux kernel with netfilter/NFQUEUE, beyond unit tests.

## Preconditions
- Use a Linux host/VM (not native Windows).
- Run as root for runtime packet interception.
- Ensure the test scanner is a separate machine/network namespace.

## Recommended Validation Sequence

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Run the Python test suite:

```bash
python -m pytest tests -q
```

3. Import smoke check:

```bash
python -c "from oschameleon.osfuscation import OSFuscation; print('ok')"
```

4. Run OSChameleon with one template (as root):

```bash
sudo python -m oschameleon \
  --template oschameleon/template/SIMATIC_300_PLC.txt \
  --interface <iface> \
  --server <mgmt_ip> \
  --debug True
```

5. From a different host, run OS detection:

```bash
nmap -O <target_ip>
```

6. Repeat runtime test with additional templates:
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
