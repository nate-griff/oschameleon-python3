![tests](https://github.com/mushorg/oschameleon/actions/workflows/test.yml/badge.svg)

OSChameleon
===========

**OS Fingerprint Obfuscation for modern Linux Kernels.**
*Author: Anton Hinterleitner is111012\@fhstp.ac.at*

Description: Fools the probes of nmap scanner

Prerequisites:

- Linux (tested with modern Debian/Ubuntu kernels)
- Python 3.8+
- `netfilterqueue` Python package
- `requirements.txt`

Recorded logs are stored to `/var/log/honeypot/`

Usage:

    python -m oschameleon \
      --template oschameleon/template/SIMATIC_300_PLC.txt \
      --server 127.0.0.1 \
      --public_ip False \
      --interface eth0 \
      --debug False

Template options include:
- `oschameleon/template/SIMATIC_300_PLC.txt`
- `oschameleon/template/3com_superstack_3.txt`
- `oschameleon/template/windows_7_SP1.txt`
- `oschameleon/template/windows_10.txt`
- `oschameleon/template/ubuntu_2204.txt`

You can also invoke directly:

    python oschameleon/oschameleonRun.py --template oschameleon/template/windows_10.txt

Install dependencies:

    pip install -r requirements.txt

**Note:** This tool modifies firewall rules and flushes its managed rules during startup/shutdown.

Firewall backend behavior:
- Uses `iptables` or `iptables-legacy` when available.
- Falls back to `nft` when iptables binaries are unavailable.
