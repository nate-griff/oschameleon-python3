#!/usr/bin/python

import shutil
import subprocess


NFT_TABLE = "oschameleon"


def _run(cmd, check=True):
    subprocess.run(cmd, check=check)


def _detect_firewall_backend():
    for cmd in ("iptables", "iptables-legacy"):
        if shutil.which(cmd):
            return ("iptables", cmd)

    if shutil.which("nft"):
        return ("nft", "nft")

    raise RuntimeError("No supported firewall backend found (iptables or nft)")


def _nft_create_rules(server):
    _run(["nft", "add", "table", "inet", NFT_TABLE], check=False)
    _run(
        [
            "nft",
            "add",
            "chain",
            "inet",
            NFT_TABLE,
            "input",
            "{",
            "type",
            "filter",
            "hook",
            "input",
            "priority",
            "0",
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ],
        check=False,
    )
    _run(
        [
            "nft",
            "add",
            "chain",
            "inet",
            NFT_TABLE,
            "output",
            "{",
            "type",
            "filter",
            "hook",
            "output",
            "priority",
            "0",
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ],
        check=False,
    )

    _run(
        [
            "nft",
            "add",
            "rule",
            "inet",
            NFT_TABLE,
            "input",
            "tcp",
            "ip",
            "saddr",
            server,
            "dport",
            "63712",
            "ct",
            "state",
            "new,established",
            "accept",
        ]
    )
    _run(
        [
            "nft",
            "add",
            "rule",
            "inet",
            NFT_TABLE,
            "output",
            "tcp",
            "ip",
            "daddr",
            server,
            "sport",
            "63712",
            "ct",
            "state",
            "established",
            "accept",
        ]
    )
    _run(
        [
            "nft",
            "add",
            "rule",
            "inet",
            NFT_TABLE,
            "output",
            "tcp",
            "ip",
            "daddr",
            server,
            "sport",
            "63712",
            "ct",
            "state",
            "new,established",
            "accept",
        ]
    )
    _run(
        [
            "nft",
            "add",
            "rule",
            "inet",
            NFT_TABLE,
            "input",
            "tcp",
            "ip",
            "saddr",
            server,
            "dport",
            "63712",
            "ct",
            "state",
            "established",
            "accept",
        ]
    )
    _run(["nft", "add", "rule", "inet", NFT_TABLE, "input", "queue", "num", "0"])


def flush_tables():
    backend, tool = _detect_firewall_backend()
    if backend == "iptables":
        _run([tool, "-F"])
    else:
        _run(["nft", "flush", "table", "inet", NFT_TABLE], check=False)
        _run(["nft", "delete", "table", "inet", NFT_TABLE], check=False)


def forward_packet(nfq_packet):
    # send the packet from NFQUEUE without modification
    nfq_packet.accept()


def drop_packet(nfq_packet):
    # drop the packet from NFQUEUE
    nfq_packet.drop()


def rules(server):
    backend, tool = _detect_firewall_backend()

    if backend == "iptables":
        _run(
            [
                tool,
                "-A",
                "INPUT",
                "-p",
                "tcp",
                "-s",
                server,
                "--dport",
                "63712",
                "-m",
                "state",
                "--state",
                "NEW,ESTABLISHED",
                "-j",
                "ACCEPT",
            ]
        )
        _run(
            [
                tool,
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "-d",
                server,
                "--sport",
                "63712",
                "-m",
                "state",
                "--state",
                "ESTABLISHED",
                "-j",
                "ACCEPT",
            ]
        )
        _run(
            [
                tool,
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "-d",
                server,
                "--sport",
                "63712",
                "-m",
                "state",
                "--state",
                "NEW,ESTABLISHED",
                "-j",
                "ACCEPT",
            ]
        )
        _run(
            [
                tool,
                "-A",
                "INPUT",
                "-p",
                "tcp",
                "-s",
                server,
                "--dport",
                "63712",
                "-m",
                "state",
                "--state",
                "ESTABLISHED",
                "-j",
                "ACCEPT",
            ]
        )

        # Configure NFQUEUE target
        _run([tool, "-A", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"])
    else:
        _nft_create_rules(server)
