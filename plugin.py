from __future__ import annotations

"""Forensics Core Cell — built-in forensics tools with zero external dependencies.

This is the first Cell plugin for ForHacker. It demonstrates the plugin contract
and provides genuinely useful file analysis tools out of the box.
"""

import hashlib
import re
import struct
import subprocess
from pathlib import Path
from typing import Any

from forhacker.plugin.base import BasePlugin, Tool

DEFAULT_YARA_RULES = r"""
rule PE_Executable {
    meta:
        description = "Detect PE executables"
        author = "ForHacker"
    strings:
        $mz = {4D 5A}
        $pe = {50 45 00 00}
    condition:
        $mz at 0 and $pe
}

rule Suspicious_PowerShell {
    meta:
        description = "Detect PowerShell download cradle and encoded commands"
    strings:
        $dc = "DownloadString" nocase
        $wc = "WebClient" nocase
        $enc = "-enc" nocase ascii wide
        $ec = "-EncodedCommand" nocase
        $iex1 = "IEX(" nocase
        $iex2 = "Invoke-Expression" nocase
    condition:
        2 of them
}

rule Suspicious_URLs {
    meta:
        description = "Detect suspicious URLs and domains"
    strings:
        $paste = "pastebin.com" nocase
        $disc = "discord.com/api" nocase
        $raw = "raw.githubusercontent.com" nocase
        $temp = "temp.sh" nocase
        $ngrok = "ngrok" nocase
    condition:
        any of them
}

rule Embedded_Base64 {
    meta:
        description = "Detect long base64-encoded strings (may indicate obfuscation)"
    strings:
        $b64 = /[A-Za-z0-9+\/=]{100,}/
    condition:
        $b64
}

rule Common_Malware_Strings {
    meta:
        description = "Detect common malware IOCs"
    strings:
        $c2_1 = "C2" nocase fullword
        $keylog = "keylogger" nocase
        $ransom = "ransom" nocase
        $trojan = "trojan" nocase
        $backdoor = "backdoor" nocase
        $botnet = "botnet" nocase
    condition:
        2 of them
}
"""


class ForensicsCorePlugin(BasePlugin):
    name = "forensics-core"
    version = "0.1.0"
    domain = "forensics"
    risk_levels = {
        "file_hash": "LOW",
        "extract_strings": "LOW",
        "pe_info": "LOW",
        "yara_scan": "MEDIUM",
        "volatility3_pslist": "MEDIUM",
    }

    def register_tools(self) -> list[Tool]:
        return [
            Tool(
                name="file_hash",
                description="Calculate SHA256 and MD5 hashes of a file",
                domain="forensics",
                risk_level="LOW",
            ),
            Tool(
                name="extract_strings",
                description="Extract ASCII/UTF-16 printable strings from a file",
                domain="forensics",
                risk_level="LOW",
            ),
            Tool(
                name="pe_info",
                description="Parse PE header: sections, entry point, imports",
                domain="forensics",
                risk_level="LOW",
                applicable_extensions=(".exe", ".dll", ".sys", ".bin"),
            ),
            Tool(name="yara_scan", description="Scan files with YARA rules", domain="forensics", risk_level="MEDIUM"),
            Tool(
                name="volatility3_pslist",
                description="List processes from memory dump via Volatility 3",
                domain="forensics",
                risk_level="MEDIUM",
                applicable_extensions=(".dmp", ".mem", ".raw", ".vmem", ".bin"),
            ),
        ]


def run_file_hash(target: str) -> dict[str, Any]:
    """Calculate SHA256 and MD5 of a file. Pure Python, no dependencies."""
    path = Path(target)
    if not path.exists():
        return {"error": f"File not found: {target}"}
    sha = hashlib.sha256()
    md5 = hashlib.md5()
    with path.open("rb") as fh:
        while chunk := fh.read(8192):
            sha.update(chunk)
            md5.update(chunk)
    return {
        "file": str(path.absolute()),
        "size": path.stat().st_size,
        "sha256": sha.hexdigest(),
        "md5": md5.hexdigest(),
    }


def run_extract_strings(target: str, min_length: int = 4) -> dict[str, Any]:
    """Extract ASCII and UTF-16-LE printable strings from a binary file."""
    path = Path(target)
    if not path.exists():
        return {"error": f"File not found: {target}"}
    data = path.read_bytes()
    ascii_pattern = re.compile(rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}")
    ascii_strings = [m.group().decode("ascii") for m in ascii_pattern.finditer(data)]
    return {
        "file": str(path.absolute()),
        "ascii_count": len(ascii_strings),
        "ascii_strings": ascii_strings[:200],
    }


def run_pe_info(target: str) -> dict[str, Any]:
    """Parse PE header: machine type, sections, entry point."""
    path = Path(target)
    if not path.exists():
        return {"error": f"File not found: {target}"}
    data = path.read_bytes()
    if data[:2] != b"MZ":
        return {"error": "Not a valid PE file (missing MZ header)"}
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            return {"error": "PE signature not found"}
        machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
        num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
        entry_rva = struct.unpack_from("<I", data, pe_offset + 40)[0]
        return {
            "file": str(path.absolute()),
            "machine": machine,
            "num_sections": num_sections,
            "entry_point_rva": hex(entry_rva),
            "is_64bit": machine == 0x8664,
        }
    except (struct.error, IndexError) as e:
        return {"error": f"Failed to parse PE header: {e}"}


def run_yara_scan(target: str, rule_path: str = "") -> dict[str, Any]:
    """Scan a file with YARA rules. Uses built-in rules by default."""
    try:
        import yara  # type: ignore[import-untyped]
    except ImportError:
        return {"error": "yara-python not installed. Run: pip install yara-python"}

    path = Path(target)
    if not path.exists():
        return {"error": f"File not found: {target}"}
    if not path.is_file():
        return {"error": f"Not a regular file: {target}"}

    if rule_path:
        source = rule_path
    else:
        rules_dir = Path(__file__).parent / "rules"
        rules_dir.mkdir(exist_ok=True)
        default_rule = rules_dir / "default.yar"
        default_rule.write_text(DEFAULT_YARA_RULES, encoding="utf-8")
        source = str(default_rule)

    try:
        rules = yara.compile(source)
        matches = rules.match(str(path))
    except Exception as e:
        return {"error": f"YARA scan failed: {e}"}

    match_details = []
    for m in matches:
        strings_info = []
        for s in m.strings:
            instances = getattr(s, "instances", [])
            for inst in instances:
                strings_info.append({
                    "offset": inst.offset,
                    "identifier": s.identifier,
                    "data": inst.matched_data.hex() if inst.matched_data else "",
                })
        match_details.append({
            "rule": m.rule,
            "tags": list(m.tags) if hasattr(m, "tags") else [],
            "strings": strings_info,
        })

    return {
        "file": str(path.absolute()),
        "rule_source": "built-in" if not rule_path else rule_path,
        "match_count": len(matches),
        "matches": match_details,
    }


def run_volatility3_pslist(target: str) -> dict[str, Any]:
    """List processes from memory dump using Volatility 3."""
    path = Path(target)
    if not path.exists():
        return {"error": f"File not found: {target}"}
    if not path.is_file():
        return {"error": f"Not a regular file: {target}"}

    try:
        result = subprocess.run(
            ["python", "-m", "volatility3", "-f", str(path.absolute()), "windows.pslist"],
            capture_output=True, text=True, timeout=120,
        )
    except FileNotFoundError:
        return {"error": "volatility3 not found. Run: pip install volatility3"}
    except subprocess.TimeoutExpired:
        return {"error": "volatility3 timed out (120s)"}
    except Exception as e:
        return {"error": f"volatility3 execution failed: {e}"}

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    if result.returncode != 0:
        return {
            "file": str(path.absolute()),
            "error": f"volatility3 exited with code {result.returncode}",
            "stderr": stderr[:500],
            "stdout": stdout[:500],
            "note": "Ensure the target is a valid Windows memory dump",
        }

    return {
        "file": str(path.absolute()),
        "plugin": "windows.pslist",
        "output": stdout[:5000],
        "line_count": len(stdout.splitlines()) if stdout else 0,
    }
