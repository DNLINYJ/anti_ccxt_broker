#!/usr/bin/env python3
"""
scan_ccxt_injection.py — CI 扫描脚本
扫描已安装 ccxt 包中的 broker/partner/builder 注入关键词。
发现新增注入点则 exit(1)。

baseline key = filename|keyword|hash(snippet) — 不依赖行号，升级时更稳健。
"""
import sys
import re
import json
import hashlib
from pathlib import Path

KEYWORDS = [
    'brokerId', 'broker_id', 'KC-API-PARTNER', 'X-BM-BROKER-ID',
    'X-CHANNEL-API-CODE', 'X-SOURCE-KEY', 'INPUT-SOURCE',
    'builderFee', 'approveBuilderFee', 'setReferrer', 'referral_code',
    'broker_sign', 'PARADEX-PARTNER',
]
EXCLUDE_PATTERNS = [r'test', r'__pycache__', r'\.pyc$']


def find_ccxt_dir():
    try:
        import ccxt
        return Path(ccxt.__file__).parent
    except ImportError:
        print("ERROR: ccxt not installed")
        sys.exit(2)


def _stable_key(filename: str, keyword: str, snippet: str) -> str:
    """filename|keyword|sha1(snippet_stripped)[:12]"""
    h = hashlib.sha1(snippet.encode('utf-8', errors='ignore')).hexdigest()[:12]
    return f"{filename}|{keyword}|{h}"


def scan():
    ccxt_dir = find_ccxt_dir()
    print(f"Scanning: {ccxt_dir}")
    try:
        import ccxt
        print(f"Version: {ccxt.__version__}")
    except Exception:
        print("Version: unknown")

    findings = {}
    for py_file in sorted(ccxt_dir.glob('*.py')):
        name = py_file.name
        if any(re.search(p, name) for p in EXCLUDE_PATTERNS):
            continue
        try:
            content = py_file.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            for kw in KEYWORDS:
                if kw in line:
                    snippet = stripped[:120]
                    key = _stable_key(name, kw, snippet)
                    findings[key] = {
                        'file': name, 'line': i,
                        'keyword': kw, 'snippet': snippet,
                    }
    return findings


def main():
    refresh = '--refresh-baseline' in sys.argv
    baseline_path = Path('broker-scan-baseline.json')
    findings = scan()

    if refresh or not baseline_path.exists():
        baseline_path.write_text(json.dumps(findings, indent=2, ensure_ascii=False))
        action = "Refreshed" if refresh else "Created"
        print(f"Baseline {action}: {len(findings)} injection points recorded")
        return

    baseline = json.loads(baseline_path.read_text(encoding='utf-8'))
    new_keys = set(findings.keys()) - set(baseline.keys())
    if new_keys:
        print(f"\n!! FAIL: {len(new_keys)} new injection points found:")
        for k in sorted(new_keys):
            f = findings[k]
            print(f"  {f['file']}:{f['line']}: [{f['keyword']}] {f['snippet']}")
        sys.exit(1)

    removed = set(baseline.keys()) - set(findings.keys())
    if removed:
        print(f"INFO: {len(removed)} previously known points no longer found")
    print(f"PASS: No new injections ({len(findings)} current, {len(baseline)} baseline)")


if __name__ == '__main__':
    main()
