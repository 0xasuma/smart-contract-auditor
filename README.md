# 🛡️ Smart Contract Security Auditor

AI-powered smart contract vulnerability scanner. Paste your Solidity code, get instant security analysis with actionable fixes.

## Features

- **15+ Vulnerability Detection** — Reentrancy, tx.origin, delegatecall, integer overflow, unchecked calls, access control, and more
- **Risk Scoring** — Grade A-F with percentage risk score
- **SWC/CWE References** — Industry-standard vulnerability identifiers
- **Fix Recommendations** — Actionable remediation for each finding
- **Contract Analysis** — Solidity version, contracts, functions, interfaces detected
- **Modern UI** — Clean, responsive interface with real-time analysis

## Detected Vulnerabilities

| Severity | Vulnerability | SWC |
|----------|--------------|-----|
| CRITICAL | Reentrancy | SWC-107 |
| CRITICAL | Delegatecall Injection | SWC-112 |
| CRITICAL | Arbitrary Storage Write | SWC-124 |
| HIGH | tx.origin Authentication | SWC-115 |
| HIGH | Selfdestruct | SWC-106 |
| HIGH | Integer Overflow/Underflow | SWC-101 |
| HIGH | Unchecked Send/Transfer | SWC-104 |
| MEDIUM | Unchecked External Call | SWC-104 |
| MEDIUM | Timestamp Dependency | SWC-116 |
| MEDIUM | Front-Running Susceptibility | SWC-114 |
| MEDIUM | Denial of Service | SWC-128 |
| LOW | Floating Pragma | SWC-103 |
| LOW | Missing Event Emission | SWC-110 |

## Quick Start

```bash
pip install flask
python app.py
```

Open `http://localhost:5003` in your browser.

## API

```bash
curl -X POST http://localhost:5003/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "pragma solidity ^0.8.0; ..."}'
```

Response:
```json
{
  "findings": [...],
  "stats": {"critical": 1, "high": 2, "medium": 1, "low": 0},
  "risk_score": 45,
  "grade": "C",
  "total_findings": 4,
  "solidity_version": "0.8.0",
  "contracts": ["MyContract"],
  "functions": ["withdraw", "transfer"]
}
```

## Live Demo

🔗 **https://0xasuma.my.id**

## Stack

- Python / Flask
- Pattern-based vulnerability detection
- SWC Registry compliance
- CWE mapping

## License

MIT
