from flask import Flask, request, jsonify, render_template_string
import re
import json
import hashlib
from datetime import datetime

app = Flask(__name__)

# === VULNERABILITY DETECTION ENGINE ===

VULN_PATTERNS = [
    {
        "id": "REENTRANCY",
        "name": "Reentrancy",
        "severity": "CRITICAL",
        "description": "External call before state update allows attacker to re-enter function",
        "patterns": [
            (r'\.call\s*\{.*value', "Low-level call with value transfer"),
            (r'\.call\.value\s*\(', "call.value used"),
            (r'\.send\s*\(', "send() used without reentrancy guard"),
            (r'\.transfer\s*\(', "transfer() used"),
        ],
        "fix": "Use ReentrancyGuard from OpenZeppelin or follow checks-effects-interactions pattern",
        "cwe": "CWE-841",
        "swc": "SWC-107"
    },
    {
        "id": "TX_ORIGIN",
        "name": "tx.origin Authentication",
        "severity": "HIGH",
        "description": "Using tx.origin for authentication is vulnerable to phishing attacks",
        "patterns": [
            (r'tx\.origin', "tx.origin used for authentication"),
        ],
        "fix": "Use msg.sender instead of tx.origin for authentication",
        "cwe": "CWE-477",
        "swc": "SWC-115"
    },
    {
        "id": "DELEGATECALL",
        "name": "Delegatecall Injection",
        "severity": "CRITICAL",
        "description": "delegatecall to user-controlled address can lead to code execution",
        "patterns": [
            (r'\.delegatecall\s*\(', "delegatecall used"),
            (r'delegatecall\s*\(', "delegatecall invoked"),
        ],
        "fix": "Never delegatecall to untrusted addresses. Use proxy patterns with proper access control",
        "cwe": "CWE-829",
        "swc": "SWC-112"
    },
    {
        "id": "SELFDESTRUCT",
        "name": "Selfdestruct",
        "severity": "HIGH",
        "description": "selfdestruct can destroy the contract and send funds to arbitrary address",
        "patterns": [
            (r'selfdestruct\s*\(', "selfdestruct used"),
            (r'suicide\s*\(', "suicide (deprecated) used"),
        ],
        "fix": "Remove selfdestruct or add strict access control. Consider upgradeable proxy pattern",
        "cwe": "CWE-284",
        "swc": "SWC-106"
    },
    {
        "id": "INTEGER_OVERFLOW",
        "name": "Integer Overflow/Underflow",
        "severity": "HIGH",
        "description": "Arithmetic operations without SafeMath can overflow/underflow (Solidity <0.8.0)",
        "patterns": [
            (r'pragma\s+solidity\s*\^?0\.[0-7]\.', "Solidity version <0.8.0 (no built-in overflow checks)"),
            (r'pragma\s+solidity\s+[\^><=]*\s*0\.[0-7]\.', "Solidity version <0.8.0"),
        ],
        "fix": "Upgrade to Solidity >=0.8.0 or use SafeMath/OpenZeppelin libraries",
        "cwe": "CWE-190",
        "swc": "SWC-101"
    },
    {
        "id": "UNCHECKED_CALL",
        "name": "Unchecked External Call",
        "severity": "MEDIUM",
        "description": "Return value of external call not checked",
        "patterns": [
            (r'\.call\s*\{.*\}\s*\(', "Low-level call return not checked"),
            (r'\.call\s*\([^)]*\)\s*;', "call() return value ignored"),
            (r'\.staticcall\s*\([^)]*\)\s*;', "staticcall() return value ignored"),
        ],
        "fix": "Always check the return value of low-level calls: (bool success, ) = addr.call(...); require(success);",
        "cwe": "CWE-252",
        "swc": "SWC-104"
    },
    {
        "id": "ACCESS_CONTROL",
        "name": "Missing Access Control",
        "severity": "HIGH",
        "description": "Critical functions lack proper access control modifiers",
        "patterns": [
            (r'function\s+(withdraw|transfer|mint|burn|pause|unpause|destroy|kill|selfdestruct)\s*\(', "Critical function may lack access control"),
            (r'function\s+\w+\s*\([^)]*\)\s+(public|external)\s+((?!onlyOwner|onlyAdmin|require|modifier))', "Public/external function without modifier"),
        ],
        "fix": "Add onlyOwner, AccessControl, or role-based modifiers to critical functions",
        "cwe": "CWE-284",
        "swc": "SWC-105"
    },
    {
        "id": "FLOATING_PRAGMA",
        "name": "Floating Pragma",
        "severity": "LOW",
        "description": "Using floating pragma (^) allows compilation with different compiler versions",
        "patterns": [
            (r'pragma\s+solidity\s+\^', "Floating pragma used"),
        ],
        "fix": "Lock pragma to a specific version: pragma solidity 0.8.19;",
        "cwe": "CWE-670",
        "swc": "SWC-103"
    },
    {
        "id": "TIMESTAMP_DEP",
        "name": "Timestamp Dependency",
        "severity": "MEDIUM",
        "description": "Using block.timestamp for critical logic can be manipulated by miners",
        "patterns": [
            (r'block\.timestamp', "block.timestamp used"),
            (r'now\s*[><=!]+', "now (alias for block.timestamp) used in comparison"),
        ],
        "fix": "Avoid using block.timestamp for critical logic. If needed, allow tolerance of ~15 seconds",
        "cwe": "CWE-829",
        "swc": "SWC-116"
    },
    {
        "id": "FRONT_RUNNING",
        "name": "Front-Running Susceptibility",
        "severity": "MEDIUM",
        "description": "Contract may be vulnerable to front-running/MEV attacks",
        "patterns": [
            (r'first\s*come|first\s*serve|FCFS', "First-come-first-serve logic"),
            (r'block\.\w+\s*[><=].*\|\|', "Block-based comparison in condition"),
            (r'setPrice|setRate|updatePrice', "Price setter without commit-reveal"),
        ],
        "fix": "Use commit-reveal scheme, private mempool, or Flashbots Protect",
        "cwe": "CWE-300",
        "swc": "SWC-114"
    },
    {
        "id": "UNCHECKED_RETURN",
        "name": "Unchecked Send/Transfer",
        "severity": "HIGH",
        "description": "send() return value not checked, transfer() can fail silently in some contexts",
        "patterns": [
            (r'\.send\s*\([^)]*\)\s*;', "send() return value not checked"),
            (r'payable\s*\([^)]*\)\.send', "payable.send() without check"),
        ],
        "fix": "Always check send() return value or use call{value: amount}(\"\") with success check",
        "cwe": "CWE-252",
        "swc": "SWC-104"
    },
    {
        "id": "DENIAL_OF_SERVICE",
        "name": "Denial of Service",
        "severity": "MEDIUM",
        "description": "Loop over unbounded array or external call in loop can cause DoS",
        "patterns": [
            (r'for\s*\([^)]*\)\s*\{[^}]*\.(send|transfer|call)', "External call inside loop"),
            (r'for\s*\([^)]*\)\s*\{[^}]*payable', "Payable operation in loop"),
            (r'\.length\s*;.*for\s*\(.*<.*\.length', "Loop over dynamic array"),
        ],
        "fix": "Use pull-over-push pattern. Limit array size or use pagination",
        "cwe": "CWE-400",
        "swc": "SWC-128"
    },
    {
        "id": "UNINIT_STORAGE",
        "name": "Uninitialized Storage Pointer",
        "severity": "HIGH",
        "description": "Uninitialized storage variables can point to unexpected storage slots",
        "patterns": [
            (r'(struct|mapping)\s+\w+\s+(storage\s+)?\w+\s*;', "Potentially uninitialized storage variable"),
        ],
        "fix": "Always use memory for local variables: MyStruct memory localVar;",
        "cwe": "CWE-824",
        "swc": "SWC-109"
    },
    {
        "id": "MISSING_EVENT",
        "name": "Missing Event Emission",
        "severity": "LOW",
        "description": "State changes without event emission make monitoring difficult",
        "patterns": [
            (r'function\s+\w+.*\{[^}]*(?:balance|totalSupply|owner|admin)[^}]*\}', "State modification without event"),
        ],
        "fix": "Emit events for all critical state changes for off-chain monitoring",
        "cwe": "CWE-778",
        "swc": "SWC-110"
    },
    {
        "id": "ARBITRARY_LOCATION",
        "name": "Arbitrary Storage Write",
        "severity": "CRITICAL",
        "description": "Assembly sstore with user-controlled slot can overwrite any storage",
        "patterns": [
            (r'assembly\s*\{[^}]*sstore', "Assembly sstore found"),
            (r'sstore\s*\(', "Direct sstore in assembly"),
        ],
        "fix": "Avoid assembly sstore with user-controlled values. Use Solidity storage patterns",
        "cwe": "CWE-123",
        "swc": "SWC-124"
    },
]

RISK_SCORES = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}

def analyze_contract(code):
    """Analyze Solidity contract for vulnerabilities."""
    findings = []
    lines = code.split('\n')
    
    for vuln in VULN_PATTERNS:
        for pattern, desc in vuln["patterns"]:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if this is a false positive (in comment)
                    stripped = line.strip()
                    if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*'):
                        continue
                    
                    findings.append({
                        "id": vuln["id"],
                        "name": vuln["name"],
                        "severity": vuln["severity"],
                        "description": vuln["description"],
                        "line": i,
                        "code": stripped[:120],
                        "detail": desc,
                        "fix": vuln["fix"],
                        "cwe": vuln["cwe"],
                        "swc": vuln["swc"],
                    })
                    break  # One match per vuln type per pattern
    
    # Deduplicate by (id, line)
    seen = set()
    unique = []
    for f in findings:
        key = (f["id"], f["line"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    
    # Calculate risk score
    total_score = sum(RISK_SCORES.get(f["severity"], 0) for f in unique)
    max_possible = len(unique) * 25 if unique else 1
    risk_pct = min(100, int((total_score / max(max_possible, 1)) * 100))
    
    # Grade
    if risk_pct >= 75:
        grade = "F"
    elif risk_pct >= 50:
        grade = "D"
    elif risk_pct >= 30:
        grade = "C"
    elif risk_pct >= 15:
        grade = "B"
    else:
        grade = "A"
    
    # Stats
    stats = {
        "critical": len([f for f in unique if f["severity"] == "CRITICAL"]),
        "high": len([f for f in unique if f["severity"] == "HIGH"]),
        "medium": len([f for f in unique if f["severity"] == "MEDIUM"]),
        "low": len([f for f in unique if f["severity"] == "LOW"]),
    }
    
    # Contract info
    solidity_version = "Unknown"
    match = re.search(r'pragma\s+solidity\s+[\^><=]*\s*([\d.]+)', code)
    if match:
        solidity_version = match.group(1)
    
    contracts = re.findall(r'contract\s+(\w+)', code)
    interfaces = re.findall(r'interface\s+(\w+)', code)
    libraries = re.findall(r'library\s+(\w+)', code)
    functions = re.findall(r'function\s+(\w+)', code)
    
    return {
        "findings": sorted(unique, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(x["severity"])),
        "stats": stats,
        "risk_score": risk_pct,
        "grade": grade,
        "total_lines": len(lines),
        "solidity_version": solidity_version,
        "contracts": contracts,
        "interfaces": interfaces,
        "libraries": libraries,
        "functions": functions,
        "total_findings": len(unique),
        "timestamp": datetime.utcnow().isoformat(),
    }


# === HTML TEMPLATE ===

HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart Contract Auditor - AI Security Analysis</title>
    <meta name="description" content="AI-powered Smart Contract Security Auditor. Detect vulnerabilities in Solidity code.">
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg: #f8fafc;
            --card: #ffffff;
            --border: #e2e8f0;
            --text: #1e293b;
            --muted: #64748b;
            --accent: #6366f1;
            --accent2: #8b5cf6;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
            --success: #10b981;
            --code-bg: #f1f5f9;
        }
        body {
            font-family: 'Inter', -apple-system, system-ui, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
        }
        .header {
            border-bottom: 1px solid var(--border);
            padding: 1rem 2rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: rgba(255,255,255,0.85);
            backdrop-filter: blur(12px);
            position: sticky;
            top: 0;
            z-index: 10;
        }
        .logo {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--accent);
        }
        .logo-icon { font-size: 1.5rem; }
        .badge {
            background: linear-gradient(135deg, var(--accent), var(--accent2));
            color: #fff;
            padding: 0.3rem 0.85rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .main {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        .hero {
            text-align: center;
            padding: 3rem 0 2rem;
        }
        .hero h1 {
            font-size: 2.5rem;
            font-weight: 800;
            margin-bottom: 0.75rem;
            background: linear-gradient(135deg, var(--accent), var(--accent2));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .hero p {
            color: var(--muted);
            font-size: 1.1rem;
            max-width: 600px;
            margin: 0 auto;
        }
        .input-section {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        }
        .input-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1rem;
        }
        .input-header h3 { font-size: 1rem; font-weight: 600; }
        .char-count { color: var(--muted); font-size: 0.85rem; }
        textarea {
            width: 100%;
            min-height: 300px;
            background: var(--code-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            color: #334155;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.85rem;
            line-height: 1.6;
            resize: vertical;
            outline: none;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        textarea:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(99,102,241,0.12);
        }
        textarea::placeholder { color: #94a3b8; }
        .btn-row { display: flex; gap: 0.75rem; margin-top: 1rem; }
        .btn {
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.9rem;
            cursor: pointer;
            transition: all 0.2s;
            border: none;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .btn-primary {
            background: linear-gradient(135deg, var(--accent), var(--accent2));
            color: #fff;
        }
        .btn-primary:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 15px rgba(99,102,241,0.3);
        }
        .btn-secondary {
            background: var(--code-bg);
            color: var(--text);
            border: 1px solid var(--border);
        }
        .btn-secondary:hover { background: #e2e8f0; }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
        .loading { display: none; text-align: center; padding: 3rem; }
        .loading.active { display: block; }
        .spinner {
            width: 40px; height: 40px;
            border: 3px solid var(--border);
            border-top-color: var(--accent);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin: 0 auto 1rem;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .results { display: none; }
        .results.active { display: block; }
        .results-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
            gap: 1rem;
        }
        .grade-badge {
            font-size: 3rem;
            font-weight: 800;
            width: 80px; height: 80px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 14px;
        }
        .grade-A { background: #ecfdf5; color: var(--success); border: 2px solid var(--success); }
        .grade-B { background: #eff6ff; color: #3b82f6; border: 2px solid #3b82f6; }
        .grade-C { background: #fefce8; color: var(--medium); border: 2px solid var(--medium); }
        .grade-D { background: #fff7ed; color: var(--high); border: 2px solid var(--high); }
        .grade-F { background: #fef2f2; color: var(--critical); border: 2px solid var(--critical); }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1rem;
            text-align: center;
            box-shadow: 0 1px 2px rgba(0,0,0,0.03);
        }
        .stat-value { font-size: 1.75rem; font-weight: 700; }
        .stat-label { color: var(--muted); font-size: 0.8rem; margin-top: 0.25rem; }
        .finding-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.25rem;
            margin-bottom: 1rem;
            border-left: 4px solid;
            box-shadow: 0 1px 2px rgba(0,0,0,0.03);
        }
        .finding-critical { border-left-color: var(--critical); }
        .finding-high { border-left-color: var(--high); }
        .finding-medium { border-left-color: var(--medium); }
        .finding-low { border-left-color: var(--low); }
        .finding-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 0.75rem;
            flex-wrap: wrap;
            gap: 0.5rem;
        }
        .finding-title { font-weight: 600; font-size: 1rem; }
        .severity-badge {
            padding: 0.2rem 0.6rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
        }
        .sev-CRITICAL { background: #fef2f2; color: var(--critical); }
        .sev-HIGH { background: #fff7ed; color: var(--high); }
        .sev-MEDIUM { background: #fefce8; color: #a16207; }
        .sev-LOW { background: #f0fdf4; color: var(--low); }
        .finding-desc { color: var(--muted); font-size: 0.9rem; margin-bottom: 0.5rem; }
        .finding-code {
            background: var(--code-bg);
            border-radius: 6px;
            padding: 0.5rem 0.75rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            color: #475569;
            margin: 0.5rem 0;
            overflow-x: auto;
        }
        .finding-meta {
            display: flex;
            gap: 1rem;
            margin-top: 0.5rem;
            font-size: 0.8rem;
            color: var(--muted);
        }
        .finding-fix {
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            border-radius: 8px;
            padding: 0.75rem;
            margin-top: 0.75rem;
            font-size: 0.85rem;
        }
        .finding-fix strong { color: var(--accent); }
        .contract-info {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.25rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 1px 2px rgba(0,0,0,0.03);
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 0.75rem;
        }
        .info-item {
            display: flex;
            justify-content: space-between;
            padding: 0.4rem 0;
            border-bottom: 1px solid var(--border);
        }
        .info-label { color: var(--muted); }
        .info-value { font-weight: 600; }
        .progress-bar {
            width: 100%;
            height: 8px;
            background: var(--border);
            border-radius: 4px;
            overflow: hidden;
            margin: 1rem 0;
        }
        .progress-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 1s ease;
        }
        .footer {
            text-align: center;
            padding: 2rem;
            color: var(--muted);
            font-size: 0.85rem;
            border-top: 1px solid var(--border);
            margin-top: 3rem;
        }
        .footer a { color: var(--accent); text-decoration: none; }
        @media (max-width: 768px) {
            .main { padding: 1rem; }
            .hero h1 { font-size: 1.75rem; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">
            <span class="logo-icon">🛡️</span>
            <span>Smart Contract Auditor</span>
        </div>
        <span class="badge">Powered by AI</span>
    </div>

    <div class="main">
        <div class="hero">
            <h1>Smart Contract Security Auditor</h1>
            <p>Paste your Solidity code below to detect vulnerabilities, security issues, and get actionable fixes.</p>
        </div>

        <div class="input-section">
            <div class="input-header">
                <h3>📝 Solidity Source Code</h3>
                <span class="char-count" id="charCount">0 chars | 0 lines</span>
            </div>
            <textarea id="codeInput" placeholder="// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MyContract {
    // Paste your Solidity code here...
}"></textarea>
            <div class="btn-row">
                <button class="btn btn-primary" id="analyzeBtn" onclick="analyze()">
                    🔍 Analyze Contract
                </button>
                <select id="exampleSelect" onchange="loadExample(this.value)" class="btn btn-secondary" style="cursor:pointer;">
                    <option value="">📄 Load Example...</option>
                    <option value="erc20">ERC20 Token (8 vulns)</option>
                    <option value="vault">ETH Vault (6 vulns)</option>
                    <option value="nft">NFT Auction (5 vulns)</option>
                    <option value="safe">Safe Contract (Clean)</option>
                </select>
                <button class="btn btn-secondary" onclick="clearAll()">
                    🗑️ Clear
                </button>
            </div>
        </div>

        <div class="loading" id="loading">
            <div class="spinner"></div>
            <p>Analyzing smart contract...</p>
        </div>

        <div class="results" id="results">
            <div class="results-header">
                <div>
                    <h2 style="margin-bottom: 0.5rem;">Audit Report</h2>
                    <p style="color: var(--muted);" id="reportTime"></p>
                </div>
                <div class="grade-badge" id="gradeBadge"></div>
            </div>

            <div class="stats-grid" id="statsGrid"></div>

            <div class="contract-info" id="contractInfo"></div>

            <h3 style="margin-bottom: 1rem;">🔎 Findings (<span id="findingCount">0</span>)</h3>
            <div id="findingsList"></div>
        </div>
    </div>

    <div class="footer">
        <p>Smart Contract Auditor &mdash; AI-Powered Security Analysis</p>
        <p style="margin-top: 0.5rem;">Built with MiMo | <a href="https://github.com/0xasuma" target="_blank">GitHub</a></p>
    </div>

    <script>
        const textarea = document.getElementById('codeInput');
        const charCount = document.getElementById('charCount');

        textarea.addEventListener('input', () => {
            const chars = textarea.value.length;
            const lines = textarea.value.split('\\n').length;
            charCount.textContent = `${chars.toLocaleString()} chars | ${lines} lines`;
        });

        const EXAMPLES = {
        erc20: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract VulnerableToken is ERC20 {
    address public owner;
    bool public paused = false;
    mapping(address => bool) public blacklist;
    
    constructor() ERC20("VulnerableToken", "VUL") {
        owner = msg.sender;
    }
    
    // Missing access control
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
    
    // tx.origin vulnerability
    function transferOwnership(address newOwner) public {
        require(tx.origin == owner);
        owner = newOwner;
    }
    
    // Reentrancy vulnerability
    function withdraw(uint256 amount) public {
        require(balanceOf(msg.sender) >= amount);
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Failed to send Ether");
        _burn(msg.sender, amount);
    }
    
    // Unchecked external call + DoS
    function airdrop(address[] calldata recipients, uint256 amount) external {
        for (uint i = 0; i < recipients.length; i++) {
            recipients[i].call{value: amount}("");
        }
    }
    
    // Timestamp dependency
    function isWinner() public view returns (bool) {
        return block.timestamp % 15 == 0;
    }
    
    // Selfdestruct
    function destroy() external {
        selfdestruct(payable(owner));
    }
    
    // Delegatecall
    function execute(address target, bytes memory data) external {
        target.delegatecall(data);
    }
    
    // Missing events
    function emergencyStop() external {
        paused = true;
    }
}`,
        
        vault: `// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract ETHVault {
    mapping(address => uint256) public balances;
    address public admin;
    address public pendingAdmin;
    
    constructor() {
        admin = msg.sender;
    }
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    // Reentrancy: state update after external call
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }
    
    // Integer overflow (Solidity <0.8.0)
    function addToBalance(uint256 extra) external {
        balances[msg.sender] += extra;
    }
    
    // tx.origin phishing
    function setAdmin(address newAdmin) external {
        require(tx.origin == admin, "Not admin");
        admin = newAdmin;
    }
    
    // Unchecked send return
    function emergencyWithdraw() external {
        uint256 bal = balances[msg.sender];
        balances[msg.sender] = 0;
        msg.sender.send(bal);
    }
    
    // Missing access control on critical function
    function sweepFunds(address to) external {
        uint256 bal = address(this).balance;
        (bool success, ) = to.call{value: bal}("");
        require(success);
    }
}`,
        
        nft: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract NFTAuction {
    address public owner;
    uint256 public highestBid;
    address public highestBidder;
    uint256 public auctionEndTime;
    bool public ended;
    
    mapping(address => uint256) public pendingReturns;
    
    constructor(uint256 _duration) {
        owner = msg.sender;
        auctionEndTime = block.timestamp + _duration;
    }
    
    function bid() external payable {
        require(block.timestamp < auctionEndTime, "Auction ended");
        require(msg.value > highestBid, "Bid too low");
        
        // No reentrancy guard, but pattern is risky
        if (highestBidder != address(0)) {
            pendingReturns[highestBidder] += highestBid;
        }
        highestBidder = msg.sender;
        highestBid = msg.value;
    }
    
    // Reentrancy: withdrawal pattern
    function withdraw() external {
        uint256 amount = pendingReturns[msg.sender];
        require(amount > 0, "Nothing to withdraw");
        pendingReturns[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
    
    // Timestamp dependency for auction end
    function hasEnded() public view returns (bool) {
        return block.timestamp >= auctionEndTime;
    }
    
    // Only owner can end auction (but uses timestamp)
    function endAuction() external {
        require(hasEnded(), "Auction not ended");
        require(!ended, "Already ended");
        ended = true;
        // Transfer NFT to highest bidder (simplified)
    }
    
    // Front-running: no commit-reveal
    function placeBidWithRefund() external payable {
        require(msg.value > highestBid);
        highestBid = msg.value;
        highestBidder = msg.sender;
    }
    
    // Missing events for bid, end, withdraw
}`,
        
        safe: `// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract SafeVault is ReentrancyGuard, Ownable {
    mapping(address => uint256) public balances;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    event AdminUpdated(address indexed oldAdmin, address indexed newAdmin);
    
    function deposit() external payable {
        require(msg.value > 0, "Must send ETH");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        emit Withdraw(msg.sender, amount);
    }
    
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
    
    function transferAdmin(address newAdmin) external onlyOwner {
        require(newAdmin != address(0), "Zero address");
        emit AdminUpdated(owner(), newAdmin);
        transferOwnership(newAdmin);
    }
}`
        };

        function loadExample(key) {
            if (!key) return;
            textarea.value = EXAMPLES[key];
            textarea.dispatchEvent(new Event('input'));
            document.getElementById('exampleSelect').value = '';
        }

        function clearAll() {
            textarea.value = '';
            textarea.dispatchEvent(new Event('input'));
            document.getElementById('results').classList.remove('active');
        }

        async function analyze() {
            const code = textarea.value.trim();
            if (!code) {
                alert('Please paste Solidity code first');
                return;
            }

            const btn = document.getElementById('analyzeBtn');
            btn.disabled = true;
            document.getElementById('loading').classList.add('active');
            document.getElementById('results').classList.remove('active');

            try {
                const res = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code })
                });
                const data = await res.json();
                renderResults(data);
            } catch (err) {
                alert('Error: ' + err.message);
            } finally {
                btn.disabled = false;
                document.getElementById('loading').classList.remove('active');
            }
        }

        function renderResults(data) {
            const results = document.getElementById('results');
            results.classList.add('active');

            // Report time
            document.getElementById('reportTime').textContent = 
                `Generated: ${new Date(data.timestamp + 'Z').toLocaleString()}`;

            // Grade
            const gradeBadge = document.getElementById('gradeBadge');
            gradeBadge.textContent = data.grade;
            gradeBadge.className = `grade-badge grade-${data.grade}`;

            // Stats
            const statsGrid = document.getElementById('statsGrid');
            const riskColor = data.risk_score >= 75 ? 'var(--critical)' : 
                            data.risk_score >= 50 ? 'var(--high)' :
                            data.risk_score >= 30 ? 'var(--medium)' : 'var(--success)';
            statsGrid.innerHTML = `
                <div class="stat-card">
                    <div class="stat-value" style="color: ${riskColor}">${data.risk_score}%</div>
                    <div class="stat-label">Risk Score</div>
                    <div class="progress-bar"><div class="progress-fill" style="width:${data.risk_score}%;background:${riskColor}"></div></div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: var(--critical)">${data.stats.critical}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: var(--high)">${data.stats.high}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: var(--medium)">${data.stats.medium}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: var(--low)">${data.stats.low}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${data.total_findings}</div>
                    <div class="stat-label">Total Issues</div>
                </div>
            `;

            // Contract info
            const info = document.getElementById('contractInfo');
            info.innerHTML = `
                <h3 style="margin-bottom: 0.75rem;">📋 Contract Information</h3>
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">Solidity Version</span>
                        <span class="info-value">${data.solidity_version}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Total Lines</span>
                        <span class="info-value">${data.total_lines}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Contracts</span>
                        <span class="info-value">${data.contracts.length ? data.contracts.join(', ') : 'N/A'}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Functions</span>
                        <span class="info-value">${data.functions.length}</span>
                    </div>
                    ${data.interfaces.length ? `<div class="info-item"><span class="info-label">Interfaces</span><span class="info-value">${data.interfaces.join(', ')}</span></div>` : ''}
                    ${data.libraries.length ? `<div class="info-item"><span class="info-label">Libraries</span><span class="info-value">${data.libraries.join(', ')}</span></div>` : ''}
                </div>
            `;

            // Findings
            document.getElementById('findingCount').textContent = data.total_findings;
            const list = document.getElementById('findingsList');
            list.innerHTML = data.findings.map(f => `
                <div class="finding-card finding-${f.severity.toLowerCase()}">
                    <div class="finding-header">
                        <span class="finding-title">${f.name}</span>
                        <span class="severity-badge sev-${f.severity}">${f.severity}</span>
                    </div>
                    <div class="finding-desc">${f.description}</div>
                    <div class="finding-code">Line ${f.line}: ${escapeHtml(f.code)}</div>
                    <div class="finding-meta">
                        <span>${f.cwe}</span>
                        <span>${f.swc}</span>
                    </div>
                    <div class="finding-fix">
                        <strong>🔧 Fix:</strong> ${f.fix}
                    </div>
                </div>
            `).join('');

            results.scrollIntoView({ behavior: 'smooth' });
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>'''


@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    data = request.get_json()
    code = data.get('code', '')
    if not code:
        return jsonify({"error": "No code provided"}), 400
    
    result = analyze_contract(code)
    return jsonify(result)


@app.route('/health')
def health():
    return jsonify({"status": "ok", "service": "smart-contract-auditor"})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=False)
