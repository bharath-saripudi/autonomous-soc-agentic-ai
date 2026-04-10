"""Attack Simulator — Generate realistic alert streams for demo.

Usage:
    1. Start server: uvicorn src.api.main:app --port 8000
    2. Run: python scripts/simulate_attack.py [scenario]

Scenarios:
    brute_force   — SSH brute force attack progression
    ransomware    — Ransomware kill chain (recon → lateral → encrypt)
    exfiltration  — Data exfiltration via DNS tunneling
    apt           — Advanced Persistent Threat multi-stage
    random        — Random mix of alert types (default)
"""
import asyncio, json, random, sys, time
import httpx

API_BASE = "http://localhost:8000"

SCENARIOS = {
    "brute_force": [
        {"source":"firewall","data":{"event_type":"ssh_auth_failure","src_ip":"45.33.32.156","dest_ip":"10.0.1.20","message":"Failed SSH login attempt","username":"root","count":1}},
        {"source":"firewall","data":{"event_type":"ssh_auth_failure","src_ip":"45.33.32.156","dest_ip":"10.0.1.20","message":"50 failed SSH login attempts in 2 minutes","username":"root","count":50}},
        {"source":"firewall","data":{"event_type":"ssh_brute_force","src_ip":"45.33.32.156","dest_ip":"10.0.1.20","message":"342 failed SSH login attempts — brute force detected","username":"root","count":342}},
        {"source":"ids","data":{"event_type":"ssh_auth_success","src_ip":"45.33.32.156","dest_ip":"10.0.1.20","message":"SSH login succeeded after 342 failures — possible compromise","username":"root"}},
        {"source":"edr","data":{"event_type":"suspicious_process","hostname":"WS-FINANCE-04","process":"reverse_shell.py","pid":4521,"message":"Reverse shell spawned after SSH compromise","parent_process":"sshd"}},
    ],
    "ransomware": [
        {"source":"edr","data":{"event_type":"suspicious_download","hostname":"WS-HR-02","src_ip":"10.0.2.15","dest_ip":"91.215.85.120","message":"Executable downloaded from suspicious domain","filename":"update_v2.exe","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}},
        {"source":"edr","data":{"event_type":"privilege_escalation","hostname":"WS-HR-02","process":"update_v2.exe","message":"Process attempted to escalate to SYSTEM privileges","technique":"T1548"}},
        {"source":"edr","data":{"event_type":"lateral_movement","src_ip":"10.0.2.15","dest_ip":"10.0.2.20","message":"SMB connection to file server — possible lateral movement","technique":"T1021.002"}},
        {"source":"edr","data":{"event_type":"mass_file_encryption","hostname":"FS-01","process":"update_v2.exe","message":"Mass file encryption detected — 2,847 files encrypted in 3 minutes","file_extension":".locked","files_affected":2847}},
        {"source":"edr","data":{"event_type":"ransom_note","hostname":"FS-01","message":"Ransom note README_DECRYPT.txt created on desktop","filename":"README_DECRYPT.txt"}},
    ],
    "exfiltration": [
        {"source":"proxy","data":{"event_type":"unusual_dns_volume","src_ip":"10.0.5.30","dest_ip":"8.8.8.8","message":"Anomalous DNS query volume: 15,000 queries in 10 minutes","query_count":15000}},
        {"source":"dns","data":{"event_type":"dns_tunneling","src_ip":"10.0.5.30","message":"Encoded data detected in DNS TXT queries to susp-domain.xyz","domain":"susp-domain.xyz","technique":"T1071.004"}},
        {"source":"dlp","data":{"event_type":"data_exfiltration","src_ip":"10.0.5.30","dest_ip":"198.51.100.50","message":"4.2 GB of data transferred via DNS tunneling","bytes_transferred":4509715660,"duration_sec":600}},
    ],
    "apt": [
        {"source":"email","data":{"event_type":"spearphishing","dest_ip":"10.0.3.5","message":"Spearphishing email with macro-enabled attachment detected","filename":"Q3_Report.xlsm","sender":"ceo@competitor.com"}},
        {"source":"edr","data":{"event_type":"macro_execution","hostname":"WS-EXEC-01","process":"EXCEL.EXE","message":"Macro executed PowerShell with encoded command","child_process":"powershell.exe -enc ..."}},
        {"source":"ndr","data":{"event_type":"c2_beacon","src_ip":"10.0.3.5","dest_ip":"185.220.101.1","message":"Periodic HTTPS beaconing to known C2 infrastructure — interval 60s","interval_sec":60,"technique":"T1071.001"}},
        {"source":"edr","data":{"event_type":"credential_dump","hostname":"WS-EXEC-01","process":"mimikatz.exe","message":"Credential harvesting tool detected — LSASS memory access","technique":"T1003.001"}},
        {"source":"ad","data":{"event_type":"golden_ticket","hostname":"DC-01","message":"Kerberos TGT forged — Golden Ticket attack detected","technique":"T1558.001","username":"krbtgt"}},
    ],
}


async def simulate(scenario: str, delay: float = 3.0):
    alerts = SCENARIOS.get(scenario)
    if not alerts:
        print(f"Unknown scenario: {scenario}")
        print(f"Available: {', '.join(SCENARIOS.keys())}, random")
        return

    print(f"\n{'='*55}")
    print(f"  Attack Simulation: {scenario.upper()}")
    print(f"  Sending {len(alerts)} alerts with {delay}s delay")
    print(f"{'='*55}\n")

    async with httpx.AsyncClient(timeout=30) as client:
        for i, alert in enumerate(alerts):
            print(f"  [{i+1}/{len(alerts)}] {alert['data'].get('event_type','unknown')}")
            try:
                resp = await client.post(f"{API_BASE}/alerts", json=alert)
                if resp.status_code == 202:
                    r = resp.json()
                    print(f"           → {r['alert_id'][:12]}... ✅")
                else:
                    print(f"           → HTTP {resp.status_code} ❌")
            except Exception as e:
                print(f"           → Error: {e} ❌")

            if i < len(alerts) - 1:
                await asyncio.sleep(delay)

    print(f"\n  Simulation complete. Watch server logs for AI analysis.\n")


async def simulate_random(count: int = 10, delay: float = 2.0):
    all_alerts = []
    for alerts in SCENARIOS.values():
        all_alerts.extend(alerts)

    print(f"\n{'='*55}")
    print(f"  Random Attack Simulation: {count} alerts")
    print(f"{'='*55}\n")

    async with httpx.AsyncClient(timeout=30) as client:
        for i in range(count):
            alert = random.choice(all_alerts)
            print(f"  [{i+1}/{count}] {alert['data'].get('event_type','unknown')}")
            try:
                resp = await client.post(f"{API_BASE}/alerts", json=alert)
                if resp.status_code == 202:
                    print(f"           → ✅")
            except:
                print(f"           → ❌")
            await asyncio.sleep(delay)

    print(f"\n  Done.\n")


if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "random"
    if scenario == "random":
        count = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        asyncio.run(simulate_random(count))
    else:
        asyncio.run(simulate(scenario))
