#!/usr/bin/env python3
# ============================================================
# HTTPS ORDINARYX
# Authorized Security Audit Toolkit
# Single-file / Linux + Termux
# ============================================================

import argparse
import hashlib
import json
import re
import socket
import ssl
import sys
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs

try:
    import requests
except ImportError:
    print("[!] requests লাগবে:")
    print("    pip install requests")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
except ImportError:
    Console = None
    Table = None


VERSION = "1.0"
TIMEOUT = 8

console = Console() if Console else None


def out(msg="", style=None):
    if console:
        console.print(msg, style=style)
    else:
        print(msg)


def banner():
    out(r"""
╔══════════════════════════════════════════════╗
║                                              ║
║             ██╗  ██╗████████╗               ║
║             ██║  ██║╚══██╔══╝               ║
║             ╚██╗██╔╝   ██║                  ║
║              ╚███╔╝    ██║                  ║
║               ╚══╝     ╚═╝                  ║
║                                              ║
║              HTTPS ORDINARYX                 ║
║          SECURITY AUDIT TOOLKIT              ║
║                                              ║
║                 v1.0                         ║
╚══════════════════════════════════════════════╝
""")


def normalize_url(target):
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target.rstrip("/")


def hostname(target):
    return urlparse(normalize_url(target)).hostname


def check_scope(target):
    host = hostname(target)

    if not host:
        return False

    # Prevent accidentally accepting malformed URLs.
    if " " in host:
        return False

    return True


def dns_lookup(target):
    host = hostname(target)

    out("\n[ DNS LOOKUP ]", "cyan")

    try:
        results = socket.getaddrinfo(host, None)
        ips = sorted(set(x[4][0] for x in results))

        for ip in ips:
            out(f"[+] {ip}", "green")

        return {"host": host, "ips": ips}

    except Exception as e:
        out(f"[-] DNS error: {e}", "red")
        return {"host": host, "ips": []}


def reverse_dns(target):
    host = hostname(target)

    out("\n[ REVERSE DNS ]", "cyan")

    try:
        ip = socket.gethostbyname(host)
        name = socket.gethostbyaddr(ip)[0]

        out(f"[+] {ip} -> {name}", "green")

        return {
            "ip": ip,
            "hostname": name
        }

    except Exception as e:
        out(f"[-] Reverse DNS failed: {e}", "yellow")
        return {}


def port_scan(target, ports=None):
    host = hostname(target)

    if ports is None:
        ports = [
            21, 22, 23, 25, 53,
            80, 110, 143, 443,
            445, 3306, 5432,
            6379, 8080, 8443
        ]

    out("\n[ PORT AUDIT ]", "cyan")

    results = []

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.7)

        try:
            result = s.connect_ex((host, port))

            if result == 0:
                out(f"[OPEN] {port}", "green")
                results.append(port)

        except Exception:
            pass

        finally:
            s.close()

    if not results:
        out("[*] No tested ports reported open.", "yellow")

    return results


def http_request(url):
    headers = {
        "User-Agent": "HTTPS-OrdinaryX/1.0 Security-Audit"
    }

    try:
        return requests.get(
            url,
            headers=headers,
            timeout=TIMEOUT,
            allow_redirects=True,
            verify=True
        )

    except requests.exceptions.SSLError as e:
        out(f"[!] TLS verification error: {e}", "yellow")

    except requests.exceptions.RequestException as e:
        out(f"[-] HTTP error: {e}", "red")

    return None


def http_headers_audit(url):
    out("\n[ HTTP SECURITY HEADERS ]", "cyan")

    r = http_request(url)

    if not r:
        return {}

    headers = {k.lower(): v for k, v in r.headers.items()}

    recommended = {
        "strict-transport-security":
            "HSTS missing",
        "content-security-policy":
            "CSP missing",
        "x-content-type-options":
            "X-Content-Type-Options missing",
        "referrer-policy":
            "Referrer-Policy missing",
        "permissions-policy":
            "Permissions-Policy missing",
        "x-frame-options":
            "X-Frame-Options missing"
    }

    findings = []

    for header, message in recommended.items():

        if header not in headers:
            out(f"[!] {message}", "yellow")
            findings.append(message)
        else:
            out(f"[+] {header}: {headers[header]}", "green")

    out(f"[+] Status: {r.status_code}", "green")
    out(f"[+] Server: {r.headers.get('Server', 'unknown')}", "green")

    return {
        "status": r.status_code,
        "headers": dict(r.headers),
        "findings": findings
    }


def cookie_audit(url):
    out("\n[ COOKIE SECURITY AUDIT ]", "cyan")

    r = http_request(url)

    if not r:
        return {}

    cookies = []

    for cookie in r.cookies:

        data = {
            "name": cookie.name,
            "secure": bool(cookie.secure),
            "httponly": "httponly" in str(cookie._rest).lower(),
            "samesite": str(cookie._rest.get("SameSite", "unknown"))
        }

        cookies.append(data)

        if not data["secure"] and url.startswith("https://"):
            out(
                f"[!] Cookie '{cookie.name}' lacks Secure flag",
                "yellow"
            )

        if not data["httponly"]:
            out(
                f"[!] Cookie '{cookie.name}' may lack HttpOnly",
                "yellow"
            )

        out(
            f"[+] {cookie.name} | "
            f"Secure={data['secure']} | "
            f"HttpOnly={data['httponly']} | "
            f"SameSite={data['samesite']}"
        )

    if not cookies:
        out("[*] No cookies observed.", "yellow")

    return {"cookies": cookies}


def cors_audit(url):
    out("\n[ CORS AUDIT ]", "cyan")

    try:
        r = requests.get(
            url,
            headers={
                "Origin": "https://ordinaryx-security-test.invalid"
            },
            timeout=TIMEOUT
        )

        acao = r.headers.get(
            "Access-Control-Allow-Origin"
        )

        acac = r.headers.get(
            "Access-Control-Allow-Credentials"
        )

        if acao:
            out(f"[+] ACAO: {acao}", "green")

            if acao == "*" and acac == "true":
                out(
                    "[!] Potentially unsafe wildcard + credentials configuration",
                    "yellow"
                )

        else:
            out("[*] No CORS header observed.", "yellow")

        return {
            "allow_origin": acao,
            "allow_credentials": acac
        }

    except Exception as e:
        out(f"[-] CORS check failed: {e}", "red")
        return {}


def tls_audit(target):
    host = hostname(target)

    out("\n[ TLS AUDIT ]", "cyan")

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (host, 443),
            timeout=TIMEOUT
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=host
            ) as ssock:

                version = ssock.version()
                cipher = ssock.cipher()
                cert = ssock.getpeercert()

                out(f"[+] TLS version: {version}", "green")
                out(f"[+] Cipher: {cipher[0]}", "green")

                return {
                    "tls_version": version,
                    "cipher": cipher[0],
                    "certificate": cert
                }

    except Exception as e:
        out(f"[-] TLS audit failed: {e}", "yellow")
        return {}


def technology_detection(url):
    out("\n[ TECHNOLOGY DETECTION ]", "cyan")

    r = http_request(url)

    if not r:
        return {}

    text = r.text.lower()
    headers = {k.lower(): v for k, v in r.headers.items()}

    technologies = []

    signatures = {
        "WordPress": [
            "wp-content",
            "wp-includes"
        ],
        "PHP": [
            ".php"
        ],
        "Laravel": [
            "laravel"
        ],
        "Django": [
            "csrfmiddlewaretoken"
        ],
        "React": [
            "react"
        ],
        "Vue": [
            "vue"
        ],
        "Next.js": [
            "__next"
        ],
        "ASP.NET": [
            "asp.net"
        ]
    }

    for tech, patterns in signatures.items():

        for pattern in patterns:

            if pattern in text:
                technologies.append(tech)
                out(f"[+] Possible {tech}", "green")
                break

    server = headers.get("server")

    if server:
        out(f"[+] Server: {server}")

    return {
        "technologies": sorted(set(technologies)),
        "server": server
    }


def sql_audit(url):
    """
    Non-destructive SQL injection indicator check.

    It does NOT:
    - dump databases
    - extract credentials
    - modify/delete data
    - run destructive SQL
    """

    out("\n[ SQL SECURITY AUDIT ]", "cyan")

    parsed = urlparse(url)

    if not parsed.query:
        out("[*] URL contains no query parameters.", "yellow")
        out("[*] Example authorized test URL: https://site.test/page?id=1")
        return {}

    params = parse_qs(parsed.query, keep_blank_values=True)

    baseline = http_request(url)

    if not baseline:
        return {}

    findings = []

    # Harmless syntax characters used only to compare responses.
    test_suffixes = ["'", "\""]

    for name, values in params.items():

        if not values:
            continue

        original = values[0]

        for suffix in test_suffixes:

            modified = url.replace(
                f"{name}={original}",
                f"{name}={original}{suffix}",
                1
            )

            try:
                r = requests.get(
                    modified,
                    headers={
                        "User-Agent":
                            "HTTPS-OrdinaryX/1.0 SQL-Audit"
                    },
                    timeout=TIMEOUT
                )

                text = r.text.lower()

                db_errors = [
                    "sql syntax",
                    "mysql",
                    "mysqli",
                    "postgresql",
                    "pg_query",
                    "sqlite error",
                    "sqlite3",
                    "ora-",
                    "oracle error",
                    "odbc",
                    "sqlstate",
                    "microsoft sql server"
                ]

                matched = [
                    x for x in db_errors
                    if x in text
                ]

                if matched:
                    finding = {
                        "parameter": name,
                        "indicator": matched,
                        "confidence": "medium"
                    }

                    findings.append(finding)

                    out(
                        f"[!] Possible SQL injection indicator "
                        f"on parameter: {name}",
                        "yellow"
                    )

                    out(
                        f"    Database error pattern: "
                        f"{', '.join(matched)}",
                        "yellow"
                    )

                    break

                # Compare significant response-size changes.
                difference = abs(
                    len(r.text) - len(baseline.text)
                )

                if difference > max(
                    1000,
                    int(len(baseline.text) * 0.30)
                ):
                    out(
                        f"[?] Response changed significantly for '{name}' "
                        f"after syntax test",
                        "yellow"
                    )

            except requests.RequestException:
                pass

    if not findings:
        out(
            "[+] No obvious SQL error indicators detected.",
            "green"
        )

    return {"findings": findings}


def xss_audit(url):
    """
    Safe reflected-input indicator.

    Uses a unique harmless marker rather than executable JavaScript.
    """

    out("\n[ XSS REFLECTION AUDIT ]", "cyan")

    parsed = urlparse(url)

    if not parsed.query:
        out("[*] No query parameters found.", "yellow")
        return {}

    params = parse_qs(
        parsed.query,
        keep_blank_values=True
    )

    marker = "ORDINARYX_REFLECT_TEST_7F3A"

    findings = []

    for name, values in params.items():

        if not values:
            continue

        original = values[0]

        test_url = url.replace(
            f"{name}={original}",
            f"{name}={marker}",
            1
        )

        try:
            r = requests.get(
                test_url,
                headers={
                    "User-Agent":
                        "HTTPS-OrdinaryX/1.0 XSS-Audit"
                },
                timeout=TIMEOUT
            )

            if marker in r.text:

                out(
                    f"[!] Reflected input detected: {name}",
                    "yellow"
                )

                findings.append({
                    "parameter": name,
                    "type": "reflected-input"
                })

        except requests.RequestException:
            pass

    if not findings:
        out(
            "[+] No reflected marker detected.",
            "green"
        )

    return {"findings": findings}


def redirect_audit(url):
    out("\n[ REDIRECT AUDIT ]", "cyan")

    try:
        r = requests.get(
            url,
            headers={
                "User-Agent": "HTTPS-OrdinaryX/1.0"
            },
            timeout=TIMEOUT,
            allow_redirects=False
        )

        location = r.headers.get("Location")

        if location:
            destination = urljoin(url, location)

            out(f"[+] Redirect: {destination}", "green")

            return {
                "status": r.status_code,
                "location": destination
            }

        out("[*] No redirect observed.")

    except Exception as e:
        out(f"[-] Redirect check failed: {e}", "red")

    return {}


def robots_check(url):
    out("\n[ ROBOTS.TXT ]", "cyan")

    robots = urljoin(
        url.rstrip("/") + "/",
        "robots.txt"
    )

    try:
        r = requests.get(
            robots,
            headers={
                "User-Agent": "HTTPS-OrdinaryX/1.0"
            },
            timeout=TIMEOUT
        )

        if r.status_code == 200:

            out("[+] robots.txt found", "green")

            lines = [
                x.strip()
                for x in r.text.splitlines()
                if x.strip()
            ]

            return {
                "status": 200,
                "lines": lines[:100]
            }

        out("[*] robots.txt not found.")

    except Exception as e:
        out(f"[-] robots check failed: {e}", "yellow")

    return {}


def basic_crawler(url, limit=20):
    out("\n[ BASIC WEB CRAWLER ]", "cyan")

    visited = set()
    queue = [url]

    while queue and len(visited) < limit:

        current = queue.pop(0)

        if current in visited:
            continue

        try:
            r = requests.get(
                current,
                headers={
                    "User-Agent":
                        "HTTPS-OrdinaryX/1.0 Crawler"
                },
                timeout=TIMEOUT
            )

            visited.add(current)

            out(
                f"[+] {len(visited):02d} {current}",
                "green"
            )

            content_type = r.headers.get(
                "Content-Type",
                ""
            )

            if "text/html" not in content_type:
                continue

            links = re.findall(
                r'href=["\']([^"\']+)["\']',
                r.text,
                re.I
            )

            base_host = hostname(url)

            for link in links:

                absolute = urljoin(
                    current,
                    link
                ).split("#")[0]

                if (
                    urlparse(absolute).hostname
                    == base_host
                    and absolute not in visited
                ):
                    queue.append(absolute)

        except requests.RequestException:
            pass

    return {
        "visited": list(visited)
    }


def hash_string(value):
    out("\n[ HASH ]", "cyan")

    result = {
        "md5": hashlib.md5(
            value.encode()
        ).hexdigest(),

        "sha1": hashlib.sha1(
            value.encode()
        ).hexdigest(),

        "sha256": hashlib.sha256(
            value.encode()
        ).hexdigest()
    }

    for k, v in result.items():
        out(f"{k.upper()}: {v}")

    return result


def security_score(results):
    score = 100

    headers = results.get(
        "headers",
        {}
    )

    score -= len(
        headers.get("findings", [])
    ) * 5

    sql = results.get(
        "sql",
        {}
    )

    score -= len(
        sql.get("findings", [])
    ) * 20

    xss = results.get(
        "xss",
        {}
    )

    score -= len(
        xss.get("findings", [])
    ) * 15

    cors = results.get(
        "cors",
        {}
    )

    if (
        cors.get("allow_origin") == "*"
        and cors.get("allow_credentials") == "true"
    ):
        score -= 15

    return max(0, score)


def full_audit(target):
    target = normalize_url(target)

    if not check_scope(target):
        out("[-] Invalid target.", "red")
        return

    results = {
        "tool": "HTTPS OrdinaryX",
        "version": VERSION,
        "target": target,
        "time": datetime.now().isoformat()
    }

    out("\n[*] Starting authorized security audit...", "cyan")
    out(f"[*] Target: {target}", "cyan")

    results["dns"] = dns_lookup(target)
    results["reverse_dns"] = reverse_dns(target)
    results["ports"] = port_scan(target)
    results["headers"] = http_headers_audit(target)
    results["cookies"] = cookie_audit(target)
    results["cors"] = cors_audit(target)
    results["tls"] = tls_audit(target)
    results["technology"] = technology_detection(target)
    results["redirect"] = redirect_audit(target)
    results["robots"] = robots_check(target)

    # SQL/XSS checks only if query parameters exist.
    results["sql"] = sql_audit(target)
    results["xss"] = xss_audit(target)

    score = security_score(results)

    results["score"] = score

    out("\n══════════════════════════════════", "cyan")
    out(f" SECURITY SCORE: {score}/100", "bold")
    out("══════════════════════════════════", "cyan")

    return results


def save_report(results, filename=None):

    if not results:
        return

    if not filename:
        stamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        filename = (
            f"ordinaryx_report_{stamp}.json"
        )

    try:
        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                results,
                f,
                indent=2,
                ensure_ascii=False,
                default=str
            )

        out(
            f"\n[+] Report saved: {filename}",
            "green"
        )

    except Exception as e:
        out(
            f"[-] Report save failed: {e}",
            "red"
        )


def menu():

    while True:

        out("""
╔══════════════════════════════════════╗
║          HTTPS ORDINARYX            ║
║        SECURITY AUDIT MENU          ║
╠══════════════════════════════════════╣
║ 1. Full Authorized Audit            ║
║ 2. DNS Lookup                       ║
║ 3. Port Audit                       ║
║ 4. HTTP Header Audit                ║
║ 5. TLS Audit                        ║
║ 6. Cookie Audit                     ║
║ 7. CORS Audit                       ║
║ 8. Technology Detection             ║
║ 9. SQL Security Audit               ║
║ 10. XSS Reflection Audit            ║
║ 11. Web Crawler                     ║
║ 12. robots.txt Check                ║
║ 13. Hash Generator                  ║
║ 0. Exit                             ║
╚══════════════════════════════════════╝
""")

        choice = input("ordinaryx > ").strip()

        if choice == "0":
            out("[+] Bye!")
            break

        if choice == "13":
            value = input("Text > ")
            hash_string(value)
            continue

        target = input(
            "Target URL/domain > "
        ).strip()

        if not target:
            continue

        target = normalize_url(target)

        if not check_scope(target):
            out("[-] Invalid target.", "red")
            continue

        if choice == "1":
            results = full_audit(target)

            if results:
                save = input(
                    "Save JSON report? [y/N] "
                ).lower()

                if save == "y":
                    save_report(results)

        elif choice == "2":
            dns_lookup(target)

        elif choice == "3":
            port_scan(target)

        elif choice == "4":
            http_headers_audit(target)

        elif choice == "5":
            tls_audit(target)

        elif choice == "6":
            cookie_audit(target)

        elif choice == "7":
            cors_audit(target)

        elif choice == "8":
            technology_detection(target)

        elif choice == "9":
            sql_audit(target)

        elif choice == "10":
            xss_audit(target)

        elif choice == "11":
            basic_crawler(target)

        elif choice == "12":
            robots_check(target)

        else:
            out("[-] Unknown option.", "red")


def main():

    parser = argparse.ArgumentParser(
        description=
        "HTTPS OrdinaryX - Authorized Security Audit Toolkit"
    )

    parser.add_argument(
        "--target",
        help="Authorized URL/domain"
    )

    parser.add_argument(
        "--full",
        action="store_true",
        help="Run full audit"
    )

    parser.add_argument(
        "--dns",
        action="store_true",
        help="DNS lookup"
    )

    parser.add_argument(
        "--ports",
        action="store_true",
        help="Port audit"
    )

    parser.add_argument(
        "--headers",
        action="store_true",
        help="HTTP security headers"
    )

    parser.add_argument(
        "--tls",
        action="store_true",
        help="TLS audit"
    )

    parser.add_argument(
        "--sql",
        action="store_true",
        help="Non-destructive SQL security audit"
    )

    parser.add_argument(
        "--xss",
        action="store_true",
        help="Safe reflected-input check"
    )

    parser.add_argument(
        "--crawl",
        action="store_true",
        help="Basic same-host crawler"
    )

    parser.add_argument(
        "--report",
        help="JSON report filename"
    )

    args = parser.parse_args()

    banner()

    if not args.target:
        menu()
        return

    target = normalize_url(args.target)

    if not check_scope(target):
        out("[-] Invalid target.", "red")
        sys.exit(1)

    results = {}

    if args.full:
        results = full_audit(target)

    elif args.dns:
        results["dns"] = dns_lookup(target)

    elif args.ports:
        results["ports"] = port_scan(target)

    elif args.headers:
        results["headers"] = http_headers_audit(target)

    elif args.tls:
        results["tls"] = tls_audit(target)

    elif args.sql:
        results["sql"] = sql_audit(target)

    elif args.xss:
        results["xss"] = xss_audit(target)

    elif args.crawl:
        results["crawl"] = basic_crawler(target)

    else:
        menu()
        return

    if args.report and results:
        save_report(results, args.report)


if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        out("\n[!] Stopped.", "yellow")

    except Exception as e:
        out(f"\n[-] Unexpected error: {e}", "red")
