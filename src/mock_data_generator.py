import json
import random
from datetime import datetime, timedelta

def generate_mock_data(scenario="secure"):
    """
    Generates structured mock security data for a given scenario.

    Args:
        scenario (str): The type of security posture to simulate.
                        Options: "secure", "vulnerable", "no-dnssec"

    Returns:
        str: A JSON string containing the mock security data.
    """
    now = datetime.utcnow()
    future_date = now + timedelta(days=365)
    
    # Base template for the JSON structure
    base_data = {
        "whois": """Domain Name: MOCKDOMAIN.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
Name Server: ns1.mock-servers.net
Name Server: ns2.mock-servers.net
DNSSEC: signedDelegation
Registry Expiry Date: 2026-08-30T04:00:00Z""",
        "dns": """; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> ANY mockdomain.com
;; ANSWER SECTION:
mockdomain.com.		300	IN	NS	ns1.mock-servers.net.
mockdomain.com.		300	IN	NS	ns2.mock-servers.net.
mockdomain.com.		300	IN	DS	370 13 2 1234567890abcdef1234567890abcdef12345678""",
        "nmap": """PORT     STATE SERVICE  VERSION
80/tcp   open  http     Apache httpd 2.4.52 ((Debian))
443/tcp  open  ssl/http Apache httpd 2.4.52 ((Debian))
|_http-title: Mock Domain - Secure""",
        "ssl_info": f"""---
Certificate chain
 0 s:C=US, O=Example Inc, CN=*.mockdomain.com
   i:C=US, O=DigiCert Inc, CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1
   v:NotBefore: Jan 15 00:00:00 {now.year} GMT; NotAfter: Jan 15 23:59:59 {future_date.year} GMT
---
Server certificate
subject=C=US, O=Example Inc, CN=*.mockdomain.com
issuer=C=US, O=DigiCert Inc, CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1
---
No client certificate CA names sent
Verify return code: 0 (ok)""",
        "security_headers": {
            "status_line": "HTTP/1.1 200 OK",
            "Content-Type": "text/html",
            "Content-Length": "12345",
            "Cache-Control": "max-age=3600",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
            "missing_headers": []
        }
    }

    # Customize data based on the scenario
    if scenario == "vulnerable":
        base_data["nmap"] = """PORT     STATE SERVICE  VERSION
80/tcp   open  http     Apache httpd 2.4.52 ((Debian))
443/tcp  open  ssl/http Apache httpd 2.4.52 ((Debian))
|_http-title: Mock Domain - Vulnerable"""
        base_data["ssl_info"] = """---
Certificate chain
 0 s:C=US, O=Example Inc, CN=*.mockdomain.com
   i:C=US, O=DigiCert Inc, CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1
   v:NotBefore: Jan 15 00:00:00 2024 GMT; NotAfter: Jan 15 23:59:59 2025 GMT
---
Server certificate
subject=C=US, O=Example Inc, CN=*.mockdomain.com
issuer=C=US, O=DigiCert Inc, CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1
---
No client certificate CA names sent
Verify return code: 10 (certificate has expired)"""
        base_data["security_headers"]["X-Frame-Options"] = "ALLOWALL" # A bad value
        base_data["security_headers"]["Strict-Transport-Security"] = None
        base_data["security_headers"]["missing_headers"] = [
            "Content-Security-Policy",
            "Referrer-Policy"
        ]

    elif scenario == "no-dnssec":
        base_data["whois"] = base_data["whois"].replace("DNSSEC: signedDelegation", "DNSSEC: unsigned")
        base_data["dns"] = """
;; ANSWER SECTION:
mockdomain.com.		300	IN	NS	ns1.mock-servers.net.
mockdomain.com.		300	IN	NS	ns2.mock-servers.net."""
    
    return json.dumps(base_data, indent=2)

if __name__ == '__main__':
    # Example usage:
    print("--- Secure Mock Data ---")
    secure_data = generate_mock_data("secure")
    print(secure_data)
    
    print("\n--- Vulnerable Mock Data ---")
    vulnerable_data = generate_mock_data("vulnerable")
    print(vulnerable_data)

    print("\n--- No DNSSEC Mock Data ---")
    no_dnssec_data = generate_mock_data("no-dnssec")
    print(no_dnssec_data)
