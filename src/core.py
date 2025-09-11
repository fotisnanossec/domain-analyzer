import os
import re
import subprocess
import json
import ipaddress
import requests
from .exceptions import ToolNotFoundError, SubprocessFailedError, ReportGenerationError
from .clients import LMStudioClient
import ssl

# A more comprehensive list of common security headers to check for.
# These headers are crucial for mitigating common web-based attacks.
SECURITY_HEADERS_LIST = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "X-XSS-Protection"
]

class DomainAnalyzer:
    """Class to gather security intelligence for a given domain or IP address."""
    def __init__(self, target):
        self.target = target
        try:
            ipaddress.ip_address(self.target)
            self.is_ip = True
        except ValueError:
            self.is_ip = False

    def _run_command(self, cmd, tool_name, stdin=None):
        """Standardized command execution method, wrapping subprocess.run with specific error handling."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False, stdin=stdin)
            
            if result.returncode != 0:
                if tool_name == "whois" and ("No match for" in result.stdout or "No match for" in result.stderr):
                    return f"No WHOIS data found for {self.target}."
                
                if tool_name == "nmap" and "is not a host or a network" in result.stderr:
                    return f"Nmap scan skipped: {self.target} is not a valid host for a direct scan."
                
                raise SubprocessFailedError(f"Command '{tool_name}' failed with return code {result.returncode}: {result.stderr}")
            return result.stdout
        except FileNotFoundError:
            raise ToolNotFoundError(f"The tool '{tool_name}' was not found. Please ensure it is installed and in your system's PATH.")
        except subprocess.TimeoutExpired:
            raise SubprocessFailedError(f"Command '{tool_name}' timed out after 300 seconds.")

    def _get_whois_info(self):
        """Retrieves WHOIS information for a domain or IP."""
        return self._run_command(["whois", self.target], "whois")

    def _get_dns_info(self):
        """Retrieves DNS records for a domain."""
        return self._run_command(["dig", "ANY", self.target], "dig")

    def _get_ssl_info(self):
        """Retrieves SSL/TLS certificate information for a domain."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            with context.wrap_socket(socket.socket(), server_hostname=self.target) as s:
                s.connect((self.target, 443))
                cert_info = s.getpeercert()
                
                # Format certificate information into a string
                cert_output = f"Certificate Subject: {cert_info['subject']}\n"
                cert_output += f"Certificate Issuer: {cert_info['issuer']}\n"
                cert_output += f"Valid from: {cert_info['notBefore']}\n"
                cert_output += f"Valid until: {cert_info['notAfter']}\n"
                
                return cert_output
        except Exception as e:
            return f"SSL check failed: {e}"

    def _check_security_headers(self):
        """Checks for security headers on a domain using requests."""
        headers = {}
        try:
            # Use requests for a more reliable HTTP check that follows redirects.
            response = requests.get(f"http://{self.target}", timeout=10, allow_redirects=True)
            for key, value in response.headers.items():
                headers[key] = value
            return headers
        except Exception:
            return None

    def _parse_headers(self, raw_headers):
        """
        Parses raw HTTP header output into a structured dictionary.
        Also identifies common missing security headers.
        """
        if not raw_headers:
            return {"status": "Could not retrieve headers", "missing_headers": SECURITY_HEADERS_LIST}
        
        parsed = {key.strip().replace('-', ' ').title().replace(' ', '-'): value.strip() for key, value in raw_headers.items()}
        
        # Check for missing security headers
        parsed["missing_headers"] = [header for header in SECURITY_HEADERS_LIST if header not in raw_headers]
        
        return parsed

    def gather_intelligence(self, cancel_event=None):
        """Gathers intelligence using various security tools."""
        results = {}

        def _perform_check(task_name, check_function):
            if cancel_event and cancel_event.is_set():
                return None
            
            result = check_function()
            if result and isinstance(result, str) and result.startswith("Error:"):
                print(f"{task_name} failed: {result}")
            return result

        # Whois lookup
        whois_data = _perform_check("Whois lookup", self._get_whois_info)
        results["whois"] = whois_data

        # DNS lookup (only for domains)
        if not self.is_ip:
            dns_data = _perform_check("DNS lookup", self._get_dns_info)
            results["dns"] = dns_data
        else:
            results["dns"] = "DNS lookup not applicable for IP address."

        # Nmap scan
        nmap_data = _perform_check("Nmap scan", lambda: self._run_command(["nmap", "-sV", "-p", "80,443", self.target], "nmap"))
        results["nmap"] = nmap_data

        # HTTP Headers check (only for domains)
        if not self.is_ip:
            raw_headers = _perform_check("Security Headers check", self._check_security_headers)
            results["security_headers"] = self._parse_headers(raw_headers)
        else:
            results["security_headers"] = "Security Headers check not applicable for IP address."
            
        # SSL check (only for domains)
        if not self.is_ip:
            ssl_data = _perform_check("SSL check", self._get_ssl_info)
            results["ssl_info"] = ssl_data
        else:
            results["ssl_info"] = "SSL check not applicable for IP address."

        return json.dumps(results, indent=2)


class ReportService:
    """Encapsulates the full analysis and report generation workflow."""
    def __init__(self, config):
        self.lm_studio_client = LMStudioClient(config)
        self.reports_dir = config.get("paths", {}).get("reports_dir", "reports")
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
        
        self.llm_prompt = self._load_llm_prompt()

    def _load_llm_prompt(self):
        """Loads the LLM prompt from an external file."""
        prompt_path = "prompts/llm_prompt.txt"
        
        if os.path.exists(prompt_path):
            with open(prompt_path, "r") as f:
                return f.read()
        else:
            # Raise a FileNotFoundError if the prompt file is missing
            raise FileNotFoundError(f"The LLM prompt file was not found at {prompt_path}.")

    def generate_security_report(self, domain, mock_data=None, cancel_event=None):
        """The core workflow method."""
        try:
            if mock_data:
                security_data = mock_data
            else:
                analyzer = DomainAnalyzer(domain)
                security_data = analyzer.gather_intelligence(cancel_event)
            
            if cancel_event and cancel_event.is_set():
                return "Analysis canceled."
            
            llm_prompt = self.llm_prompt + security_data
            report_content = self.lm_studio_client.generate_report(llm_prompt)
            
            if not mock_data:
                self.save_report(domain, report_content)
            
            return report_content
        except Exception as e:
            raise ReportGenerationError(f"Failed to generate report: {e}")

    def save_report(self, target, report):
        """Saves the generated report to a file."""
        report_filename = f"{target}_security_report.txt"
        report_path = os.path.join(self.reports_dir, report_filename)
        with open(report_path, "w") as f:
            f.write(report)

