import re
import sys
import socket
import requests
from datetime import datetime
from email import message_from_file
from email.utils import parsedate_to_datetime
from ipaddress import ip_address, IPv4Address

def check_ip_reputation(ip):
    """Check IP against common blacklists."""
    try:
        # Basic DNS blacklist check (example with Spamhaus)
        ip_parts = ip.split('.')
        reverse_ip = '.'.join(reversed(ip_parts))
        try:
            socket.gethostbyname(f"{reverse_ip}.zen.spamhaus.org")
            return False  # Listed in blacklist
        except socket.gaierror:
            return True  # Not listed
    except:
        return True  # Unable to check, assume good

def validate_message_id(message_id):
    """Validate Message-ID format."""
    if not message_id:
        return False
    pattern = r'^<[A-Za-z0-9!#$%&\'*+\-/=?^_`{|}~.]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}>$'
    return bool(re.match(pattern, message_id))

def extract_headers_from_email_file(email_file_path):
    """Extract the header section from a raw email file."""
    with open(email_file_path, 'r', encoding='utf-8', errors='replace') as f:
        msg = message_from_file(f)
        headers = []
        for k, v in msg.items():
            headers.append(f"{k}: {v}")
        return "\n".join(headers)

def analyze_email_header(header_text):
    """Analyze email header for phishing, spoofing, and misconfiguration indicators."""
    findings = []
    risk_score = 0

    # Convert header to dict
    headers = {}
    for line in header_text.split("\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

    # 1. Message-ID Validation
    message_id = headers.get("message-id", "")
    if not validate_message_id(message_id):
        findings.append(f"Invalid or missing Message-ID: {message_id}")
        risk_score += 10

    # 2. Return-Path vs From Analysis
    return_path = headers.get("return-path", "")
    from_email = headers.get("from", "")
    if return_path and from_email:
        # Extract email from Return-Path
        return_path_email = re.search(r'<?([\w\.-]+@[\w\.-]+)>?', return_path)
        from_email_addr = re.search(r'<?([\w\.-]+@[\w\.-]+)>?', from_email)
        if return_path_email and from_email_addr:
            if return_path_email.group(1).lower() != from_email_addr.group(1).lower():
                findings.append(f"Return-Path mismatch with From: {return_path} vs {from_email}")
                risk_score += 15

    # 3. Date Header Analysis
    date_header = headers.get("date", "")
    if date_header:
        try:
            email_date = parsedate_to_datetime(date_header)
            time_diff = abs((datetime.now() - email_date).total_seconds())
            if time_diff > 86400 * 7:  # More than 7 days old
                findings.append(f"Suspicious email date: {date_header}")
                risk_score += 5
        except:
            findings.append(f"Invalid date format: {date_header}")
            risk_score += 5

    # 4. Check From vs Reply-To mismatch
    from_email = headers.get("from", "")
    reply_to = headers.get("reply-to", "")
    if reply_to and reply_to.lower() != from_email.lower():
        findings.append(f"Mismatch between FROM and REPLY-TO: {from_email} vs {reply_to}")
        risk_score += 15

    # 5. Check suspicious domains in From
    if from_email and not re.search(r'@[a-z0-9.-]+\.[a-z]{2,}$', from_email, re.I):
        findings.append(f"Invalid FROM address format: {from_email}")
        risk_score += 20

    # 6. SPF check
    received_spf = headers.get("received-spf", "")
    if "fail" in received_spf.lower() or "softfail" in received_spf.lower():
        findings.append(f"SPF check failed: {received_spf}")
        risk_score += 25

    # 7. DKIM check
    auth_results = headers.get("authentication-results", "")
    if "dkim=fail" in auth_results.lower():
        findings.append(f"DKIM check failed: {auth_results}")
        risk_score += 25

    # 8. DMARC check
    if "dmarc=fail" in auth_results.lower():
        findings.append(f"DMARC check failed: {auth_results}")
        risk_score += 30

    # 9. Enhanced IP Analysis
    ip_headers = {
        'x-originating-ip': headers.get("x-originating-ip", ""),
        'x-sender-ip': headers.get("x-sender-ip", ""),
        'x-remote-ip': headers.get("x-remote-ip", "")
    }
    
    for header_name, ip in ip_headers.items():
        if ip:
            # Validate IP format
            try:
                parsed_ip = ip_address(ip.strip('[]'))
                if isinstance(parsed_ip, IPv4Address):
                    # Check IP reputation
                    if not check_ip_reputation(str(parsed_ip)):
                        findings.append(f"IP {parsed_ip} found in blacklist ({header_name})")
                        risk_score += 20
                    # Check if IP is from common cloud providers
                    if any(cloud_prefix in str(parsed_ip) for cloud_prefix in ['13.', '52.', '34.', '35.']):  # AWS examples
                        findings.append(f"Sender IP from cloud provider: {parsed_ip}")
                        risk_score += 5
            except ValueError:
                findings.append(f"Invalid IP format in {header_name}: {ip}")
                risk_score += 10

    # Analysis of Received Chain
    received_headers = [line for line in header_text.split("\n") if line.lower().startswith("received:")]
    if len(received_headers) < 2:
        findings.append("Too few 'Received' headers — possible spoofing")
        risk_score += 20

    # Check for missing important headers
    important_headers = ["from", "to", "subject", "date"]
    for h in important_headers:
        if h not in headers:
            findings.append(f"Missing important header: {h}")
            risk_score += 15

    # Check for suspicious keywords in subject
    subject = headers.get("subject", "")
    if re.search(r'(urgent|verify|action required|password|account|login)', subject, re.I):
        findings.append(f"Suspicious keywords in subject: {subject}")
        risk_score += 10

    # Categorize based on risk score and findings
    if risk_score < 20:
        category = "clean"
    elif risk_score >= 50:
        category = "malicious"
    else:
        category = "suspicious"
    
    return {
        "category": category,
        "risk_score": risk_score,
        "findings": findings
    }

def main():
    if len(sys.argv) < 2:
        print("Usage: python email_header_analysis.py <email_file.eml>")
        sys.exit(1)
    email_file = sys.argv[1]
    header_text = extract_headers_from_email_file(email_file)
    result = analyze_email_header(header_text)
    print(f"Category: {result['category'].upper()}")
    print(f"Risk Score: {result['risk_score']}")
    if result['findings']:
        print("Indicators:")
        for f in result['findings']:
            print(f"- {f}")
    else:
        print("No obvious phishing signs found in header.")

if __name__ == "__main__":
    main()
