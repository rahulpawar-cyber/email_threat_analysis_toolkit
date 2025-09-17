import re
import sys
import ssl
import socket
import requests
import base64
import tldextract
import urllib.parse
from datetime import datetime
from email import message_from_file
from difflib import SequenceMatcher
from urllib3.util import parse_url

# Known URL shortener domains
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd',
    'cli.gs', 'pic.gd', 'DwarfURL.com', 'ow.ly', 'yfrog.com',
    'migre.me', 'ff.im', 'tiny.cc', 'url4.eu', 'tr.im',
    'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com', 'short.to',
    'budurl.com', 'ping.fm', 'post.ly', 'Just.as', 'bkite.com',
    'snipr.com', 'fic.kr', 'loopt.us', 'doiop.com', 'twitthis.com'
}

# Common brand names to check for typosquatting
COMMON_BRANDS = {
    # Tech Companies
    'google', 'microsoft', 'apple', 'amazon', 'facebook', 'meta',
    'twitter', 'linkedin', 'netflix', 'instagram', 'yahoo', 'spotify',
    'whatsapp', 'telegram', 'tiktok', 'snapchat', 'youtube',
    
    # Financial Services
    'paypal', 'visa', 'mastercard', 'amex', 'americanexpress',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc',
    'westernunion', 'venmo', 'coinbase', 'robinhood',
    
    # E-commerce
    'ebay', 'walmart', 'target', 'bestbuy', 'alibaba', 'shopify',
    'fedex', 'ups', 'dhl', 'usps',
    
    # Cloud Services
    'dropbox', 'icloud', 'onedrive', 'salesforce', 'zendesk',
    'github', 'gitlab', 'atlassian', 'slack', 'zoom'
}

def extract_urls_from_body(body):
	url_regex = r"(https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+)"
	return re.findall(url_regex, body)

def get_email_body(msg):
	if msg.is_multipart():
		for part in msg.walk():
			ctype = part.get_content_type()
			if ctype == 'text/plain' and not part.get('Content-Disposition'):
				return part.get_payload(decode=True).decode(errors='replace')
	else:
		return msg.get_payload(decode=True).decode(errors='replace')
	return ""

def check_ssl_cert(hostname):
    """Check SSL certificate validity."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                # Check if cert is expired
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y GMT')
                if datetime.now() > not_after:
                    return False
                return True
    except:
        return False

def is_potential_homograph(domain):
    """Check for potential homograph attacks using non-ASCII characters."""
    try:
        # Convert to IDNA to check if it contains non-ASCII characters
        idna = domain.encode('idna').decode('ascii')
        return idna != domain
    except:
        return True

def check_domain_similarity(domain):
    """Check if domain is similar to known brand names."""
    ext = tldextract.extract(domain)
    domain_name = ext.domain
    return max(
        SequenceMatcher(None, domain_name, brand).ratio()
        for brand in COMMON_BRANDS
    )

def analyze_path(path):
    """Analyze URL path for suspicious patterns."""
    suspicious_patterns = [
        r'\.\./',  # Directory traversal
        r'(;|:).+',  # Command injection attempts
        r'\.(php|asp|aspx|jsp|cgi).*\?',  # Suspicious parameters
        r'(exec|system|eval|select|union|insert|drop)',  # Code injection attempts
    ]
    return any(re.search(pattern, path, re.I) for pattern in suspicious_patterns)

def check_url_format(url):
    """Enhanced URL format checking."""
    findings = []
    risk_score = 0
    
    try:
        parsed = parse_url(url)
        ext = tldextract.extract(url)
        
        # Check for IP address (including IPv6)
        if re.match(r"https?://\[.*\]", url) or re.match(r"https?://(\d{1,3}\.){3}\d{1,3}", url):
            findings.append("Uses IP address instead of domain name")
            risk_score += 20

        # Check for URL shorteners
        if ext.registered_domain in URL_SHORTENERS:
            findings.append("Uses URL shortening service")
            risk_score += 10

        # Check for user info in URL
        if '@' in url:
            findings.append("Contains user info (@) - potential phishing")
            risk_score += 25

        # Check for excessive subdomains or length
        if url.count('.') > 4:
            findings.append("Excessive number of subdomains")
            risk_score += 15
        if len(url) > 100:
            findings.append("Suspiciously long URL")
            risk_score += 10

        # Check for suspicious encoding
        if re.search(r'%[0-9a-fA-F]{2}', url):
            decoded = urllib.parse.unquote(url)
            if any(char.isascii() and not char.isprintable() for char in decoded):
                findings.append("Contains suspicious encoded characters")
                risk_score += 20

        # Check for homograph attacks using basic pattern
        non_ascii = any(ord(char) > 127 for char in parsed.host)
        if non_ascii:
            findings.append("Contains non-ASCII characters - potential homograph attack")
            risk_score += 30

        # Check for suspicious port numbers
        if parsed.port and parsed.port not in (80, 443, 8080, 8443):
            findings.append(f"Unusual port number: {parsed.port}")
            risk_score += 15

        # Analyze URL path for suspicious patterns
        suspicious_patterns = [
            r'\.\./',  # Directory traversal
            r'(;|:).+',  # Command injection attempts
            r'\.(php|asp|aspx|jsp|cgi).*\?',  # Suspicious parameters
            r'(exec|system|eval|select|union|insert|drop)',  # Code injection attempts
        ]
        if parsed.path and any(re.search(pattern, parsed.path, re.I) for pattern in suspicious_patterns):
            findings.append("Suspicious patterns in URL path")
            risk_score += 20

        # Check for suspicious query parameters
        if parsed.query:
            suspicious_params = ['cmd', 'exec', 'run', 'script', 'password', 'pwd', 'login']
            query_params = urllib.parse.parse_qs(parsed.query)
            if any(param.lower() in suspicious_params for param in query_params):
                findings.append("Suspicious query parameters detected")
                risk_score += 15

    except Exception as e:
        findings.append(f"Malformed URL: {str(e)}")
        risk_score += 30

    return {
        "is_suspicious": risk_score >= 30,
        "risk_score": risk_score,
        "findings": findings
    }

def scan_url_with_virustotal(url, api_key):
	vt_url = "https://www.virustotal.com/api/v3/urls"
	headers = {"x-apikey": api_key}
	url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
	response = requests.get(f"{vt_url}/{url_id}", headers=headers)
	if response.status_code == 200:
		data = response.json()
		stats = data['data']['attributes']['last_analysis_stats']
		malicious = stats.get('malicious', 0)
		suspicious = stats.get('suspicious', 0)
		if malicious > 0:
			return "malicious"
		elif suspicious > 0:
			return "suspicious"
		else:
			return "clean"
	return "unknown"

def analyze_url(url, api_key=None):
    """
    Comprehensive URL analysis combining multiple detection methods.
    Returns a dictionary with detailed analysis results.
    """
    results = {
        "category": "unknown",
        "risk_score": 0,
        "findings": []
    }
    
    # Check URL format and structure
    format_check = check_url_format(url)
    results["findings"].extend(format_check["findings"])
    results["risk_score"] += format_check["risk_score"]
    
    # Check with VirusTotal if API key is provided
    if api_key:
        try:
            vt_result = scan_url_with_virustotal(url, api_key)
            if vt_result == "malicious":
                results["findings"].append("Flagged as malicious by VirusTotal")
                results["risk_score"] += 50
            elif vt_result == "suspicious":
                results["findings"].append("Flagged as suspicious by VirusTotal")
                results["risk_score"] += 25
        except Exception as e:
            results["findings"].append(f"VirusTotal scan failed: {str(e)}")
    
    # Categorize based on risk score
    if results["risk_score"] < 20:
        results["category"] = "clean"
    elif results["risk_score"] >= 50:
        results["category"] = "malicious"
    else:
        results["category"] = "suspicious"
    
    return results
