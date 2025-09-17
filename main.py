import sys
import os
import json
import locale
from email import message_from_file
from analysis.email_header_analysis import analyze_email_header, extract_headers_from_email_file
from analysis.url_analysis import extract_urls_from_body, analyze_url, get_email_body
from analysis.attachement_analysis import extract_attachments, analyze_attachment

# Set UTF-8 encoding for stdout
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        # Python < 3.7
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer)


def calculate_overall_score(header_score, url_score, attachment_score):
    """Calculate overall risk score based on component scores."""
    # Weight the scores (can be adjusted based on importance)
    weights = {
        'header': 0.3,
        'url': 0.35,
        'attachment': 0.35
    }
    
    scores = []
    if header_score is not None:
        scores.append(header_score * weights['header'])
    if url_score is not None:
        scores.append(url_score * weights['url'])
    if attachment_score is not None:
        scores.append(attachment_score * weights['attachment'])
    
    return sum(scores) if scores else 0

def get_category_from_score(score):
    """Convert numerical score to category."""
    if score < 20:
        return "clean"
    elif score < 50:
        return "suspicious"
    else:
        return "malicious"

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <email_file.eml>")
        sys.exit(1)
        
    email_file = sys.argv[1]
    with open(email_file, 'r', encoding='utf-8', errors='replace') as f:
        msg = message_from_file(f)

    results = {
        "header": {},
        "urls": {
            "category": "clean",
            "risk_score": 0,
            "findings": {}
        },
        "attachments": {
            "category": "clean",
            "risk_score": 0,
            "findings": {}
        },
        "overall": {}
    }

    # Header analysis
    header_text = extract_headers_from_email_file(email_file)
    results["header"] = analyze_email_header(header_text)

    # URL analysis
    body = get_email_body(msg)
    urls = extract_urls_from_body(body)
    if urls:
        url_findings = {}
        max_url_score = 0
        for url in urls:
            url_result = analyze_url(url)
            url_findings[url] = url_result["findings"]
            max_url_score = max(max_url_score, url_result["risk_score"])
        
        results["urls"] = {
            "category": get_category_from_score(max_url_score),
            "risk_score": max_url_score,
            "findings": url_findings
        }

    # Attachment analysis
    attachments = extract_attachments(msg)
    if attachments:
        attachment_findings = {}
        max_attachment_score = 0
        for filepath in attachments:
            verdict, findings = analyze_attachment(filepath)
            attachment_findings[filepath] = findings
            # Convert verdict to score
            score = {"clean": 0, "suspicious": 35, "malicious": 75}[verdict]
            max_attachment_score = max(max_attachment_score, score)
        
        results["attachments"] = {
            "category": get_category_from_score(max_attachment_score),
            "risk_score": max_attachment_score,
            "findings": attachment_findings
        }

    # Calculate overall score and verdict
    overall_score = calculate_overall_score(
        results["header"].get("risk_score", 0),
        results["urls"]["risk_score"],
        results["attachments"]["risk_score"]
    )
    
    results["overall"] = {
        "category": get_category_from_score(overall_score),
        "risk_score": round(overall_score, 1)
    }

    # Print results as JSON, ensuring proper encoding
    try:
        # Try to print with UTF-8 encoding
        print(json.dumps(results, ensure_ascii=False))
    except UnicodeEncodeError:
        # Fallback to ASCII-only output if UTF-8 fails
        print(json.dumps(results, ensure_ascii=True))

if __name__ == "__main__":
    main()
