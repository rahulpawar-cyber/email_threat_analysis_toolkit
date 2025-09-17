import os
import sys
import hashlib
import re
import math
import mimetypes
from email import message_from_file
from email.header import decode_header, make_header
from datetime import datetime

# Initialize mimetypes
mimetypes.init()

# File signatures (magic numbers) for common file types
FILE_SIGNATURES = {
    b'MZ': 'executable',  # Windows executable
    b'%PDF': 'pdf',      # PDF document
    b'PK\x03\x04': 'zip',  # ZIP archive or Office document
    b'\x7F\x45\x4C\x46': 'elf',  # Linux executable
    b'\xFF\xD8\xFF': 'jpeg',   # JPEG image
    b'\x89PNG': 'png',    # PNG image
    b'GIF87a': 'gif',     # GIF image
    b'GIF89a': 'gif',     # GIF image
    b'<?xml': 'xml',      # XML document
    b'{\\rtf': 'rtf',     # RTF document
    b'%!PS': 'ps',        # PostScript
    b'\xD0\xCF\x11\xE0': 'ole'  # OLE document (old Office)
}

def extract_attachments(msg, save_dir="attachments"):
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)
    attachments = []
    for part in msg.walk():
        content_disposition = part.get("Content-Disposition", None)
        if content_disposition and 'attachment' in content_disposition.lower():
            filename = part.get_filename()
            if filename:
                filename = str(make_header(decode_header(filename)))
                filepath = os.path.join(save_dir, filename)
                with open(filepath, 'wb') as f:
                    f.write(part.get_payload(decode=True))
                attachments.append(filepath)
    return attachments

def get_file_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def check_file_extension(filepath):
    suspicious_exts = [
        # Executables
        '.exe', '.dll', '.com', '.bat', '.cmd', '.msi', '.scr',
        # Scripts
        '.js', '.vbs', '.ps1', '.wsf', '.hta', '.jse', '.vbe', '.wsh',
        # System
        '.sys', '.cpl', '.msc', '.pif', '.gadget',
        # Java
        '.jar', '.jnlp',
        # Office with macros
        '.docm', '.xlsm', '.pptm'
    ]
    _, ext = os.path.splitext(filepath)
    return ext.lower() in suspicious_exts

def check_double_extension(filename):
    parts = filename.lower().split('.')
    suspicious_exts = ['exe', 'js', 'vbs', 'bat', 'cmd', 'ps1', 'wsf', 'hta', 'msi']
    return len(parts) > 2 and parts[-1] in suspicious_exts

def calculate_entropy(data):
    """Calculate Shannon entropy of a file's contents."""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

def detect_file_type(filepath, content):
    """Detect file type using signatures and extension."""
    # Check file signatures
    for signature, file_type in FILE_SIGNATURES.items():
        if content.startswith(signature):
            return file_type
            
    # Fallback to extension-based detection
    ext = os.path.splitext(filepath)[1].lower().lstrip('.')
    if ext:
        return ext
    return 'unknown'

def check_office_document(content):
    """Check if content is a potentially malicious Office document."""
    if content.startswith(b'PK\x03\x04'):  # Modern Office file
        # Look for indicators of macros or external content
        indicators = [b'vbaProject.bin', b'_VBA_PROJECT_CUR', 
                     b'word/vbaData.xml', b'xl/vbaProject.bin']
        return any(ind in content for ind in indicators)
    return False

def check_file_content(filepath):
    """Check file contents for suspicious characteristics."""
    findings = []
    try:
        with open(filepath, 'rb') as f:
            content = f.read(1024 * 1024)  # Read first MB for initial checks
            
        # Check file size
        size = os.path.getsize(filepath)
        if size < 1024 and check_file_extension(filepath):  # Suspicious if executable < 1KB
            findings.append("Unusually small executable")
        if size > 10 * 1024 * 1024:  # Flag files > 10MB
            findings.append("Very large attachment")

        # Check entropy of first MB
        entropy = calculate_entropy(content)
        if entropy > 7.5:  # High entropy might indicate encryption/packing
            findings.append("High entropy - possible packed/encrypted content")

        # Detect file type
        detected_type = detect_file_type(filepath, content)
        declared_ext = os.path.splitext(filepath)[1].lower().lstrip('.')
        
        # Check for type mismatches
        if detected_type != 'unknown' and detected_type != declared_ext:
            findings.append(f"File type mismatch: detected {detected_type}, declared {declared_ext}")

        # Check for dangerous content types
        if detected_type in ['executable', 'elf']:
            findings.append("Contains executable code")
        elif detected_type == 'ole' or check_office_document(content):
            findings.append("Office document with potential macros")

        # Check for script content
        script_patterns = [
            b'javascript:', b'vbscript:', b'<script', 
            b'function()', b'eval(', b'exec(',
            b'ActiveXObject', b'WScript.Shell'
        ]
        if any(pattern in content.lower() for pattern in script_patterns):
            findings.append("Contains script code")

        # Check timestamps
        stat = os.stat(filepath)
        created = datetime.fromtimestamp(stat.st_ctime)
        modified = datetime.fromtimestamp(stat.st_mtime)
        if abs((created - modified).days) > 365:
            findings.append("Suspicious timestamp difference")

    except Exception as e:
        findings.append(f"Error analyzing content: {str(e)}")

    return findings

def analyze_attachment(filepath):
    """Analyze attachment for suspicious/malicious characteristics."""
    findings = []
    filename = os.path.basename(filepath)
    
    # Basic checks
    if check_file_extension(filepath):
        findings.append("Suspicious file extension")
    if check_double_extension(filename):
        findings.append("Double extension detected")
    
    # Content analysis
    content_findings = check_file_content(filepath)
    findings.extend(content_findings)
    
    # Determine verdict
    if len(findings) >= 2:
        return "malicious", findings
    elif len(findings) == 1:
        return "suspicious", findings
    return "clean", []

def main(filepath):
    verdict, findings = analyze_attachment(filepath)
    print(f"\nVerdict: {verdict.upper()}")
    if findings:
        print("\nFindings:")
        for finding in findings:
            print(f"- {finding}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python attachment_analysis.py <file_path>")
        sys.exit(1)
    main(sys.argv[1])