# email_threat_analysis_toolkit
A toolkit with web UI for analyzing .eml files, detecting suspicious headers, malicious URLs, and harmful attachments using advanced security checks.
=======

# Email Threat Analysis Toolkit

This project provides a sophisticated toolkit and web UI for analyzing `.eml` email files for threats, including suspicious headers, malicious URLs, and dangerous attachments. It uses advanced detection techniques and multiple security checks for comprehensive threat analysis.

## Features
- **Advanced Header Analysis**: 
  - SPF, DKIM, DMARC, and ARC authentication validation
  - Received chain temporal analysis
  - Return-Path verification
  - Message-ID validation
  - Risk scoring system

- **Enhanced URL Detection**:
  - Homograph attack detection
  - Typosquatting detection
  - SSL certificate validation
  - Domain reputation checking
  - Path traversal detection
  - URL shortener detection
  - Command injection pattern detection

- **Comprehensive Attachment Analysis**:
  - Advanced file type detection
  - Content analysis
  - Entropy calculation
  - MIME type validation
  - Metadata analysis
  - Timestamp verification

- **Risk Assessment**:
  - Numerical risk scoring for all components
  - Detailed findings and explanations
  - Multiple security check layers
  - Comprehensive verdict system

- **Modern Interface**:
  - Streamlit web UI with instant analysis
  - Color-coded risk indicators
  - Detailed findings breakdown
  - Progress tracking
  - Interactive result display

## File Structure
```
main.py                      # Main pipeline: runs all analysis and prints verdicts
streamlit_app.py             # Streamlit web UI for interactive analysis
analysis/
	email_header_analysis.py     # Header analysis logic
	url_analysis.py              # URL analysis logic
	attachement_analysis.py      # Attachment analysis logic
	__init__.py                  # (empty, marks as package)
demo.eml                     # Sample email for testing
attachments/                 # Extracted attachments (auto-created)
```

## Usage

### 1. Web UI (Recommended)
Launch the Streamlit app:
```
streamlit run streamlit_app.py
```
Upload a `.eml` file and view the results in your browser.

### 2. Command Line
Analyze an email file and print verdicts:
```
python main.py demo.eml
```

## Requirements
- Python 3.7+
- Required libraries (install with `pip install -r requirements.txt`):
  - `requests`: For API interactions
  - `streamlit`: For web interface
  - `tldextract`: For domain analysis
  - `urllib3`: For URL parsing
  - `python-magic`: For file type detection
  - `ssdeep`: For fuzzy hashing (optional)

## Notes
- Attachments are extracted to the `attachments/` folder
- The sample `demo.eml` file is provided for testing
- All analysis modules are independent and can be extended
- Risk scoring system is customizable
- SSL certificate validation requires internet access
- Domain reputation checking uses multiple sources
- URL analysis supports IPv6 addresses
