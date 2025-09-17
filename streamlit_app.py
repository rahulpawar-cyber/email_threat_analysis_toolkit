import streamlit as st
import os
import json
import tempfile
import subprocess
import time
from datetime import datetime

# Page configuration
st.set_page_config(
    page_title="Email Threat Analysis Toolkit",
    page_icon="📧",
    layout="centered",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .risk-meter { margin: 1em 0; padding: 1em; border-radius: 5px; }
    .finding-box { background: #f8f9fa; padding: 1em; border-radius: 5px; margin: 0.5em 0; }
    .component-title { font-size: 1.2em; font-weight: bold; margin: 1em 0; }
    .risk-score { font-size: 2em; font-weight: bold; text-align: center; }
    .risk-label { font-size: 1.2em; text-align: center; margin-top: 0.5em; }
    
    /* Findings styling */
    .findings-container {
        max-height: none !important;
        overflow: visible !important;
    }
    .findings-table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 1em;
    }
    .findings-row {
        border-bottom: 1px solid #eee;
        padding: 0.75em 0;
        margin: 0.5em 0;
    }
    .findings-header {
        font-weight: bold;
        color: #444;
        font-size: 1.1em;
        padding: 0.5em 0;
        border-bottom: 2px solid #ddd;
    }
    .url-finding {
        background: #f8f9fa;
        padding: 1em;
        border-radius: 5px;
        margin: 0.75em 0;
        border-left: 3px solid #0366d6;
    }
    .attachment-finding {
        background: #f8f9fa;
        padding: 1em;
        border-radius: 5px;
        margin: 0.75em 0;
        border-left: 3px solid #28a745;
    }
    .finding-item {
        padding: 0.5em;
        margin: 0.25em 0;
        background: white;
        border-radius: 4px;
        border: 1px solid #eee;
    }
    div[data-testid="stExpander"] {
        border: none !important;
        box-shadow: none !important;
    }
</style>
""", unsafe_allow_html=True)

# Title and description
st.markdown("""
<div style='display: flex; align-items: center; justify-content: center; margin-bottom: 1em;'>
    <img src='https://img.icons8.com/ios-filled/50/000000/new-post.png' width='40' style='margin-right: 12px;'>
    <span style='font-size: 2.2rem; font-weight: bold; color: #111;'>Email Threat Analysis Toolkit</span>
</div>
<p style='text-align: center; color: #666;'>Advanced email analysis for detecting sophisticated threats in headers, URLs, and attachments.</p>
""", unsafe_allow_html=True)

# Sidebar with info
with st.sidebar:
    st.markdown("### About")
    st.markdown("""
    This toolkit uses advanced detection techniques:
    
    🔍 **Header Analysis**
    - SPF, DKIM, DMARC verification
    - Received chain analysis
    - Message-ID validation
    
    🌐 **URL Analysis**
    - Homograph attack detection
    - SSL certificate validation
    - Domain reputation check
    
    📎 **Attachment Analysis**
    - Deep file inspection
    - Content analysis
    - Entropy calculation
    """)
    
    st.markdown("### Risk Score Legend")
    st.markdown("""
    - 0-20: Clean ✅
    - 21-50: Suspicious ⚠️
    - 51+: Malicious ❌
    """)



uploaded_file = st.file_uploader("Choose an .eml email file", type=["eml"])

if uploaded_file is not None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name

    st.info("File uploaded. Ready to scan!")
    if st.button("🚀 Start Analysis"):

        progress_placeholder = st.empty()
        progress_bar = st.progress(0)

        # Simulate progress with percent, updating in place
        for percent_complete in range(0, 100, 13):
            time.sleep(0.12)
            progress_bar.progress(percent_complete)
            progress_placeholder.markdown(f"<b>Processing email... <span id='percent'>{percent_complete}%</span></b>", unsafe_allow_html=True)
        # Ensure 100% is shown before analysis complete
        progress_bar.progress(100)
        progress_placeholder.markdown(f"<b>Processing email... <span id='percent'>100%</span></b>", unsafe_allow_html=True)

        # Run main.py with the uploaded file
        with st.spinner("Running deep analysis..."):
            result = subprocess.run([
                "python", "main.py", tmp_path
            ], capture_output=True, text=True)

        st.success("Analysis Complete!")

        try:
            # Parse the output as JSON
            analysis_results = json.loads(result.stdout)
            
            # Display overall result first
            overall_color = "#21ba45" if analysis_results["overall"]["category"] == "clean" else (
                "#fbbd08" if analysis_results["overall"]["category"] == "suspicious" else "#db2828"
            )
            
            st.markdown(
                f"""
                <div style='text-align: center; padding: 1em; background: {overall_color}20; border-radius: 10px;'>
                    <h2 style='color: {overall_color}'>OVERALL: {analysis_results["overall"]["category"].upper()}</h2>
                    <div class='risk-score'>{analysis_results["overall"]["risk_score"]}</div>
                    <div class='risk-label'>Risk Score</div>
                </div>
                """,
                unsafe_allow_html=True
            )

            # Create three columns for the components
            col1, col2, col3 = st.columns(3)

            # Header Analysis
            with col1:
                header = analysis_results["header"]
                color = "#21ba45" if header["category"] == "clean" else (
                    "#fbbd08" if header["category"] == "suspicious" else "#db2828"
                )
                st.markdown(
                    f"""
                    <div class='component-title'>📧 Header Analysis</div>
                    <div style='background: {color}20; padding: 1em; border-radius: 5px;'>
                        <div style='color: {color}; font-weight: bold;'>{header["category"].upper()}</div>
                        <div>Risk Score: {header["risk_score"]}</div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            # URL Analysis
            with col2:
                urls = analysis_results["urls"]
                color = "#21ba45" if urls["category"] == "clean" else (
                    "#fbbd08" if urls["category"] == "suspicious" else "#db2828"
                )
                st.markdown(
                    f"""
                    <div class='component-title'>🌐 URL Analysis</div>
                    <div style='background: {color}20; padding: 1em; border-radius: 5px;'>
                        <div style='color: {color}; font-weight: bold;'>{urls["category"].upper()}</div>
                        <div>Risk Score: {urls["risk_score"]}</div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
                # URLs section removed

            # Attachment Analysis
            with col3:
                attachments = analysis_results["attachments"]
                color = "#21ba45" if attachments["category"] == "clean" else (
                    "#fbbd08" if attachments["category"] == "suspicious" else "#db2828"
                )
                st.markdown(
                    f"""
                    <div class='component-title'>📎 Attachment Analysis</div>
                    <div style='background: {color}20; padding: 1em; border-radius: 5px;'>
                        <div style='color: {color}; font-weight: bold;'>{attachments["category"].upper()}</div>
                        <div>Risk Score: {attachments["risk_score"]}</div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
                # Attachments section removed

            # Additional details in expandable sections
            with st.expander("📊 Detailed Analysis"):
                st.markdown("### 🔍 Complete Analysis Details")
                
                # Header Details
                st.markdown("#### 📧 Header Analysis")
                st.markdown(f"""
                * **Category:** {analysis_results['header']['category'].upper()}
                * **Risk Score:** {analysis_results['header']['risk_score']}
                """)
                if analysis_results['header'].get('findings'):
                    st.markdown("**Key Findings:**")
                    for finding in analysis_results['header']['findings']:
                        st.markdown(f"- {finding}")
                st.markdown("---")

                # URL Details
                st.markdown("#### 🌐 URL Analysis")
                st.markdown(f"""
                * **Category:** {analysis_results['urls']['category'].upper()}
                * **Risk Score:** {analysis_results['urls']['risk_score']}
                """)
                if analysis_results['urls'].get('findings'):
                    st.markdown("**Analyzed URLs:**")
                    for url, findings in analysis_results['urls']['findings'].items():
                        st.markdown(f"**URL:** `{url}`")
                        if findings:
                            for finding in findings:
                                st.markdown(f"- {finding}")
                        st.markdown("")
                st.markdown("---")

                # Attachment Details
                st.markdown("#### 📎 Attachment Analysis")
                st.markdown(f"""
                * **Category:** {analysis_results['attachments']['category'].upper()}
                * **Risk Score:** {analysis_results['attachments']['risk_score']}
                """)
                if analysis_results['attachments'].get('findings'):
                    st.markdown("**Analyzed Attachments:**")
                    for attachment, findings in analysis_results['attachments']['findings'].items():
                        st.markdown(f"**File:** `{os.path.basename(attachment)}`")
                        if findings:
                            for finding in findings:
                                st.markdown(f"- {finding}")
                        st.markdown("")
                st.markdown("---")

                # Overall Summary
                st.markdown("#### 📊 Overall Summary")
                st.markdown(f"""
                * **Final Verdict:** {analysis_results['overall']['category'].upper()}
                * **Total Risk Score:** {analysis_results['overall']['risk_score']}
                """)

            # Timestamp
            st.markdown(
                f"""
                <div style='text-align: right; color: #666; font-size: 0.8em; margin-top: 2em;'>
                    Analysis completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </div>
                """,
                unsafe_allow_html=True
            )

        except json.JSONDecodeError:
            # Fallback to old format if JSON parsing fails
            st.warning("Using legacy output format")
            for line in result.stdout.splitlines():
                st.text(line)

        if result.stderr:
            st.error(result.stderr)

        os.remove(tmp_path)
else:
    st.info("Please upload a .eml file to begin analysis.")
