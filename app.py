"""
PhishSentinel - Agentic AI Phishing Email Analyzer
Streamlit Dashboard for analyzing phishing emails using LangGraph agentic system.
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import uuid
import json
import os
from datetime import datetime
from typing import Dict, List, Any

# Import agent modules
from agent.graph import create_analysis_graph, run_analysis
from agent.state import PhishingAnalysisState
from utils.db import save_analysis, get_analysis, get_analysis_history, init_database
from utils.email_parser import parse_raw_email, read_eml_file


# Page configuration
st.set_page_config(
    page_title="PhishSentinel - AI Phishing Analyzer",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "Get help": None,
        "Report a bug": None,
        "About": None,
    },
)


# Custom CSS - Enhanced Aesthetic Design
st.markdown(
    """
<style>
    /* Import Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    /* Main App Styles */
    .stApp {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    }
    
    /* Font Family */
    * {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    /* Main Header */
    .main-header {
        font-size: 2.8rem;
        font-weight: 700;
        background: linear-gradient(90deg, #60a5fa, #a78bfa, #f472b6);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        text-align: center;
        margin-bottom: 0.5rem;
        letter-spacing: -0.02em;
    }
    
    .sub-header {
        font-size: 1rem;
        color: #94a3b8;
        text-align: center;
        margin-bottom: 1.5rem;
        font-weight: 400;
    }
    
    /* Threat Level Colors */
    .threat-safe { 
        color: #22c55e; 
        background: linear-gradient(135deg, #22c55e20, #22c55e10);
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
    }
    .threat-suspicious { 
        color: #eab308; 
        background: linear-gradient(135deg, #eab30820, #eab30810);
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
    }
    .threat-likely { 
        color: #f97316; 
        background: linear-gradient(135deg, #f9731620, #f9731610);
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
    }
    .threat-critical { 
        color: #ef4444; 
        background: linear-gradient(135deg, #ef444420, #ef444410);
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
    }
    
    /* Metric Cards */
    .metric-card {
        background: linear-gradient(145deg, #1e293b, #334155);
        padding: 1.25rem;
        border-radius: 1rem;
        text-align: center;
        border: 1px solid #475569;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 12px -2px rgba(0, 0, 0, 0.4);
    }
    
    /* Sidebar */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0f172a 0%, #1e293b 100%);
        border-right: 1px solid #334155;
    }
    
    .sidebar-title {
        font-size: 1.75rem;
        font-weight: 700;
        background: linear-gradient(90deg, #60a5fa, #a78bfa);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }
    
    /* IOC Badges */
    .ioc-badge {
        display: inline-block;
        padding: 0.35rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.8rem;
        font-weight: 600;
        letter-spacing: 0.025em;
    }
    .ioc-high { 
        background: linear-gradient(135deg, #fee2e2, #fecaca); 
        color: #dc2626; 
    }
    .ioc-medium { 
        background: linear-gradient(135deg, #fef3c7, #fde68a); 
        color: #d97706; 
    }
    .ioc-low { 
        background: linear-gradient(135deg, #d1fae5, #a7f3d0); 
        color: #059669; 
    }
    
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 0.5rem;
    }
    .stTabs [data-baseweb="tab"] {
        background: #1e293b;
        border-radius: 0.5rem 0.5rem 0 0;
        padding: 0.75rem 1.25rem;
        border: 1px solid #334155;
        border-bottom: none;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(180deg, #3b82f6, #2563eb);
        border-color: #3b82f6;
    }
    
    /* Buttons */
    button[kind="primary"] {
        background: linear-gradient(135deg, #3b82f6, #8b5cf6);
        border: none;
        border-radius: 0.75rem;
        padding: 0.75rem 1.5rem;
        font-weight: 600;
        transition: all 0.2s ease;
    }
    button[kind="primary"]:hover {
        background: linear-gradient(135deg, #2563ec, #7c3aed);
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
    }
    
    /* Expanders */
    .streamlit-expanderHeader {
        background: linear-gradient(135deg, #1e293b, #334155);
        border-radius: 0.75rem;
        border: 1px solid #475569;
        color: #e2e8f0;
    }
    
    /* DataFrame */
    [data-testid="stDataFrame"] {
        border-radius: 0.75rem;
        border: 1px solid #475569;
    }
    
    /* Input Fields */
    .stTextInput > div > div > input {
        background: #1e293b;
        border: 1px solid #475569;
        border-radius: 0.5rem;
        color: #e2e8f0;
    }
    .stTextInput > div > div > input:focus {
        border-color: #3b82f6;
        box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
    }
    
    /* Text Area */
    .stTextArea > div > div > textarea {
        background: #1e293b;
        border: 1px solid #475569;
        border-radius: 0.5rem;
        color: #e2e8f0;
    }
    
    /* Radio Buttons */
    .stRadio > div {
        background: #1e293b;
        padding: 0.75rem;
        border-radius: 0.5rem;
        border: 1px solid #475569;
    }
    
    /* Success/Error/Info Messages */
    .stSuccess {
        background: linear-gradient(135deg, #22c55e20, #16a34a20);
        border: 1px solid #22c55e;
        border-radius: 0.5rem;
    }
    .stError {
        background: linear-gradient(135deg, #ef444420, #dc262620);
        border: 1px solid #ef4444;
        border-radius: 0.5rem;
    }
    .stInfo {
        background: linear-gradient(135deg, #3b82f620, #2563eb20);
        border: 1px solid #3b82f6;
        border-radius: 0.5rem;
    }
    
    /* Spinner */
    .stSpinner > div {
        border-color: #3b82f6 transparent transparent;
    }
    
    /* Hide default Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Custom scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    ::-webkit-scrollbar-track {
        background: #1e293b;
    }
    ::-webkit-scrollbar-thumb {
        background: #475569;
        border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: #64748b;
    }
    
    /* Card container */
    .css-card {
        background: linear-gradient(145deg, #1e293b, #334155);
        border-radius: 1rem;
        padding: 1.5rem;
        border: 1px solid #475569;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
    }
    
    /* Section headers */
    h2, h3 {
        color: #f1f5f9;
        font-weight: 600;
    }
    
    /* Paragraph text */
    p, li {
        color: #cbd5e1;
    }
    
    /* Code blocks */
    code {
        background: #0f172a;
        color: #a78bfa;
        padding: 0.2rem 0.4rem;
        border-radius: 0.25rem;
    }
</style>
""",
    unsafe_allow_html=True,
)


def init_session_state():
    """Initialize session state variables."""
    if "analysis_result" not in st.session_state:
        st.session_state.analysis_result = None
    if "analysis_history" not in st.session_state:
        st.session_state.analysis_history = []
    if "api_key" not in st.session_state:
        st.session_state.api_key = ""


def render_sidebar():
    """Render the sidebar with input options."""
    with st.sidebar:
        st.markdown(
            '<p class="sidebar-title">🕵️ PhishSentinel</p>', unsafe_allow_html=True
        )
        st.markdown("---")

        # API Key input
        api_key = st.text_input(
            "OpenAI API Key",
            type="password",
            value=st.session_state.api_key,
            help="Enter your OpenAI API key to enable AI analysis",
        )
        if api_key:
            st.session_state.api_key = api_key
            os.environ["OPENAI_API_KEY"] = api_key

        st.markdown("---")

        # Input mode
        input_mode = st.radio(
            "Input Mode", ["Paste Email Text", "Upload .eml File"], horizontal=True
        )

        st.markdown("---")

        # Analyze button
        analyze_btn = st.button(
            "🔍 Analyze Email",
            type="primary",
            width="stretch",
            disabled=not api_key,
        )

        st.markdown("---")

        # History link
        st.markdown("📜 **[Analysis History](#history-tab)**")

        return input_mode, analyze_btn


def get_email_content(input_mode: str) -> str:
    """Get email content based on input mode."""
    if input_mode == "Paste Email Text":
        email_text = st.text_area(
            "Paste Email Content",
            height=300,
            placeholder="Paste raw email content here (headers + body)...",
        )
        return email_text
    else:
        uploaded_file = st.file_uploader(
            "Upload .eml file",
            type=["eml", "txt"],
            help="Upload a .eml file to analyze",
        )
        if uploaded_file:
            try:
                content = uploaded_file.getvalue().decode("utf-8", errors="ignore")
                return content
            except Exception as e:
                st.error(f"Error reading file: {e}")
                return ""
        return ""


def render_threat_gauge(score: int) -> go.Figure:
    """Render threat score gauge chart."""
    # Determine color based on score
    if score <= 20:
        color = "#22c55e"  # Green
    elif score <= 45:
        color = "#eab308"  # Yellow
    elif score <= 74:
        color = "#f97316"  # Orange
    else:
        color = "#ef4444"  # Red

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            domain={"x": [0, 1], "y": [0, 1]},
            title={
                "text": f"<b>Threat Score</b><br><span style='font-size:0.8em;color:#94a3b8'>{score}/100</span>",
                "font": {"size": 20, "color": "#f1f5f9"},
            },
            number={
                "font": {"size": 48, "color": color, "family": "Inter"},
                "prefix": "",
                "suffix": "",
            },
            gauge={
                "axis": {
                    "range": [0, 100],
                    "tickwidth": 1,
                    "tickcolor": "#475569",
                    "showticklabels": True,
                    "tickfont": {"color": "#94a3b8"},
                },
                "bar": {"color": color, "thickness": 0.8},
                "bgcolor": "#1e293b",
                "borderwidth": 2,
                "bordercolor": "#475569",
                "steps": [
                    {"range": [0, 20], "color": "rgba(34, 197, 94, 0.15)"},
                    {"range": [20, 45], "color": "rgba(234, 179, 8, 0.15)"},
                    {"range": [45, 74], "color": "rgba(249, 115, 22, 0.15)"},
                    {"range": [74, 100], "color": "rgba(239, 68, 68, 0.15)"},
                ],
                "threshold": {
                    "line": {"color": "white", "width": 3},
                    "thickness": 0.85,
                    "value": score,
                },
            },
        )
    )

    fig.update_layout(
        height=280,
        margin=dict(l=30, r=30, t=60, b=30),
        paper_bgcolor="#0f172a",
        font={"color": "#f1f5f9", "family": "Inter"},
    )

    return fig


def render_radar_chart(indicator_results: Dict[str, int]) -> go.Figure:
    """Render radar chart for indicator scores."""
    # Map indicator keys to readable names
    indicator_names = {
        "spf_check": "SPF",
        "dkim_check": "DKIM",
        "dmarc_check": "DMARC",
        "reply_to_mismatch": "Reply-To Mismatch",
        "return_path_mismatch": "Return-Path Mismatch",
        "suspicious_received_chain": "Received Chain",
        "message_id_anomaly": "Message-ID Anomaly",
        "urgency_signals": "Urgency Signals",
        "credential_harvesting_cues": "Credential Harvesting",
        "impersonation_signals": "Impersonation",
        "suspicious_links": "Suspicious Links",
        "homoglyph_domains": "Homoglyph Domains",
    }

    # Extract scores
    categories = []
    scores = []

    for key, name in indicator_names.items():
        if key in indicator_results:
            categories.append(name)
            scores.append(indicator_results[key])

    # Close the polygon
    categories = categories + [categories[0]]
    scores = scores + [scores[0]]

    fig = go.Figure()

    fig.add_trace(
        go.Scatterpolar(
            r=scores,
            theta=categories,
            fill="toself",
            name="Indicator Scores",
            fillcolor="rgba(139, 92, 246, 0.35)",
            line=dict(color="rgba(139, 92, 246, 0.9)", width=2),
        )
    )

    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 10],
                showticklabels=True,
                tickfont={"color": "#94a3b8"},
                gridcolor="#334155",
                linecolor="#475569",
                angle=0,
            ),
            bgcolor="#1e293b",
        ),
        showlegend=False,
        height=320,
        margin=dict(l=40, r=40, t=40, b=40),
        paper_bgcolor="#0f172a",
        font={"color": "#f1f5f9", "family": "Inter"},
    )

    return fig


def render_ioc_chart(ioc_list: List[Dict]) -> go.Figure:
    """Render bar chart for IOC counts by type."""
    if not ioc_list:
        return None

    # Count IOCs by type
    type_counts = {}
    for ioc in ioc_list:
        ioc_type = ioc.get("type", "unknown")
        type_counts[ioc_type] = type_counts.get(ioc_type, 0) + 1

    df = pd.DataFrame(list(type_counts.items()), columns=["Type", "Count"])

    fig = px.bar(
        df,
        x="Type",
        y="Count",
        color="Type",
        title="<b>IOC Count by Type</b>",
        color_discrete_sequence=[
            "#3b82f6",
            "#8b5cf6",
            "#ec4899",
            "#f59e0b",
            "#22c55e",
            "#ef4444",
        ],
        text_auto=True,
    )

    fig.update_layout(
        height=300,
        showlegend=False,
        paper_bgcolor="#0f172a",
        plot_bgcolor="#1e293b",
        font={"color": "#f1f5f9", "family": "Inter"},
        title_font={"size": 18, "color": "#f1f5f9"},
        xaxis=dict(
            gridcolor="#334155",
            linecolor="#475569",
            tickfont={"color": "#94a3b8"},
        ),
        yaxis=dict(
            gridcolor="#334155",
            linecolor="#475569",
            tickfont={"color": "#94a3b8"},
        ),
    )

    return fig


def render_analysis_tab(result: Dict[str, Any]):
    """Render the Analysis tab."""
    if not result:
        st.info("👈 Enter an email and click 'Analyze Email' to begin analysis.")
        return

    # Get data from result
    threat_score = result.get("threat_score", 0)
    threat_level = result.get("threat_level", "Unknown")
    indicator_results = result.get("indicator_results", {})
    ioc_list = result.get("ioc_list", [])
    parsed_headers = result.get("parsed_headers", {})
    summary_report = result.get("summary_report", "")

    # Get SPF, DKIM, DMARC status
    spf_status = "Unknown"
    dkim_status = "Unknown"
    if parsed_headers.get("Authentication-Results"):
        auth_results = parsed_headers.get("auth_results", {})
        spf_status = auth_results.get("spf", "unknown").upper()
        dkim_status = auth_results.get("dkim", "unknown").upper()

    # Top row: Gauge and metrics
    col1, col2 = st.columns([2, 1])

    with col1:
        # Threat gauge
        fig_gauge = render_threat_gauge(threat_score)
        st.plotly_chart(fig_gauge, width="stretch")

    with col2:
        # Metric cards
        st.metric("Threat Level", threat_level)
        st.metric("SPF Status", spf_status)
        st.metric("DKIM Status", dkim_status)
        st.metric("Total IOCs", len(ioc_list))

    # Radar chart
    st.subheader("📊 Indicator Analysis")
    fig_radar = render_radar_chart(indicator_results)
    st.plotly_chart(fig_radar, width="stretch")

    # Full report expander
    with st.expander("📋 Full Analyst Report"):
        st.markdown(summary_report)

    # Raw headers expander
    with st.expander("🔍 Raw Parsed Headers"):
        st.json(parsed_headers)


def render_ioc_tab(result: Dict[str, Any]):
    """Render the IOC Report tab."""
    if not result:
        st.info("👈 Enter an email and click 'Analyze Email' to begin analysis.")
        return

    ioc_list = result.get("ioc_list", [])

    if not ioc_list:
        st.info("No IOCs detected in this email.")
        return

    # Create DataFrame
    df = pd.DataFrame(ioc_list)

    # Display dataframe
    st.dataframe(
        df,
        width="stretch",
        column_config={
            "type": st.column_config.TextColumn("Type"),
            "value": st.column_config.TextColumn("Value"),
            "context": st.column_config.TextColumn("Context"),
            "severity": st.column_config.TextColumn(
                "Severity", help="Severity level of the IOC"
            ),
        },
    )

    # Download button
    csv = df.to_csv(index=False)
    st.download_button(
        label="📥 Download IOCs as CSV",
        data=csv,
        file_name="phishsentinel_iocs.csv",
        mime="text/csv",
    )

    # Bar chart
    fig = render_ioc_chart(ioc_list)
    if fig:
        st.plotly_chart(fig, width="stretch")


def render_history_tab():
    """Render the History tab."""
    st.subheader("📜 Analysis History")

    # Load history
    history = get_analysis_history(20)

    if not history:
        st.info("No analysis history found. Analyze some emails to see them here!")
        return

    # Create DataFrame
    df = pd.DataFrame(history)

    # Format timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M")

    # Display
    st.dataframe(
        df[["timestamp", "threat_score", "threat_level", "sender_email", "subject"]],
        width="stretch",
        hide_index=True,
    )

    # Show selection to reload
    st.markdown("---")
    st.markdown("### Load Previous Analysis")

    selected_id = st.selectbox(
        "Select an analysis to view",
        options=[h["id"] for h in history],
        format_func=lambda x: f"{x[:8]}... - {next((h['threat_level'] for h in history if h['id'] == x), '')}",
    )

    if selected_id:
        analysis = get_analysis(selected_id)
        if analysis:
            raw_json = analysis.get("raw_json", "{}")
            try:
                result = json.loads(raw_json)
                st.session_state.analysis_result = result
                st.success("Analysis loaded! Switch to Analysis tab to view.")
            except:
                st.error("Could not load analysis details.")


def main():
    """Main application entry point."""
    # Initialize
    init_database()
    init_session_state()

    # Header
    st.markdown(
        '<p class="main-header">🕵️ PhishSentinel</p>\n        <p class="sub-header">Agentic AI Phishing Email Analyzer • Powered by LangGraph & GPT-4o</p>',
        unsafe_allow_html=True,
    )
    st.markdown("---")

    # Sidebar
    input_mode, analyze_btn = render_sidebar()

    # Main content
    email_content = get_email_content(input_mode)

    # Process analysis
    if analyze_btn and email_content:
        with st.spinner("🔍 Agent analyzing email..."):
            try:
                # Create analysis ID
                analysis_id = str(uuid.uuid4())

                # Run analysis
                result = run_analysis(
                    raw_email=email_content,
                    analysis_id=analysis_id,
                )

                # Save to database
                if result:
                    save_analysis(
                        analysis_id=analysis_id,
                        threat_score=result.get("threat_score", 0),
                        threat_level=result.get("threat_level", "Unknown"),
                        summary=result.get("summary_report", ""),
                        raw_state=result,
                        sender_email=result.get("sender_email"),
                        subject=result.get("subject"),
                    )

                    st.session_state.analysis_result = result
                    st.success("✅ Analysis complete!")
                else:
                    st.error(
                        "Analysis failed. Please check your API key and try again."
                    )

            except Exception as e:
                st.error(f"Error during analysis: {str(e)}")

    # Tabs
    tab1, tab2, tab3 = st.tabs(["📊 Analysis", "🎯 IOC Report", "📜 History"])

    with tab1:
        render_analysis_tab(st.session_state.analysis_result)

    with tab2:
        render_ioc_tab(st.session_state.analysis_result)

    with tab3:
        render_history_tab()


if __name__ == "__main__":
    main()
