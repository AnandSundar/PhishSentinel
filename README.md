# 🕵️ PhishSentinel - Agentic AI Phishing Email Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/Threat%20Score-0-green?style=for-the-badge&label=0-20" alt="Safe">
  <img src="https://img.shields.io/badge/Threat%20Score-45-yellow?style=for-the-badge&label=21-45" alt="Suspicious">
  <img src="https://img.shields.io/badge/Threat%20Score-74-orange?style=for-the-badge&label=46-74" alt="Likely Phishing">
  <img src="https://img.shields.io/badge/Threat%20Score-100-red?style=for-the-badge&label=75-100" alt="Critical">
</p>

PhishSentinel is an Agentic AI Phishing Email Analyzer powered by LangGraph and OpenAI GPT-4o. It provides autonomous multi-agent analysis of emails to detect phishing attempts, extract IOCs (Indicators of Compromise), and generate comprehensive threat reports.

## 🚀 Features

- **🤖 Agentic AI Analysis**: Multi-node LangGraph agent with specialized analysis nodes
- **📊 12 Phishing Indicators**: Comprehensive detection across headers and body
- **🎯 IOC Extraction**: Automatically extract URLs, IPs, domains, and file hashes
- **📈 Interactive Dashboard**: Plotly visualizations with gauge, radar, and bar charts
- **💾 Analysis History**: SQLite-backed storage for tracking past analyses
- **🔒 Homoglyph Detection**: Detect Unicode lookalike characters in domains
- **📧 EML Support**: Parse both raw email text and .eml file uploads

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        PhishSentinel                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐    ┌──────────────┐    ┌─────────────────────┐ │
│  │  Input   │───▶│ parse_email  │───▶│ header_analysis     │ │
│  │ (email)  │    │    _node     │    │      _node           │ │
│  └──────────┘    └──────────────┘    └──────────┬──────────┘ │
│                                                    │             │
│                      ┌─────────────────────────────┼─────────────┤
│                      │                             │             │
│                      ▼                             ▼             │
│            ┌──────────────────┐         ┌───────────────────┐  │
│            │  IOC extraction   │◀────────│ body_analysis    │  │
│            │      _node        │         │      _node        │  │
│            └────────┬─────────┘         └─────────┬─────────┘  │
│                     │                               │             │
│                     └─────────────┬─────────────────┘             │
│                                   ▼                               │
│                        ┌──────────────────┐                       │
│                        │     score_       │                       │
│                        │   aggregation   │                       │
│                        └────────┬────────┘                       │
│                                 │                                 │
│                                 ▼                                 │
│                        ┌──────────────────┐                       │
│                        │ report_genera   │                       │
│                        │   tion_node     │                       │
│                        └────────┬────────┘                       │
│                                 │                                 │
│                                 ▼                                 │
│                        ┌──────────────────┐                       │
│                        │   sqlite_storage│                       │
│                        │      _node      │                       │
│                        └──────────────────┘                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## 📋 12 Phishing Indicators

### Header Analysis (7 indicators)
| Indicator | Description |
|-----------|-------------|
| SPF Check | Sender Policy Framework verification |
| DKIM Check | DomainKeys Identified Mail signature |
| DMARC Check | Domain-based Message Authentication |
| Reply-To Mismatch | Reply-To domain differs from From |
| Return-Path Mismatch | Return-Path domain differs from From |
| Suspicious Received Chain | IP hops > 5 or private IP ranges |
| Message-ID Anomaly | Message-ID domain differs from sender |

### Body Analysis (5 indicators)
| Indicator | Description |
|-----------|-------------|
| Urgency Signals | Urgency language ("act now", "suspended") |
| Credential Harvesting Cues | Password/login/verify phrases |
| Impersonation Signals | Brand impersonation (PayPal, Microsoft) |
| Suspicious Links | Mismatched anchor text, IP URLs |
| Homoglyph Domains | Unicode lookalike characters |

## 🛠️ Setup Instructions

### Prerequisites
- Python 3.10+
- OpenAI API Key

### Installation

1. **Clone the repository**
```bash
cd PhishSentinel
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment**
```bash
# Copy the example environment file
copy .env.example .env

# Edit .env and add your OpenAI API key
# OPENAI_API_KEY=sk-your-api-key-here
```

5. **Run the application**
```bash
streamlit run app.py
```

The application will open in your browser at `http://localhost:8501`

## 📖 How It Works

1. **Input**: Paste email text or upload a .eml file
2. **Parse**: Extract headers and body using Python email stdlib
3. **Analyze**: Run through 12 detection indicators
4. **Score**: Calculate weighted threat score (0-100)
5. **Report**: Generate AI-powered threat narrative
6. **Store**: Save to SQLite for history tracking

### Threat Score Calculation

```
Threat Score = Σ(Header Indicators × 1.0) + Σ(Body Indicators × 1.5) + IOC Penalty
```

| Score Range | Threat Level |
|-------------|---------------|
| 0-20 | Safe ✅ |
| 21-45 | Suspicious ⚠️ |
| 46-74 | Likely Phishing 🚨 |
| 75-100 | Critical ☠️ |

## 📱 Dashboard Screenshots

### Analysis Dashboard
![Analysis Dashboard](docs/analysis.png)
*Threat gauge, metric cards, and radar chart visualization*

### IOC Report
![IOC Report](docs/iocs.png)
*Extracted indicators of compromise with CSV export*

### History
![History](docs/history.png)
*Previous analysis history with reload capability*

## 📁 Project Structure

```
phishsentinel/
├── app.py                    # Streamlit dashboard
├── agent/
│   ├── __init__.py
│   ├── graph.py              # LangGraph StateGraph
│   ├── nodes.py              # Analysis node functions
│   ├── state.py              # TypedDict state definition
│   └── schemas.py            # Pydantic models
├── utils/
│   ├── email_parser.py       # Email parsing helpers
│   ├── homoglyph.py          # Unicode homoglyph detection
│   ├── scoring.py            # Score aggregation logic
│   └── db.py                 # SQLite operations
├── data/
│   └── phishsentinel.db      # SQLite database
├── samples/
│   └── sample_phish.eml      # Sample phishing email
├── .env.example
├── requirements.txt
└── README.md
```

## 🔧 Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| OPENAI_API_KEY | OpenAI API key | Required |
| OPENAI_MODEL | Model to use | gpt-4o |
| OPENAI_TEMPERATURE | LLM temperature | 0.1 |

## 🚀 Live Demo

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://phishsentinel.streamlit.app)

*Deploy your own instance to Streamlit Cloud*

## 🧪 Testing with Sample Email

The project includes a sample phishing email at `samples/sample_phish.eml` that demonstrates multiple detection indicators:

- SPF/DKIM/DMARC failures
- Reply-To domain mismatch
- Homoglyph domain (payраl.com with Cyrillic 'а')
- Urgency language ("24 hours", "suspended")
- Credential harvesting cues
- IP-based URL

## 📝 License

MIT License - see LICENSE file for details

## ⚠️ Disclaimer

This tool is for educational and defensive security purposes only. Always verify suspicious emails through official channels and never use this tool for unauthorized access to systems.

---

<p align="center">Built with ❤️ using LangGraph, LangChain, and Streamlit</p>
