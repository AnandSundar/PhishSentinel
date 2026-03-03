<div align="center">

# 🕵️ PhishSentinel

### AI-Powered Phishing Email Threat Analyzer

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![LangGraph](https://img.shields.io/badge/LangGraph-Agentic_AI-1C3C3C?logo=langchain)](https://langchain-ai.github.io/langgraph/)
[![OpenAI GPT-4o](https://img.shields.io/badge/OpenAI-GPT--4o-412991?logo=openai)](https://openai.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?logo=streamlit)](https://streamlit.io/)

**PhishSentinel autonomously analyzes suspicious emails, scores their threat level from 0–100, extracts attack indicators, and presents findings in a live dashboard — in under 10 seconds.**

[🚀 Live Demo](YOUR_DEMO_URL) · [📖 Docs](#-documentation) · [🐛 Report Bug](https://github.com/YOUR_USERNAME/phishsentinel/issues) · [💡 Request Feature](https://github.com/YOUR_USERNAME/phishsentinel/issues)

</div>

---

## 🎯 What is This?

**PhishSentinel is an intelligent security tool that detects phishing emails** — fake emails designed to trick you into giving up passwords, clicking dangerous links, or sending money to scammers. Think of it as a digital detective that reads every suspicious email and tells you exactly how dangerous it is.

Phishing is the **#1 cyber threat of 2026**, costing businesses over $3.5 billion every year. Criminals now use artificial intelligence (AI — computer systems that can learn and make decisions) to craft fake emails that are nearly indistinguishable from real ones. These attacks fool even careful, tech-savvy employees. Every company, from small startups to Fortune 500 giants, desperately needs better tools to catch these threats before they cause damage.

What makes PhishSentinel different from basic spam filters is that it uses an **AI agent** — a program that reasons step-by-step like a human security analyst — instead of simple keyword matching. While traditional tools look for words like "urgent" or "click here," PhishSentinel understands context, analyzes email headers (the behind-the-scenes routing information), detects visual tricks like lookalike domain names, and weighs 12 different risk factors to produce a reliable threat score.

> 💼 **For Hiring Managers:** PhishSentinel demonstrates production-level skills in AI agent design, cybersecurity tooling, and full-stack Python development. It is the kind of tool real SOC (Security Operations Center) teams request but rarely have. The architecture mirrors enterprise threat intelligence platforms costing tens of thousands of dollars per year.

---

## ✨ Features

| Feature | What It Does (Plain English) |
|---------|------------------------------|
| **SPF Check** | SPF (Sender Policy Framework) — checks whether the email was sent from an authorized server for that domain, detecting spoofed sender addresses |
| **DKIM Check** | DKIM (DomainKeys Identified Mail) — verifies a digital signature embedded in the email to prove it wasn't tampered with during transit |
| **DMARC Check** | DMARC (Domain-based Message Authentication, Reporting, and Conformance) — tells receiving servers what to do with emails that fail SPF or DKIM checks |
| **Homoglyph Detection** | Detects lookalike Unicode characters in domain names (like using "аmazon.com" with a Cyrillic 'а' instead of Latin 'a') that trick the human eye |
| **Urgency Analysis** | AI scans the email body for pressure tactics like "Act now!" or "Your account will be suspended" that rush victims into mistakes |
| **IOC Extraction** | IOC (Indicators of Compromise) — automatically pulls out malicious URLs, suspicious IP addresses, and questionable domains as evidence |
| **Threat Scoring** | Converts 12 individual indicator results into a single 0–100 threat score using weighted algorithms |
| **Radar Chart** | Plotly visualization showing all 12 indicator scores at once, making attack patterns instantly visible |
| **Gauge Chart** | Color-coded speedometer-style display showing the overall threat level (Safe, Suspicious, Likely Phishing, or Critical) |
| **IOC Export** | Download extracted threat indicators as CSV files for use in other security tools |
| **Analysis History** | SQLite database storing previous analyses with timestamps, so you can track threats over time |
| **.EML File Upload** | Import raw email files directly from Outlook, Thunderbird, or other email clients |
| **Structured LLM Output** | Uses Pydantic (a Python library for data validation) to ensure AI responses follow a predictable format |

---

## 🏗️ How It Works (Architecture)

### Plain English Explanation

When you paste an email into PhishSentinel, it passes through **7 specialized AI agents** arranged in a pipeline called a graph. Each agent has one job: the first reads and decodes the email, the second checks authentication headers, the third scans the message body for suspicious language, the fourth extracts dangerous links, and so on. These agents pass information forward like an assembly line, with conditional branches that skip unnecessary steps for safe emails. Finally, a scoring agent weighs all findings and a report generator writes a human-readable summary. The entire process completes in seconds, and results are saved to a local database.

### Agent Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        PhishSentinel                            │
│                     LangGraph Agent Flow                        │
└─────────────────────────────────────────────────────────────────┘

  📧 Raw Email Input
        │
        ▼
┌───────────────────┐
│  1. Email Parser  │  ← Extracts headers, body, attachments
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  2. Header Agent  │  ← Checks SPF, DKIM, DMARC, IP hops
└────────┬──────────┘
         │
    ┌────┴────┐
    │ All     │
    │ auth    │ ← Conditional branch (LangGraph edge)
    │ pass?   │
    └────┬────┘
    NO   │ YES
    │    └──────────────────────┐
    ▼                           ▼
┌──────────────┐     ┌──────────────────────┐
│ Deep Header  │     │  Skip deep inspection │
│ Inspection   │     │  (fast path)          │
└──────┬───────┘     └──────────┬────────────┘
       │                        │
       └───────────┬────────────┘
                   ▼
         ┌─────────────────┐
         │  3. Body Agent  │  ← LLM scans for urgency, brand
         └────────┬────────┘    impersonation, homoglyph domains
                  │
                  ▼
         ┌─────────────────┐
         │  4. IOC Extract │  ← Pulls IPs, URLs, domains as
         └────────┬────────┘    Indicators of Compromise
                  │
                  ▼
         ┌─────────────────┐
         │  5. Scoring     │  ← Weights 12 indicators → 0–100
         └────────┬────────┘    threat score
                  │
                  ▼
         ┌─────────────────┐
         │  6. Report Gen  │  ← GPT-4o writes analyst narrative
         └────────┬────────┘
                  │
                  ▼
         ┌─────────────────┐
         │  7. SQLite Save │  ← Stores analysis for history tab
         └────────┬────────┘
                  │
                  ▼
         📊 Streamlit Dashboard
```

### Technology Stack

| Layer | Technology | Why We Chose It |
|-------|------------|-----------------|
| **AI Agent Framework** | LangGraph | LangGraph (a LangChain extension for building stateful, multi-actor applications) lets us define complex agent workflows as graphs with conditional edges, making the pipeline modular and easy to extend |
| **Language Model** | OpenAI GPT-4o | GPT-4o provides excellent reasoning for security analysis tasks while supporting structured output via function calling, ensuring consistent data formats |
| **Web Dashboard** | Streamlit | Streamlit (a Python library for creating data apps) allows rapid UI development without writing HTML/JavaScript, perfect for data-heavy security tools |
| **Charts** | Plotly | Plotly creates interactive, publication-quality visualizations that render beautifully in browsers and export cleanly to images |
| **Email Parsing** | Python `email` stdlib | Python's built-in `email` library handles MIME (Multipurpose Internet Mail Extensions) encoding, attachments, and header parsing without external dependencies |
| **Data Storage** | SQLite | SQLite (a serverless, self-contained database engine) requires zero setup, stores data in a single file, and handles thousands of analyses without configuration |
| **Config/Secrets** | python-dotenv + st.secrets | `python-dotenv` loads API keys from `.env` files locally; `st.secrets` manages them securely in Streamlit Cloud — keeping credentials out of code |
| **Language** | Python 3.11+ | Python 3.11 offers better error messages, faster performance, and modern typing features that make complex agent code more maintainable |

---

## 🔍 The 12 Phishing Indicators

| # | Indicator | Category | Max Score | Plain English Explanation |
|---|-----------|----------|-----------|---------------------------|
| 1 | **SPF Check** | Header | 10 | SPF (Sender Policy Framework) — verifies the email came from an authorized mail server for the sender's domain; failure suggests spoofing |
| 2 | **DKIM Check** | Header | 10 | DKIM (DomainKeys Identified Mail) — validates a cryptographic signature proving the email wasn't modified after being sent |
| 3 | **DMARC Check** | Header | 10 | DMARC tells email providers what to do with messages that fail authentication; absence means no enforcement policy |
| 4 | **Reply-To Mismatch** | Header | 10 | When the "Reply-To" address differs from the "From" address, scammers may be redirecting responses to a different account |
| 5 | **Return-Path Mismatch** | Header | 10 | The Return-Path (where bounced emails go) should match the sender; mismatches indicate potential spoofing |
| 6 | **Suspicious IP Chain** | Header | 10 | Traces the path through mail servers (IP hops); blacklisted IPs or unexpected geographic routes raise flags |
| 7 | **Message-ID Anomaly** | Header | 10 | Legitimate emails have properly formatted Message-IDs; suspicious patterns may indicate mass spam tools |
| 8 | **Urgency Signals** | Body (AI) | 10 | Phrases creating artificial pressure like "Immediate action required" or "24 hours only" — classic manipulation tactics |
| 9 | **Credential Harvesting Cues** | Body (AI) | 10 | Requests for passwords, credit card numbers, or account verification — legitimate services rarely ask for these via email |
| 10 | **Brand Impersonation** | Body (AI) | 10 | Emails claiming to be from banks, tech companies, or government agencies that use unofficial domains or slight name variations |
| 11 | **Suspicious Link Analysis** | Body (AI) | 10 | URLs that redirect through trackers, use URL shorteners to hide destinations, or contain typos of real domains |
| 12 | **Homoglyph Domain Detection** | Body (AI) | 10 | Internationalized domain names using visually similar Unicode characters (Cyrillic 'а' vs Latin 'a') to impersonate trusted brands |

### Threat Score Legend

```
THREAT SCORE LEGEND
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  0 – 20  │ ✅ Safe              │ No significant indicators found
 21 – 45  │ ⚠️  Suspicious       │ Minor anomalies, exercise caution  
 46 – 74  │ 🚨 Likely Phishing   │ Multiple strong indicators present
 75 – 100 │ ☠️  Critical         │ High-confidence phishing attack
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 🖥️ Dashboard Screenshots

### Threat Analysis Tab

> The main dashboard showing a Plotly gauge chart with threat score 87/100 (Critical), four metric cards, and a radar chart plotting all 12 indicator scores.

![Threat Analysis Tab](docs/screenshots/threat_analysis.png)

### IOC Report Tab

> The IOC (Indicator of Compromise) report tab showing extracted malicious URLs, sender IPs, and suspicious domains in a sortable table with CSV export.

![IOC Report Tab](docs/screenshots/ioc_report.png)

### Analysis History Tab

> The history tab showing the last 20 email analyses stored in SQLite, with timestamps, threat scores, and clickable rows to reload past results.

![Analysis History Tab](docs/screenshots/history_tab.png)

---

## 🚀 Installation & Setup

### Prerequisites

Before you begin, ensure you have:

- **Python 3.11 or higher** — [Download from python.org](https://www.python.org/downloads/)
- **pip** — Python's package installer (included with Python 3.4+)
- **OpenAI API Key** — [Get yours at OpenAI](https://platform.openai.com/api-keys) (requires account creation and billing setup)

### Quick Start (5 Steps)

```bash
# Step 1: Clone the repository
git clone https://github.com/YOUR_USERNAME/phishsentinel.git
cd phishsentinel

# Step 2: Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Step 3: Install dependencies
pip install -r requirements.txt

# Step 4: Set your OpenAI API key
cp .env.example .env
# Edit .env and add: OPENAI_API_KEY=your_key_here

# Step 5: Run the app
streamlit run app.py
```

**The app will open at [http://localhost:8501](http://localhost:8501) in your browser.**

> 💡 **Pro Tip:** Test the app immediately using the included sample email: `samples/sample_phish.eml`

### Deploy to Streamlit Cloud (Free)

Want a public URL to share with stakeholders? Deploy to Streamlit Cloud in minutes:

1. **Push to GitHub**: Ensure your code is in a public or private GitHub repository
2. **Sign up**: Create a free account at [share.streamlit.io](https://share.streamlit.io)
3. **Connect repo**: Click "New app" and select your `phishsentinel` repository
4. **Set secrets**: In the app settings, add your `OPENAI_API_KEY` as a secret (never commit this to Git!)
5. **Deploy**: Streamlit Cloud will automatically detect `app.py` and launch your dashboard

Your app will be live at `https://your-app-name.streamlit.app` — perfect for demos and portfolio links.

---

## 📁 Project Structure

```
phishsentinel/
│
├── 📄 app.py                    # Streamlit UI entry point — run this to start the app
│
├── 🤖 agent/
│   ├── __init__.py
│   ├── graph.py                 # LangGraph StateGraph — defines the AI agent pipeline
│   ├── nodes.py                 # 7 agent node functions (the "workers" in the pipeline)
│   ├── state.py                 # Shared data structure passed between agents
│   └── schemas.py               # Data models for structured AI output (Pydantic)
│
├── 🛠️  utils/
│   ├── email_parser.py          # Reads and extracts raw email components
│   ├── homoglyph.py             # Detects lookalike Unicode characters in domains
│   ├── scoring.py               # Converts indicator results into 0–100 threat score
│   └── db.py                    # SQLite database read/write helpers
│
├── 📊 data/
│   └── phishsentinel.db         # Auto-created SQLite database (analysis history)
│
├── 📧 samples/
│   └── sample_phish.eml         # Demo phishing email — use this to test the app instantly
│
├── 📸 docs/screenshots/         # Dashboard screenshots for this README
│
├── .env.example                 # Template for your API key config
├── requirements.txt             # Python package dependencies
└── README.md                    # You are here
```

---

## 🔐 Security & Privacy

PhishSentinel is designed with privacy as a core principle:

### No Email Storage by Default

**Emails are analyzed in memory and never stored.** Only the *analysis results* (threat scores, extracted IOCs, summary text) are saved to the local SQLite database. The original email content is discarded after processing completes. This means sensitive email content stays ephemeral — there is no growing archive of private communications on your server.

### API Key Safety

Your OpenAI API key is protected through multiple layers:
- **Local development**: Stored in `.env` file (which is gitignored by default)
- **Production deployment**: Managed via `st.secrets` in Streamlit Cloud
- **Never in code**: The application reads from environment variables, keeping credentials out of version control

### Local-First Design

PhishSentinel runs entirely on your own machine or private server. Emails are sent to **only two places**:
1. **Your local SQLite database** — for history storage
2. **OpenAI's API** — for AI analysis (via encrypted HTTPS connection)

No third-party analytics, no external logging services, no data brokers.

### OpenAI Data Handling

According to [OpenAI's API data usage policy](https://openai.com/policies/api-data-usage-policies), data sent through the API:
- **Is NOT used** to train OpenAI's models
- **Is retained temporarily** only for abuse monitoring (up to 30 days for enterprise, shorter for standard)
- **Can be zero retention** for eligible enterprise customers

> ⚠️ **Important:** Do not analyze emails containing sensitive personal data (SSNs, medical records, passwords) unless you have reviewed OpenAI's data usage policy and your organization's data handling requirements.

---

## 💼 Why This Project Matters (For Hiring Managers)

### The Real-World Problem

Phishing is the **#1 cyber threat facing businesses today**. According to the FBI's Internet Crime Complaint Center, phishing attacks cost organizations over $3.5 billion annually. In 2026, AI-generated phishing emails have become nearly impossible to distinguish from legitimate communications — even security professionals fall for sophisticated attacks.

Yet most companies still rely on basic spam filters that use simple keyword matching. They need intelligent tools that understand *context*, detect *nuanced deception*, and provide *actionable intelligence* — exactly what PhishSentinel delivers.

### Skills Demonstrated

Building PhishSentinel required mastery of eight critical engineering skills:

- **🤖 AI Agent Architecture** — Designed a multi-node agent system using LangGraph with conditional branching and state management
- **🔗 LLM Integration** — Integrated OpenAI GPT-4o with structured output schemas for reliable, parseable results
- **🔒 Cybersecurity Domain Knowledge** — Implemented SPF/DKIM/DMARC authentication checks and IOC extraction patterns used by enterprise SOC teams
- **📊 Data Visualization** — Created interactive Plotly charts (gauge, radar) that communicate threat data intuitively
- **🗄️ Database Design** — Built a SQLite-backed history system with proper schema design and query optimization
- **🧪 Input Validation** — Handled raw email parsing, file uploads, and edge cases in user-provided data
- **🌐 Full-Stack Development** — Delivered a complete application from backend AI agents to frontend dashboard
- **📝 Technical Documentation** — Produced clear README and inline documentation for maintainability

### Enterprise-Grade Patterns

PhishSentinel mirrors the architectural patterns found in commercial threat intelligence platforms costing $50,000+ per year:

- **Agent Graphs** — Modular AI components that can be extended or replaced independently
- **Structured LLM Output** — Using Pydantic schemas to ensure AI responses are machine-parseable
- **IOC Extraction** — Automated threat indicator harvesting for integration with SIEM (Security Information and Event Management) tools
- **Scoring Algorithms** — Weighted multi-factor analysis rather than binary yes/no decisions

> 🎯 **Bottom line:** PhishSentinel is not a tutorial project. It is a working security tool built with the same architectural patterns (agent graphs, structured LLM output, IOC extraction) used in enterprise threat intelligence platforms costing tens of thousands of dollars per year.

---

## 🗺️ Roadmap

| Feature | Status | Target |
|---------|--------|--------|
| Core 12-indicator analysis | ✅ Complete | v1.0 |
| Streamlit dashboard | ✅ Complete | v1.0 |
| SQLite history | ✅ Complete | v1.0 |
| VirusTotal API integration (URL scanning) | 🔄 In Progress | v1.1 |
| Bulk .eml folder analysis | 📋 Planned | v1.1 |
| Slack/Teams alert webhook | 📋 Planned | v1.2 |
| PDF report export | 📋 Planned | v1.2 |
| Multi-language phishing detection | 💡 Idea | v2.0 |
| Outlook add-in integration | 💡 Idea | v2.0 |

**Status Key:**
- ✅ Complete — Ready to use
- 🔄 In Progress — Currently being developed
- 📋 Planned — Scheduled for upcoming release
- 💡 Idea — Under consideration

---

## 🤝 Contributing

We welcome contributions from the security and AI community!

### How to Contribute

1. **Fork the Repository**: Click the "Fork" button on GitHub
2. **Create a Branch**: `git checkout -b feature/your-feature-name`
3. **Make Changes**: Write code, add tests, update docs
4. **Commit**: `git commit -m "Add: your feature description"`
5. **Push**: `git push origin feature/your-feature-name`
6. **Pull Request**: Open a PR with a clear description of changes

### Code Standards

- **Formatting**: Use [Black](https://black.readthedocs.io/) (`black .`)
- **Type Hints**: All functions must have type annotations
- **Docstrings**: Google-style docstrings for all public functions
- **Tests**: Include tests for new indicators or features

### Adding a New Phishing Indicator

Want to make PhishSentinel smarter? Here's how to add a new detection indicator:

1. **Define the Logic**: Create a function in `utils/` (e.g., `utils/new_detector.py`)
2. **Add to Pipeline**: Import and call your function in `agent/nodes.py` (in the appropriate agent node)
3. **Update State**: Add the new indicator to `agent/state.py` (in `PhishingAnalysisState`)
4. **Update Scoring**: Add weight to `utils/scoring.py` (`INDICATOR_WEIGHTS`)
5. **Update Schema**: Add to `agent/schemas.py` (in `IndicatorResult` or similar)
6. **Update UI**: Add visualization in `app.py`

Follow the **node pattern**: Each agent node receives the current state, performs analysis, and returns an updated state. The graph handles passing data between nodes.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

### What This Means

- ✅ Commercial use allowed
- ✅ Modification allowed
- ✅ Distribution allowed
- ✅ Private use allowed
- ⚠️ No warranty provided

---

## 📬 Contact

- **GitHub**: [@YOUR_USERNAME](https://github.com/YOUR_USERNAME)
- **LinkedIn**: [Your Name](https://linkedin.com/in/YOUR_PROFILE)
- **Email**: your.email@example.com

---

<div align="center">

**Built with ☕ and too much threat intelligence**

🕵️ *Stay suspicious. Stay safe.*

</div>
