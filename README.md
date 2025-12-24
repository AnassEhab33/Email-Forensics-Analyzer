# Email Forensics Analyzer

A comprehensive email forensics tool for investigating phishing campaigns and email spoofing attacks.

**Digital Forensics Course Project**

---

## 🎯 Features

| Feature | Description |
|---------|-------------|
| **MBOX Parsing** | Parse email archive files (MBOX format) |
| **Header Analysis** | Extract and analyze email headers (From, To, Return-Path, etc.) |
| **Spoofing Detection** | Multi-level detection with risk scoring (LOW → CRITICAL) |
| **Interaction Graph** | Visual network of sender/receiver relationships |
| **Attachment Extraction** | Save attachments with hash values (MD5, SHA256) |
| **Web Interface** | Modern dark theme with real-time visualization |

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd email-forensics-analyzer
pip install -r requirements.txt
```

### 2. Run the Application

```bash
python app.py
```

### 3. Open in Browser

Navigate to: **http://localhost:5000**

### 4. Upload Sample File

Use the included test file: `sample_data/test_emails.mbox`

---

## 📁 Project Structure

```
email-forensics-analyzer/
├── app.py                    # Flask web application
├── requirements.txt          # Python dependencies
├── forensics/                # Core analysis modules
│   ├── mbox_parser.py        # MBOX file parsing
│   ├── header_analyzer.py    # Email header extraction
│   ├── spoofing_detector.py  # Spoofing detection engine
│   ├── interaction_graph.py  # Relationship graph builder
│   └── attachment_handler.py # Attachment extraction
├── templates/                # HTML templates
│   ├── index.html            # Upload page
│   ├── dashboard.html        # Main analysis view
│   ├── email_detail.html     # Single email view
│   └── attachments.html      # Attachments gallery
├── static/css/               # Stylesheets
│   └── styles.css            # Dark theme UI
└── sample_data/              # Test files
    └── test_emails.mbox      # Sample phishing emails
```

---

## 🔍 Spoofing Detection Checks

The tool performs the following checks on each email:

1. **From/Return-Path Mismatch** - Sender domain differs from return path
2. **From/Reply-To Mismatch** - Replies go to different domain
3. **Suspicious Domain Patterns** - Typosquatting (paypa1, micr0soft, etc.)
4. **Dangerous Attachments** - Executable files (.exe, .bat, .js, etc.)
5. **Phishing Keywords** - Urgent language in subject lines
6. **Missing Message-ID** - Standard header is absent
7. **SPF/DKIM Failures** - Email authentication failed

### Risk Levels

| Level | Score | Meaning |
|-------|-------|---------|
| 🟢 LOW | 0-19 | Minor concerns or clean |
| 🟡 MEDIUM | 20-39 | Some suspicious indicators |
| 🟠 HIGH | 40-59 | Multiple red flags |
| 🔴 CRITICAL | 60+ | Highly likely phishing/spoofing |

---

## 📊 Sample Case: Phishing Campaign Investigation

The included `test_emails.mbox` contains:

| Email | Type | Spoofing Indicators |
|-------|------|---------------------|
| PayPal Security | 🔴 Phishing | Domain mismatch, typosquatting (paypa1) |
| Microsoft Support | 🔴 Phishing | .exe attachment, SPF fail, fake domain |
| Nigerian Prince | 🔴 Scam | Reply-to mismatch, lottery keywords |
| Bank of America | 🔴 Phishing | Missing Message-ID, domain mismatch |
| John Smith (Q4 Report) | 🟢 Legitimate | Clean headers |
| Sarah Wilson (Meeting) | 🟢 Legitimate | Clean headers |
| IT Department | 🟢 Legitimate | Clean headers |
| David Brown (Partnership) | 🟢 Legitimate | Clean headers |

---

## 🛠️ Technologies Used

- **Python 3** - Core programming language
- **Flask** - Web framework
- **Standard Library** - `mailbox`, `email` modules (no external forensic tools)
- **Vis.js** - Interactive network graphs
- **Chart.js** - Risk distribution charts
- **CSS3** - Modern glassmorphism UI

---

## ⚠️ Important Notes

- This tool is for **educational purposes** in digital forensics
- Does **NOT** use pre-built forensic tools (Autopsy, FTK, etc.)
- Built from scratch using Python standard library
- Sample data includes fake phishing emails for demonstration

---

## 👨‍💻 Authors
- Anass Ehab Einshouka
- Seif Usama
- Mahmoud Omar Elkhaligy

---
Digital Forensics Course Project - 2025
