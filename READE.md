# Enterprise Link & Website Security Auditor

A full-stack cybersecurity tool that detects phishing links, brand impersonation, typosquatting, and malicious websites in real time. Built with a Python FastAPI backend, a cloud-hosted web dashboard, and a Manifest V3 Chrome Extension.

## Live Demo
- **Web Dashboard:** [https://onrender.com](https://onrender.com)
- **Backend API:** [https://onrender.com](https://onrender.com)

---

## Key Features
- **Multi-Layer URL & Brand Heuristics:** Detects raw IP URLs, `@` destination masking, excessive subdomains, high-risk TLDs, punycode/homograph attacks (`xn--`), and fuzzy typosquatting against major brands.
- **Infrastructure & Network Checks:** Validates SSL/TLS certificate expiration and trust chains, inspects DNS `A` records, checks WHOIS domain age, and traces multi-hop HTTP redirects.
- **Content & Threat Intelligence:** Scans target HTML for credential-harvesting password forms and integrates with **Google Safe Browsing** and **VirusTotal** threat feeds.
- **Audit Dashboard & Bulk Scanner:** Supports single or multi-URL batch scanning, 4-category risk breakdown bars, SQLite audit logging, and one-click CSV report exports.
- **Chrome Extension (Manifest V3):** One-click popup scanner that automatically audits the active browser tab against the live cloud API.

---

## Tech Stack
- **Backend:** Python, FastAPI, Uvicorn, `tldextract`, `python-whois`, `dnspython`, `requests`
- **Frontend & Extension:** HTML5, CSS3, Vanilla JavaScript, Chrome Extensions Manifest V3
- **Hosting & Security:** Render (Web Service + Static Site), API Key Authentication (`X-API-Key`), Environment Variable Secrets

---

## Project Structure
```text
link-detector/
├── backend/
│   ├── main.py          # FastAPI server, CORS & authentication endpoints
│   └── detector.py      # URL heuristics, SSL, DNS, redirect & threat-intel engine
├── frontend/
│   └── index.html       # Web auditor dashboard with bulk scan & CSV export
├── extension/
│   ├── manifest.json    # Chrome Extension Manifest V3 configuration
│   ├── popup.html       # Extension popup UI
│   └── popup.js         # Active-tab scanner logic
└── requirements.txt     # Python dependencies
```

---

## Local Setup & Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com
   cd link-detector
   ```

2. **Create a virtual environment and install dependencies:**
   ```bash
   python -m venv venv
   source venv/bin/activate        # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Configure environment variables:**
   Create a `.env` file inside `backend/` with your optional API keys:
   ```env
   APP_API_KEY=your_custom_secret_key
   GOOGLE_SAFE_BROWSING_KEY=your_google_safe_browsing_key
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   ```

4. **Start the backend server:**
   ```bash
   cd backend
   uvicorn main:app --reload
   ```

5. **Load the Chrome Extension:**
   - Open `chrome://extensions` in Google Chrome.
   - Enable **Developer mode** (top right).
   - Click **Load unpacked** and select the `extension/` folder.
