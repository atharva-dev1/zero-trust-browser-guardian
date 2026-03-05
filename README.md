<div align="center">

# 🛡️ Zero-Trust Browser Guardian (ZTBG)

### *Your AI Security Agent Inside Every Tab*

![Version](https://img.shields.io/badge/version-1.0.1-blue?style=flat-square)
![Manifest](https://img.shields.io/badge/Manifest-V3-green?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-purple?style=flat-square)
![Privacy](https://img.shields.io/badge/data%20collected-none-brightgreen?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Chrome-yellow?style=flat-square)

**Built by Atharva Sharma & Ashwin Jauhary · Team Nexora**

[Features](#-features) · [Installation](#-installation) · [Architecture](#-architecture) · [Tech Stack](#-tech-stack) · [Testing](#-testing) · [Contributing](#-contributing)

</div>

---

## 🔍 What is ZTBG?

Most browsers trust every website by default. **ZTBG trusts nothing.**

Zero-Trust Browser Guardian is a lightweight Chrome Extension that acts as your personal AI security agent — silently monitoring every page you visit for phishing attacks, data exfiltration attempts, dark patterns, and obfuscated malicious scripts.

**Everything runs 100% locally on your device. No data ever leaves your browser.**

---

## ✨ Features

### 🔴 Inbound Threat Detection
- **DOM Structure Analysis** — detects fake forms, hidden iframes, and phishing overlays
- **URL & Domain Scoring** — flags hyphens, free TLDs (`.tk`, `.ml`), IP-based URLs, punycode
- **IDN Homograph Detection** — catches lookalike domains using Cyrillic/Unicode characters
- **Obfuscated JS Scanner** — identifies `eval()`, `atob()`, `String.fromCharCode()` chains
- **NLP Keyword Scoring** — scores urgency, fear, and authority language patterns
- **Dark Pattern Detection** — confirm-shaming, pre-checked boxes, roach motel patterns
- **Real-time Risk Score** — 0–100 score shown on badge: 🟢 Safe / 🟡 Suspicious / 🔴 Dangerous

### 🔵 Outbound Data Protection
- **Clipboard Paste Interception** — warns before you paste secrets into untrusted pages
- **Form Submit Blocking** — stops sensitive data reaching unverified domains
- **Pattern Detection** — AWS keys, GitHub tokens, JWTs, credit cards, private keys
- **Shannon Entropy Analysis** — catches unknown secret formats no regex can identify

---

## 📦 Installation

### Option A — Chrome Web Store *(Recommended)*
> Coming soon — submission in progress

### Option B — Load Unpacked (Developer Mode)

```bash
# 1. Clone the repo
git clone https://github.com/your-username/ztbg-extension.git

# 2. Open Chrome and navigate to
chrome://extensions

# 3. Enable Developer Mode (toggle — top right corner)

# 4. Click "Load Unpacked" → select the /ztbg-extension folder

# 5. Pin the extension to your toolbar — you're protected ✅
```

---

## 🏗️ Architecture

### File Structure

```
ztbg-extension/
├── manifest.json              ← Extension config (Manifest V3)
├── background.js              ← Service Worker — orchestrates pipeline
├── content.js                 ← Injected into every page — DOM scanner
├── popup.html                 ← Extension UI shell
├── popup.js                   ← Popup logic & rendering
├── popup.css                  ← Popup styles
├── detector/
│   ├── phishing.js            ← Inbound threat detection
│   ├── dataleak.js            ← Outbound data protection
│   ├── entropy.js             ← Shannon entropy calculator
│   └── domAnalyzer.js         ← DOM anomaly & dark pattern scanner
├── constants.js               ← All regex patterns & keyword lists
└── icons/
    ├── 16.png
    ├── 48.png
    └── 128.png
```

### Detection Pipeline

```
Page Load
    │
    ▼
content.js injected
    │
    ├──► domAnalyzer.js  ──► DOM structure anomalies
    ├──► phishing.js     ──► URL scoring + NLP keywords
    └──► entropy.js      ──► Script entropy analysis
    │
    ▼
Risk Score calculated (0–100)
    │
    ▼
background.js ──► Badge color + score updated
    │
    ▼
Popup reads chrome.storage.local ──► Renders result

─────────────────────────────────────
Paste / Submit Events (separate flow)
─────────────────────────────────────
User pastes or submits form
    │
    ▼
dataleak.js + entropy.js scan value
    │
    ├── Match found ──► Inline warning shown, action intercepted
    └── No match    ──► Action proceeds normally
```

---

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| Extension Layer | JavaScript ES6+, Chrome Extension APIs (Manifest V3) |
| Content Scripts | Vanilla JS, MutationObserver, Paste/Submit event listeners |
| Detection Engine | Regex patterns, Shannon Entropy, Heuristic risk scoring |
| Local NLP | Rule-based keyword classifier (no external model) |
| Storage | `chrome.storage.local` — device-only, encrypted |
| Background | Service Worker (ephemeral, MV3-compliant) |
| UI | HTML + CSS, DOM APIs only (no frameworks) |

### Future Enterprise Stack *(Planned)*

| Layer | Technology |
|---|---|
| Backend | Node.js + Express |
| Database | MongoDB / PostgreSQL |
| Dashboard | React admin panel |
| Performance | WebAssembly for faster local inference |
| Integration | SIEM / SOC webhook support |

---

## 🧪 Testing

### Test Sensitive Data Detection

Paste these **safe test strings** into any input field on any website to verify detection:

| Type | Test String |
|---|---|
| Fake AWS Key | `AKIAIOSFODNN7EXAMPLE` |
| Fake JWT | `eyJhbGciOiJIUzI1NiJ9.dGVzdA.test` |
| Test Credit Card | `4111 1111 1111 1111` |
| Fake GitHub Token | `ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` |
| Fake Private Key | `-----BEGIN RSA PRIVATE KEY-----` |

**Expected:** A warning banner appears above the input before paste completes.

### Test Phishing Detection

```
✅ Visit https://google.com           → Green badge (Safe, score 0–30)
⚠️  Visit http://testphp.vulnweb.com  → Yellow/Red badge (Suspicious/Dangerous)
🔴 Create local test.html with eval(atob("...")) in a script tag → Red badge
```

### Test Rescan

```
1. Open any https:// page
2. Click the ZTBG icon → click 🔄 Rescan
3. Badge should update within ~2 seconds

On chrome:// pages → Rescan button is greyed out (expected behaviour)
```

---

## 🔒 Privacy

| | |
|---|---|
| Data collected | **None** |
| Data sent to servers | **None — 100% local** |
| Browsing history stored | **No** |
| Clipboard contents stored | **No** |
| Analytics / telemetry | **No** |
| Accounts required | **No** |

All processing happens on-device. The only data stored is your per-domain settings and a session log of threat *types* (never the actual values) in `chrome.storage.local`.

---

## 🛠️ Permissions Explained

| Permission | Why It's Needed |
|---|---|
| `activeTab` | Scan the currently open tab for threats |
| `storage` | Save your settings and allowlist locally |
| `scripting` | Inject the security scanner into web pages |
| `clipboardRead` | Check clipboard before paste events complete |

---

## 🤝 Contributing

Contributions are welcome! Here's how:

```bash
# 1. Fork the repository
# 2. Create your feature branch
git checkout -b feature/your-feature-name

# 3. Make your changes and commit
git commit -m "feat: describe your change clearly"

# 4. Push to your branch
git push origin feature/your-feature-name

# 5. Open a Pull Request with a clear description
```

### Good First Issues
- Add more phishing keyword patterns to `constants.js`
- Improve the popup UI for mobile screen sizes
- Add support for Firefox (WebExtensions API compatibility)
- Write unit tests for `entropy.js` and `dataleak.js`
- Add more sensitive data regex patterns

---

## 📋 Roadmap

- [x] Core phishing detection engine
- [x] Clipboard paste interception
- [x] Shannon entropy analysis
- [x] Real-time risk score badge
- [x] Per-domain allow/block toggle
- [ ] Chrome Web Store release
- [ ] Firefox / Edge support
- [ ] Enterprise admin dashboard
- [ ] Threat intelligence sharing (opt-in)
- [ ] WebAssembly inference module
- [ ] Mobile browser support

---

## 📄 License

```
MIT License

Copyright (c) 2025 Atharva Sharma & Ashwin Jauhary (Team Nexora)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software to deal in the Software without restriction, including the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
```

---

## 👥 Authors

**Atharva Sharma** & **Ashwin Jauhary**  
Team Nexora · HackTrack Round 1

---

<div align="center">

**Zero-Trust · Local-Only · No Data Sent · Privacy-First**

*If ZTBG helped you, consider giving it a ⭐ on GitHub*

</div>
