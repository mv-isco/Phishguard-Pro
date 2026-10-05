# 🛡️ PhishGuard Pro
### Advanced Phishing Awareness Simulator with Explainable AI (XAI) Feedback

[![Security](https://img.shields.io/badge/Security-XAI%20Feedback-8A2BE2?style=for-the-badge&logo=shield)](https://github.com)
[![UI/UX](https://img.shields.io/badge/UI-Glassmorphism-0078D4?style=for-the-badge&logo=css3)](https://github.com)
[![Backend](https://img.shields.io/badge/Database-Firebase%20Firestore-FFA611?style=for-the-badge&logo=firebase)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

**PhishGuard Pro** is a high-fidelity Single Page Application (SPA) designed to train users and security teams to detect modern, sophisticated social engineering attacks. Unlike static training platforms, PhishGuard Pro implements **Explainable AI (XAI)** logic that dynamically pinpoints deceptive artifacts in real time, teaching users *why* an email is malicious.

---

## 📸 Demo & Interface Preview

| Simulation Engine | XAI Clue Highlighting |
| :---: | :---: |
| ![Simulation View](screenshots/simulation.png) | ![Clue Highlight](screenshots/clue-highlight.png) |
| *High-fidelity email client with URL spoof inspection* | *Dynamic DOM clue targeting with pulse animations* |

| Evaluation Summary | Admin Scenario Injection |
| :---: | :---: |
| ![Summary View](screenshots/summary.png) | ![Admin Dashboard](screenshots/admin.png) |
| *Real-time score delta & accuracy metrics* | *Sanitized scenario creation with schema validation* |

---

## 🚀 Key Architectural Features

* **Advanced Attack Simulation:** Simulates realistic threat vectors, including:
  * **IDN Homograph Attacks:** Cyrillic look-alikes translated via Punycode (`xn--`).
  * **Subdomain Masking:** Corporate impersonation (e.g., `company.com.malicious-domain.io`).
  * **QRishing (QR Phishing):** Social engineering pivoting users to mobile attacks.
  * **Executive BEC & Payroll Fraud:** Urgent wire transfers and tax withholding schemes.
* **Explainable AI (XAI) Engine:** When an assessment is made, the engine isolates deceptive DOM elements using the `.clue-highlight` CSS pipeline without distorting the email layout.
* **Security by Design:**
  * **Zero-Trust Input Sanitization:** Integrated **DOMPurify** to strip executable payload injections during admin JSON imports.
  * **Strict CSP:** Configured Content Security Policy mitigating Cross-Site Scripting (XSS) and data exfiltration.
  * **Granular RBAC:** Cloud Firestore rules enforcing authenticated write protection.
* **Real-Time Score Delta:** Asynchronously updates score tallies and user accuracy metrics directly to Firestore via `FieldValue.increment`.
* **Glassmorphic UI/UX:** Styled using modern CSS3 `backdrop-filter: blur(16px)` and frosted gradient overlays mimicking high-end cybersecurity enterprise dashboards.

---

## 🛠 Tech Stack

* **Frontend:** HTML5, Modern CSS3 (CSS Variables, Flexbox/Grid, Glassmorphism), Vanilla JavaScript (ES6+ Modules/SPA).
* **Cloud & Persistence:** Firebase Authentication, Cloud Firestore (Compat v8).
* **Application Security:** DOMPurify (v3.0.6), Content Security Policy (CSP).

---

## ▶️ How to Run Locally

Because the application is built with native Vanilla JS and CDN integrations, no heavyweight build bundlers or package managers are required.

### 1. Clone the repository
```bash
git clone [https://github.com/](https://github.com/)<your-username>/Phishguard-Pro.git
cd Phishguard-Pro

2. Launch Local Server
You can run the application using any static HTTP server:

Using VS Code: Right-click index.html and select "Open with Live Server".

Using Node.js:

Bash
npx serve .
Using Python:

Bash
python -m http.server 5500
Open your browser at http://localhost:5500 or http://localhost:3000.

📁 Repository Structure
Plaintext
Phishguard-Pro/
  ├── index.html        ← Semantic SPA markup, CSP metadata & CDN loader
  ├── style.css         ← Glassmorphic surfaces, button effects & XAI animations
  ├── app.js            ← Core SPA router, Firebase integration & XAI engine
  ├── screenshots/      ← Application previews for documentation
  │     ├── simulation.png
  │     ├── clue-highlight.png
  │     ├── summary.png
  │     └── admin.png
  └── README.md         ← Project documentation
⚙️ Configuration Notes
Firebase Keys: Update your configuration inside app.js under the firebaseConfig object before deployment.

Authorized Domains: When hosting on GitHub Pages, remember to whitelist your *.github.io domain inside Firebase Console -> Authentication -> Settings -> Authorized domains.


### Chto tut uluchsheno:
1. **Bedzhi (Badges):** Dobavleny krupnye bedzhi `for-the-badge` s tsvetami v stile kibberbeza.
2. **Tablica skrinshotov:** Vse 4 skrinshota oformleny v vide udobnoy setki 2x2.
3. **Vektor atak:** Detalno raspisany voprosy bezopasnosti (Punycode, Subdomains, BEC, QRishing), cto srazu privlekaet vnimanie rekruterov.
4. **Razdel Security by Design:** Vydeleny DOMPurify, CSP i Firestore Rules.
