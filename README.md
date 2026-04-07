# 🛡️ PhishGuard Pro 
### Advanced Phishing Awareness Simulator with XAI Feedback

![Security](https://img.shields.io/badge/Security-XAI-blueviolet) 
![UI/UX](https://img.shields.io/badge/UI-Glassmorphism-blue)
![Firebase](https://img.shields.io/badge/Backend-Firebase-orange)

**PhishGuard Pro** is a high-fidelity Single Page Application (SPA) designed to train users in identifying sophisticated phishing vectors. The project integrates **Explainable AI (XAI)** principles by providing real-time, visual feedback on deceptive elements.

---

### 🚀 Key Technical Features

* **Advanced Threat Simulation:** Supports detection training for Homograph (Punycode) attacks, Sub-domain trickery, and Hidden IP-based URLs.
* **Explainable AI (XAI) Component:** Implemented a custom logic engine that visually isolates malicious artifacts (DOM elements) upon user interaction.
* **Security-by-Design:** * Integrated **DOMPurify** for input sanitization.
    * Established a strict **Content Security Policy (CSP)** to mitigate XSS risks.
* **Real-time Synchronization:** Built using **Firebase (Auth & Firestore)** for seamless, real-time score tracking and leaderboard updates.
* **Modern UI/UX:** Designed with a **Glassmorphism** aesthetic using CSS3 `backdrop-filter` for a premium, dashboard-like feel.

### 🛠 Tech Stack
* **Frontend:** HTML5, CSS3 (Glassmorphism), JavaScript (SPA logic).
* **Backend:** Firebase Auth, Cloud Firestore.
* **Security Tools:** DOMPurify, CSP.
