# 🛡️ PhishGuard Pro 
### Advanced Phishing Awareness Simulator with XAI Feedback

![Security](https://img.shields.io/badge/Security-XAI-blueviolet) 
![UI/UX](https://img.shields.io/badge/UI-Glassmorphism-blue)
![Firebase](https://img.shields.io/badge/Backend-Firebase-orange)

**PhishGuard Pro** — это высокотехнологичное SPA-приложение, созданное для обучения пользователей выявлению сложных фишинговых атак. Проект использует принципы **Объяснимого ИИ (XAI)**, предоставляя визуальную обратную связь в реальном времени.

---

### 🚀 Ключевые особенности

* **Симуляция продвинутых угроз:** Обучение детекции омографических атак (Punycode), махинаций с поддоменами и скрытых IP-адресов.
* **Компонент XAI (Explainable AI):** Кастомный логический движок, который подсвечивает вредоносные артефакты в DOM-дереве при взаимодействии.
* **Security-by-Design:** * Интеграция **DOMPurify** для очистки входных данных.
    * Строгая политика безопасности контента (**CSP**) для защиты от XSS.
* **Real-time синхронизация:** Использование **Firebase (Auth & Firestore)** для отслеживания очков и обновления таблицы лидеров.
* **Modern UI/UX:** Дизайн в стиле **Glassmorphism** с использованием `backdrop-filter` для создания премиального интерфейса.

### 🛠 Стек технологий
* **Frontend:** HTML5, CSS3 (Glassmorphism), JavaScript (SPA logic).
* **Backend:** Firebase Auth, Cloud Firestore.
* **Безопасность:** DOMPurify, CSP.
