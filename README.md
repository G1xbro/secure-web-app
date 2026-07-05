# 🛡️ Secure Web Application Portal

A lightweight, security-hardened backend API designed to showcase secure software development lifecycle (SDLC) practices. This application implements defensive programming principles to robustly mitigate threats defined in the **OWASP Top 10** vulnerability framework.

## 🚀 Technical Stack
* **Language:** Python 3
* **Framework:** Flask (Microframework)
* **Database & ORM:** SQLite / Flask-SQLAlchemy (Parameterized Mapping)
* **Authentication:** JSON Web Tokens (PyJWT) & Cryptographic Password Hashing (Bcrypt)
* **Validation:** Pydantic Core

---

## 🏗️ Core Architecture & Data Flow



1. **Client Request:** User authenticates or interacts via REST API routes.
2. **AAA Security Layer:** Middleware decorators intercept incoming JWT bearer tokens, verify cryptographic integrity, and evaluate role permissions.
3. **Validation & Sanitization:** Inputs pass through strict type-checking models (Pydantic) and string sanitizers (HTML Entity Encoding) before execution.
4. **Data Isolation Layer:** Data interaction is handled securely via parameterized Object-Relational Mapping (ORM) routines.

---

## 🔒 Security Matrix & Threat Mitigations

| Threat Category (OWASP Top 10) | Vulnerability Description | Mitigation Strategy Implemented |
| :--- | :--- | :--- |
| **A01:2021-Broken Access Control** | Insecure Direct Object References (IDOR / BOLA) where users view unauthorized data records. | Integrated dynamic data ownership validation (`note.user_id == current_user.id`) and a custom `@token_required(allowed_roles=[...])` RBAC decorator. |
| **A02:2021-Cryptographic Failures** | Storing cleartext passwords or using weak MD5/SHA1 hashing algorithms. | Deployed `bcrypt` adaptive salting and key-derivation hashing, completely isolating raw inputs from database storage. |
| **A03:2021-Injection** | SQL Injection (SQLi) and Cross-Site Scripting (XSS) payload executions. | Swapped raw SQL inputs for parameterized SQLAlchemy queries, and executed complete `html.escape()` entity parsing to neutralize script vectors. |
| **A05:2021-Security Misconfiguration** | Missing HTTP security headers, leaving browsers prone to clickjacking or MIME sniffing. | Injected global `app.after_request` hooks enforcing `X-Frame-Options: DENY`, strict `Content-Security-Policy` templates, and `X-Content-Type-Options: nosniff`. |
| **A09:2021-Security Logging & Monitoring Failures** | Lack of forensic audit records during credential exploitation or intrusion events. | Configured an unalterable local `security.log` file tracking authorization anomalies, while rigorously excluding PII/Passwords from log outputs. |

---

## ⚙️ Local Installation & Setup

**1. Clone the Repository:**
```bash
git clone [https://github.com/YOUR_GITHUB_USERNAME/secure-web-app.git](https://github.com/YOUR_GITHUB_USERNAME/secure-web-app.git)   
```

**2. Establish Environment Dependencies:**

```bash
python -m venv venv
source venv/bin/activate  # On Windows use: .\venv\Scripts\Activate
pip install -r requirements.txt
```

**3. Configure Environment Constants:**
Create a local .env configuration file in the project root directory:
```
FLASK_ENV=development
DATABASE_URL=sqlite:///secure_app.db
SECRET_KEY=generate_your_own_secure_hex_string
```

**4. Boot the Application Engine:**

    `python app.py`

---