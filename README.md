# 🚨 Vulnerable Web Application Lab - OWASP Top 10

[![Python](https://img.shields.io/badge/Python-3.9-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-green.svg)](https://flask.palletsprojects.com/)
[![Docker](https://img.shields.io/badge/Docker-Enabled-blue.svg)](https://www.docker.com/)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-orange.svg)](https://owasp.org/www-project-top-ten/)

## 📋 Overview
An intentionally vulnerable web application designed for learning and practicing OWASP Top 10 security vulnerabilities. Perfect for cybersecurity students, penetration testers, and developers learning secure coding practices.

## 🎯 Features
- ✅ **7+ OWASP Top 10 Vulnerabilities**
- ✅ **Dockerized Setup** (One-command deployment)
- ✅ **Complete Lab Report** with remediation
- ✅ **Educational Purpose Only** (Do not deploy in production)

## 🔓 Included Vulnerabilities
| Vulnerability | OWASP Category | Severity | Endpoint |
|---------------|----------------|----------|----------|
| SQL Injection | A03: Injection | Critical | `/search?q=` |
| Cross-Site Scripting (XSS) | A03: Injection | High | `/comment` |
| Broken Authentication | A07: Auth Failures | High | `/login` |
| Insecure Direct Object References | A01: Broken Access Control | Medium | `/profile/<id>` |
| Security Misconfiguration | A05: Security Misconfig | Medium | `/admin` |
| Command Injection | Additional | Critical | `/ping?host=` |
| Unrestricted File Upload | A03: Injection | Medium | `/upload` |

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Git

### One-Command Setup
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/vulnerable-webapp-lab.git
cd vulnerable-webapp-lab

# Start the vulnerable application
docker-compose up --build

```
📚 Learning Resources
OWASP Top 10 2021
OWASP Testing Guide
PortSwigger Web Security Academy

📄 License
Educational Use Only - Not for Production Deployment

👤 Author
Muhammad Rafay Aijaz

GitHub: @RafayAijaz

🙏 Acknowledgments

OWASP Foundation for the Top 10 framework
Flask framework developers
Docker community

⚠️ Disclaimer: This application is for educational purposes only. The author is not responsible for any misuse of this software.



