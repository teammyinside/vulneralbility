# Stored XSS in ELEX WordPress HelpDesk & Customer Ticketing System (v3.2.9)

[![Security](https://img.shields.io/badge/Security-High-red)](https://cwe.mitre.org/data/definitions/79.html)
[![CVE Status](https://img.shields.io/badge/CVE-Pending-yellow)]()

## 📌 Overview

A **Stored Cross-Site Scripting (XSS)** vulnerability was discovered in **ELEX WordPress HelpDesk & Customer Ticketing System** version **3.2.9**.

This flaw allows an unauthenticated attacker (depending on site configuration) to inject malicious JavaScript code into the **ticket subject** field, which will execute automatically when an administrator views the ticket list in the admin panel — **without opening the ticket**.

**Impact:** Cookie theft, session hijacking, full admin compromise.

---

## 📂 Full Report

Detailed description, proof-of-concept, and mitigation can be found in:  
📄 [`elex-wsdesk-stored-xss.md`](./elex-wsdesk-stored-xss.md)

---

## 🛡️ Severity

- **Vulnerability Type:** Stored XSS  
- **Impact:** High — Admin account takeover possible  
- **Authentication Required:** No (in default configuration)

---

## 🧑‍💻 Credits

Discovered by: **Athiwat Tiprasaharn**

---

## 📅 Timeline

- **2025-08-09** — Vulnerability discovered & reported to vendor.
- **Pending** — Vendor response.
- **Pending** — CVE assignment.

---

## 📚 References

- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP XSS Prevention Cheat Sheet](https://owasp.org/www-community/xss-prevention)
