# Stored XSS in ELEX WordPress HelpDesk & Customer Ticketing System (v3.2.9)

**CVE ID:** Pending  
**Discovered:** 2025-08-09  
**Reporter:** Athiwat Tiprasaharn  
**Status:** Vendor notified, patch pending  
**Severity:** High  
**CWE:** [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

---

## Description

A **Stored Cross-Site Scripting (XSS)** vulnerability exists in **ELEX WordPress HelpDesk & Customer Ticketing System** version **3.2.9**.  
The vulnerability occurs due to the application's failure to properly sanitize user input in the **ticket subject field** before rendering it in the administrator ticket view.

An attacker can exploit this flaw by injecting malicious JavaScript code into the ticket subject. When an administrator visits the ticket management panel, the injected script executes in the admin's browser within the context of the WordPress site. This can lead to **cookie theft, session hijacking, or full compromise of the administrator account**.

---

## Affected Product

- **Plugin Name:** ELEX WordPress HelpDesk & Customer Ticketing System  
- **Version:** 3.2.9  
- **Vulnerability Type:** Stored XSS  
- **Impact:** Administrator account compromise, session hijacking, theft of sensitive information  
- **Authentication Required:** Not required (depending on site configuration — the issue is exploitable if ticket submission is allowed for unauthenticated users)

---

## Proof of Concept (PoC)

> **Note:** This PoC is provided for educational and testing purposes only. Do not use against systems without proper authorization.

1. Access the ticket submission form provided by the plugin.  
   (If the site allows public submissions, no authentication is required. Otherwise, log in as a low-privileged user.)

2. In the **Subject** field of the ticket form, insert the following payload as showned in the image below
<img width="2309" height="1044" alt="สกรีนช็อต 2025-08-09 222657" src="https://github.com/user-attachments/assets/bc27f241-c842-40a8-a5a2-49fa078f3e82" />


3. Submit the ticket.

4. When an administrator logs in to the WordPress admin panel and navigates to:
WSDesk → Ticket
the ticket subject is rendered without proper sanitization.

<img width="2874" height="883" alt="สกรีนช็อต 2025-08-09 222743" src="https://github.com/user-attachments/assets/719712e8-85d7-4729-bebf-6fdaeb2d9b83" />


5. The payload executes immediately — even without the admin opening the ticket — sending the admin's cookies to the attacker's webhook.

<img width="2879" height="1187" alt="สกรีนช็อต 2025-08-09 222721" src="https://github.com/user-attachments/assets/cbab152e-5890-44b4-a6f2-85fd72c1ea9e" />


## Impact
Successful exploitation allows an attacker to:

- Execute arbitrary JavaScript in the administrator’s browser.

- Steal administrator cookies or session tokens.

- Perform actions on behalf of the administrator (privilege escalation).

- Potentially gain full control of the WordPress site.

## Mitigation
Until a patch is released, it is recommended to:

- Restrict ticket submission to authenticated and trusted users only.

- Sanitize and escape all user input before rendering in HTML.

- Use WordPress functions like esc_html() and wp_kses() when outputting dynamic content.

## Timeline
2025-08-09 — Vulnerability discovered.
2025-08-09 — Vendor notified.
Pending — Vendor response.
Pending — CVE assignment.

## References

CWE-79: https://cwe.mitre.org/data/definitions/79.html

OWASP XSS Prevention Cheat Sheet: https://owasp.org/www-community/xss-prevention
