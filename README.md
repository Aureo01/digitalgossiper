# DigitalGossiper 

Advanced Web Reconnaissance & Intelligence Engine  

Not just scanning.  
Understanding.

---

## What is DigitalGossiper?

DigitalGossiper is an advanced reconnaissance engine designed to extract:

- Structural intelligence
- Internal logic
- Technology stack
- Security posture
- Hidden attack surface

It doesn’t just ask *“Is it up?”*  
It asks:

> “How is this application built, protected, and exposed?”

---

## Core Capabilities

###  Technology Fingerprinting

Identifies:

- Web servers (Apache, Nginx, IIS, etc.)
- Backend technologies (PHP, ASP.NET, Node.js, Python)
- Frontend frameworks (React, Vue, Angular)
- CMS indicators (e.g., WordPress)
- CDN and infrastructure hints

---

###  WAF & CDN Detection

Detects protection layers such as:

- Cloudflare
- CloudFront
- Basic WAF signatures

Includes protection confidence and inferred protection level.

---

###  Cookie Intelligence

Analyzes cookies for:

- Session identifiers
- Auth-related cookies
- Internal/debug cookies
- Security flag presence

Helps assess session handling exposure.

---

###  CSP & Security Headers Analysis

- Parses Content Security Policy
- Scores strength (weak / moderate / strict)
- Extracts directive structure

Useful for understanding client-side security posture.

---

###  Logical Structure Extraction

Parses HTML and identifies:

- Login endpoints
- Admin/dashboard references
- API routes
- External domains
- Embedded JS files
- HTML comments

Because the frontend leaks architecture.

---

###  JavaScript Intelligence Extraction

Downloads JS files and extracts:

- Hidden API endpoints
- Versioned routes (/v1/, /api/, /rest/)
- Potential API keys / tokens
- Internal domains

This is where modern apps expose their logic.

---

###  Path Enumeration

Scans common sensitive paths like:

- /admin
- /api
- /config
- /backup
- /debug
- /logs
- /env
- /dashboard

Returns valid responses including:
200, 301, 302, 403, 405

---

###  Infrastructure Intelligence

- IP resolution
- Basic SSL certificate inspection
- CDN inference
- Reverse DNS
- Basic provider hints

---

## Usage

Scan a single target:

```bash
- python3 digitalgossiper.py example.com

Interactive mode (manual input):

- python3 digitalgossiper.py 


