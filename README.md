# A series of PortSwigger Web Academy lab writeups from an AppSec perspective and secure coding focus

This repository contains a curated collection of writeups for PortSwigger Web Security Academy labs — but with a twist.
Most public writeups focus only on exploitation: how to reproduce a vulnerability, craft the payload, and complete the lab. This repo goes further.

Each writeup breaks down:
🔍 What’s actually happening in the backend code:
- Likely source-code patterns that caused the vulnerability
- Framework-specific issues (PHP, Java, Python, Node.js, etc.)
- Misconfigurations and insecure defaults

🛠️ How to fix it using secure coding best practices:
- Proper input validation & output encoding
- Correct use of frameworks and libraries
- Recommended configuration changes
- Examples of safe patterns vs. vulnerable ones
- Architecture security improvements

🎯 Who is this for?
- AppSec engineers
- Security-minded developers
- OSWE / HTB / red-blue hybrid learners
- Anyone who wants not only to hack the labs but also to understand and prevent these vulnerabilities in real software

📘 What you’ll find here
- Clear exploitation walkthroughs (short, focused)
- Code-level analysis of why the bug exists
- Secure-by-design remediation guidance
- Complete exploitation scripts
- References to standards: OWASP ASVS, Top 10, secure coding guides
- Occasional threat-modeling insights

This repository is meant to bridge the gap between offensive testing and defensive engineering — turning each lab into a practical lesson in building and maintaining secure applications.
