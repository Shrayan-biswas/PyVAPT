# Changelog

## 1.0.0
- Single-file Flask app automating the non-intrusive parts of a 12-phase website VAPT workflow.
- Modules: recon, security headers, TLS, CORS, HTTP methods, endpoint crawler, directory audit,
  API probe, frontend/JS audit, cookie audit, optional whatweb / nmap / nikto / sslscan.
- Multi-threaded scanning with a shared global rate limiter, Stop button and progress bar.
- CVSS 3.1 scoring, persistent findings register with remediation / retest statuses.
- Separate findings, scan history and reports per target.
- Reports named `<target>_VAPT_Report` in HTML, PDF and JSON.
- Manual-testing checklists for authentication, authorization, injection and validation phases.
- Black and white (grayscale) UI and print-friendly grayscale reports.
- Animated monochrome interface (rotating rings that speed up during a scan, hairline layout, invert toggle, reduced-motion support).
- Credit and MIT license in the app header, footer, reports, JSON output and source.
