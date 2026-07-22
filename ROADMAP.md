# MapSec Roadmap

Future features and improvements planned for the project.

---

## Phase 1: Core Plugins + Tests ✅
- [x] **Whois** — domain/IP registration info (pure Python, socket)
- [x] **Banner Grabbing** — collect service banners from open ports
- [x] **Unit Tests** (pytest) — tests for plugins, engine, models

## Phase 2: Security Plugins + Analysis ✅
- [x] **SSL/TLS Check** — certificate analysis, protocols, vulnerabilities
- [x] **HTTP Headers** — security headers check (CSP, HSTS, X-Frame-Options, etc.)
- [x] **Security Analysis Engine** — automatic rules-based + optional LLM analysis

## Phase 3: Export & Reports ✅
- [x] **HTML Report** — professional dark-theme report with collapsible sections, SVG score gauge
- [x] **PDF Export** — printable report via reportlab (title page, executive summary, findings table)

## Phase 4: Threat Intelligence + i18n ✅
- [x] **Shodan** — IoT/device search on exposed services
- [x] **CVE Lookup** — vulnerability database integration (NVD API)
- [x] **i18n** — English + Portuguese (BR) translation system
- [x] **CVE Translation** — auto-translate CVE descriptions via Google Translate (deep-translator)

## Phase 5: Scan Management
- [ ] **Scan Profiles** — quick / full / stealth presets
- [ ] **Scan History** — save and compare results over time

## Phase 6: Polish & Distribution
- [ ] **Image Metadata (EXIF)** — extract and analyze EXIF data from images
- [ ] **Network Topology** — visualize discovered hosts/connections
- [ ] **CI/CD** — GitHub Actions for automated tests + build
- [ ] **PyPI Publishing** — `pip install mapsec`
