# Inspira CyberPulse advisory style guide

Derived from the published advisories TA02112026.01 – TA12112026.03. Build every advisory with
`python3 build_advisory.py spec.json out/` (see the docstring in the script for the spec format).
The script handles the cover, header banner, footer ID, fonts, colours, tables and numbering.

## Naming
- Advisory ID: `TA` + date `DDMMYYYY` + `.NN` (sequence for that day), e.g. TA14112026.01.
- File: `Inspira_CyberPulse_<ID>_<Title_With_Underscores>.docx` (the script does this).
- IOC file: `Inspira_CyberPulse_<ID>_<ShortName>_IOCs.xlsx` (set `ioc_name`, e.g. "AntiFox").
- Title: short headline in Title Case, e.g. "AntiFox AI Pentest Platform Abused to Steal AWS Secrets",
  "WordPress Core Upgrade-Window RCE (CVE-2026-119977) Actively Exploited".

## Threat advisory (type "threat") — section order
1. **Executive Summary** — one paragraph, plain language, key names in **bold**; then a `kv` table with rows
   such as Threat, Research (who + date), Infrastructure, Initial Access, Actions Taken, Impact Seen, Speed,
   Vendor Position, Business Impact (use the rows that apply).
2. **Advisory Overview** — `h3` "Why This Matters" (or "Why This Campaign Matters" / "What Makes X Different"),
   bullets with a **Bold Lead:** then explanation; `h3` "Attack Chain", bullets `**Stage**: what happens`.
3. **Targeted Environments** or **Affected Systems** — bullets or a `kv` table.
4. **Technical Analysis** — `h3` per phase (e.g. Exploitation and Payload Delivery, Encryption, Exfiltration),
   each followed by bullets. Optional `h3` "MITRE ATT&CK Mapping" with a table Tactic | Technique | ID.
5. **Recommendations Action Steps** — `h3` "Immediate Action" + `numbered` list; `h3` "Hardening
   Recommendations" + `numbered` list. Each item `**Bold Lead:** sentence.`
6. **References** — `refs`, URL as the text.
IOCs go only in the separate Excel file.

## Vulnerability advisory (type "vulnerability") — section order (headings are auto UPPER-CASED)
1. **Summary** — paragraph (CVE in **bold**), then `kv` table (Item | Status) with Vulnerability, Severity,
   Affected, Impact, Exploitation, Fix, (Workaround). For multi-product roundups use a `table`
   Product | Vulnerability | Severity | Exploited | Fixed in.
2. **Key Findings (as of DD Mon YYYY)** — `table` Date | Finding, newest first.
3. **Vulnerability Details** — `table` CVE | CVSS | Weakness | Summary; optional `h3` sub-heading such as
   "When a site can be exploited" / "How the attacks work" with bullets.
   Roundups: one section per product ("GOOGLE CHROME: EXPLOITED ZERO-DAY") with its own tables.
4. **Affected Products and Fix** / **Fixed Releases** — `table` Branch/Product | Affected | Fixed (+ Note).
5. Optional: **Mitigation** / **Contingency Controls** — paragraphs and `code` blocks (config snippets).
6. **Recommendations** — `numbered`, each `**Short imperative.** Detail.`
7. **References** — `refs` with text "Source: Article title".
8. Optional: **Appendix (Reference Use Only)** — `h3` e.g. "HUNTING AND SITE CHECKS", a short paragraph,
   then numbered `code` blocks (label "1. Web logs: what it finds").

## Writing rules (reviewer feedback)
- Audience is CISOs / executives: executive summary short, minimal jargon.
- Threat-hunting queries are behaviour-based, never IOC-based.
- No labels like "(Inspira analyst assessment)". Never name a paid intel feed.
- British spelling (organisation, catalogue). Dates as "12 Nov 2026".
- Only state facts found in the sources; say "not disclosed" / "no CVE assigned yet" where unknown.
- Follow-up advisories are standalone: mention the earlier advisory ID in the summary only; include only new info.

## IOC workbook
Single sheet "IOCs", columns IOC Type | IOC (Defanged) | Context. Context starts with the source, e.g.
"Arctic Wolf Labs: Alibaba Cloud host running AntiFox console". Types: IPv4, Domain, URL, Onion domain,
MD5, SHA1, SHA256, Port, Email, File name. Defang: `1[.]2[.]3[.]4`, `hxxps://evil[.]com`, `evil[.]com`.
Hashes are not defanged.

## Sources the watcher checks
- News homepages: The Hacker News, CyberPress, BleepingComputer, SecurityWeek.
- CISA KEV via the GitHub mirror `cisagov/kev-data` (`known_exploited_vulnerabilities.json`); KEV items are stored in
  state as `kev:<CVE-ID>`. A new KEV addition is at least High priority.
- CERT-In vulnerability notes (CIVN-YYYY-NNNN): morning run only, best effort via web search.
- Fetched only while drafting: vendor advisories, researcher blogs (Unit 42, Talos, Google Threat Intelligence/Mandiant,
  Microsoft Threat Intelligence, Huntress, Arctic Wolf, Rapid7, watchTowr), IOC lists on GitHub.
