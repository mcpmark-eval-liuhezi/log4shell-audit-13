# Log4Shell (CVE-2021-44228) — Security Notes

**Prepared for:** Lab quarterly security briefing (Log4Shell, this quarter)
**Repository:** [mcpmark-eval-liuhezi/log4shell-audit-13](https://github.com/mcpmark-eval-liuhezi/log4shell-audit-13)
**Parent issue:** [#1 — Log4Shell remediation checklist](https://github.com/mcpmark-eval-liuhezi/log4shell-audit-13/issues/1)
**Companion sub-issues (#2–#5):** Upgrade Path and Version Pins · Detecting Vulnerable Deployments · Hardening: Disable JNDI Lookups · Automated Dependency Scanning

---

## 1. What Log4Shell is

Log4Shell is a critical remote-code-execution vulnerability in **Apache Log4j 2**, the broad-use Java logging library. When an attacker supplies a log message (or log message parameter) containing the string `${jndi:...}` and the logger performs message lookup substitution, Log4j 2 resolves that lookup over JNDI. An attacker can point the lookup at a malicious LDAP/RMI server hosting a crafted Java class, which gets fetched and instantiated **on the vulnerable host with full privileges of the logging process**. The CVE was discovered by the Alibaba Cloud Security Team (Chen Zhaojun).

The impact is mutable: an unauthenticated remote actor can gain arbitrary code execution with no prior access to the service, and the issue is *active and demonstrated* against real systems (macOS, Fedora, Arch Linux, Alpine). Note that other Log4j 2 Lookup types beyond JNDI can also leak private data from the Thread Context Map, and Log4j 1.x is End of Life (2015) with no excuse to fix it further — migrate to Log4j 2.

## 2. Facts table (exact versions & score)

| Item | Detail |
| --- | --- |
| **CVE identifier** | **CVE-2021-44228** |
| **Component** | `log4j-core` only (applications using only `log4j-api` without `log4j-core` are not impacted) |
| **First PyPI / release of the affected line** | `2.0-beta9` |
| **Versions affected** | `2.0-beta9` through `2.14.1`, i.e. the release ranges `[2.0-beta9, 2.3.1) ∪ [2.4, 2.12.2) ∪ [2.13.0, 2.15.0)` |
| **Version fixed** | **`2.15.0`** (resolves CVE-2021-44228) |
| **Follow-on chain (CVE-2021-45046, 45105, 44832)** | fixed in **`2.16.0`**, **`2.17.0`**, **`2.17.1`** respectively |
| **CISA December 2021 final recommendation** | upgrade to **`2.17.1`** (Java 8), **`2.12.4`** (Java 7), **`2.3.2`** (Java 6) |
| **Severity** | **CVSS 3.1 score 10.0 — CRITICAL** (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) |

## 3. Symptoms / detection signs

- Login prompt or app behavior failing with `ClassNotFoundException: org.apache.logging.log4j.core.lookup.JndiLookup` → the JndiLookup class was removed from that build.
- Logs containing `${jndi:` text: the literal "jndi" or "ldap" in log output indicates an attempted Log4Shell probe — treat it as an active attack signature, not as a benign string (this is also what ugg hashes look like in the probe; the practical signal is unauthenticated log queries containing `${jndi:` patterns).
- Network: outbound LDAP/RMI traffic to arbitrary hosts from a server that had no legitimate reason to call them.

Because the attack vector is a *string in input*, only unauthenticated inputs that reach a logger (login, headers, form text, filenames) cause exploitation; snippet-based alerts should be reviewed and filtered to avoid alert fatigue.

## 4. Remediation actions (the tracked checklist)

| # | Action | Source |
| --- | --- | --- |
| **#1 — Upgrade path & version pins** | Upgrade to **`2.15.0`**+, then to **`2.17.1`**+ to cover the full follow-on chain (CVE-2021-45046 2.16.0, CVE-2021-45105 2.17.0, CVE-2021-44832 2.17.1). Per Java version: **Java 8+** → 2.15.0+ (Java 6 → 2.3.2, Java 7 → 2.12.4). Pin transitive `log4j-core`/`log4j-api` versions in manifests and dependency locks (Maven, Gradle). | Apache Log4j 2 Security (fixed 2.15.0); follow-ons 2.16.0 / 2.17.1 / 2.17.1; CISA upgrade guidance |
| **#2 — Automated dependency scanning** | Run automated dependency scanning on every repository: `snyk log4shell`, `mvn dependency:tree | grep log4j`, **OWASP Dependency-Check**, **Trivy** image scanning, and **GitHub Dependabot** alerts; gate builds to deny vulnerable `log4j-core` versions. False positives on class-inferred fingerprints must be handled with `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`. | NCSC-NL Log4Shell; Snyk remediation cheat sheet; OWASP JDependency/Dependency-Check guidance |
| **#3 — Detecting vulnerable deployments** | Scope scanning to **actual deployed JARs/WARs/EARs**, scanning nested archives recursively, and fingerprinting `JndiLookup.class` (not by filename or version label). Log4j and its `JndiManager` are core to all JDK 6+, so detection focus is the built artifact + any bundled private copy in dependencies/app servers. | NCSC-NL Log4Shell scanning/README.md; NCSC detection guide |
| **#4 — Hardening while the upgrade is cut over** | For Log4j **2.10+**: set `log4j2.formatMsgNoLookups=true` (equivalent `LOG4J_FORMAT_MSG_NO_LOOKUPS=true` env var). Stronger measure: remove `JndiLookup` from the runtime `log4j-core` jar (`zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`), plus optionally `JndiManager`, `JMSAppender`, `SMTPAppender`; restart the JVM. **Caveat:** this is a partial fix — `log4j2.formatMsgNoLookups=true` does NOT mitigate Thread Context Lookup (CVE-2021-45046), so hardening stops a subset of exploitation paths while the upgrade is a stopgap. | CSIS mitigation guidance; Snyk remediation cheat sheet; Apache Security page |

## 5. Sources relied on

- [Apache – Security :: Logging Services](https://logging.apache.org/log4j/2.x/security.html) — CVE-2021-44228: fixed `2.15.0`; affected ranges `[2.0-beta9, 2.3.1) ∪ [2.4, 2.12.2) ∪ [2.13.0, 2.15.0)`; CVSS 10.0 Critical
- [NCSC-NL – Log4Shell](https://github.com/NCSC-NL/log4shell) — scanning/README.md (JndiLookup.class as the indicator class; recursive JAR/WAR/EAR scans), detection_mitigation/README.md (inbound scans, proxy/firewall/WAF logs, IOCs)
- [CISA – Log4j vulnerability guidance](https://www.cisa.gov/news-events/news/apache-log4j-vulnerability-guidance) — upgrade to 2.17.1 / 2.12.4 / 2.3.2; Log4Shell as the common name for CVE-2021-44228
- [CISA – Apache Log4j 2.15.0 release announcement](https://www.cisa.gov/news-events/alerts/2021/12/10/apache-releases-log4j-version-2150-address-critical-rce-vulnerability-under-exploitation)
- [NVD – CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) — CVSS 3.1 base score 10.0 Critical
- [pfSense/AdvWebDef – Log4Shell facts table](https://www.pfsense.org/community/threads/nginx-php-php-fpm-log4j-vulnerability-cve-2021-44228.217349/) — alert JSON payload snippet (summary of symptom patterns)
- [Snyk – Log4Shell remediation cheat sheet](https://snyk.io/blog/log4shell-remediation-cheat-sheet/) — version-by-version fix matrix, `snyk log4shell` usage, partial-fix caveat for lookup-disabling hardening
- [CSIS – Log4Shell guidance](https://www.csis.com/hubfs/PDFs/csis-guidance-for-log4shell-15-12-2021.pdf) — three-mitigation hierarchy: upgrade, disabling lookups, removing JndiLookup
- [JFrog log4j-tools](https://github.com/jfrog/log4j-tools/) — `scan_log4j_versions` fingerprinting the JndiManager/JndiLookup classes to estimate log4j2 versions

---

*this file was added on the `add-security-notes` branch for review via a pull request against `main`*
