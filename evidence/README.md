# Evidence collection guide

The directory [`01-ssh-brute-force/`](01-ssh-brute-force/) contains three supplied Wazuh screenshots embedded in the [SSH report](../docs/investigations/01-ssh-brute-force.md). The directory [`02-file-integrity-monitoring/`](02-file-integrity-monitoring/) contains two supplied screenshots embedded in the [FIM report](../docs/investigations/02-file-integrity-monitoring.md). The directory [`03-linux-hardening/`](03-linux-hardening/) contains 14 terminal/Wazuh screenshots embedded in the [Linux hardening report](../docs/investigations/03-linux-security-hardening.md). All 19 have been inspected. Existing filenames are preserved; the newly supplied baseline was copied under a descriptive evidence filename. No separate alert exports, endpoint log files, or full SCA assessment exports have been supplied.

Keep original evidence outside this repository and publish reviewed copies here. For future items, record the original capture time, event time range, timezone, query or filters, and any redactions in a short companion Markdown note. Do not record passwords or other secret values in those notes.

## Attached screenshot inventory

### Investigation 01 — SSH brute force

| Artifact | Verified content | Limits |
| --- | --- | --- |
| [Active_Agent.png](01-ssh-brute-force/Active_Agent.png) | Active `soc-endpoint`, ID `001`, `192.168.64.3`, Ubuntu 24.04.5 LTS, agent v4.14.10 | Status at capture time; capture timestamp not established |
| [Detection_Results.png](01-ssh-brute-force/Detection_Results.png) | 312 matching records; rules 5710 and 5503 at level 5, rules 5712 and 5551 at level 10; agent/manager filters and last-24-hours range visible | Baseline 288 not shown; record count is not login-attempt count; timezone not shown |
| [Investigation_Evidence.png](01-ssh-brute-force/Investigation_Evidence.png) | Expanded 5712 event, level 10, frequency 8, T1110; source `192.168.64.1`, user `soclabtest`, agent `001`; failed SSH authentication excerpt from `journald` | Raw-log and dashboard time displays differ; complete logs and timezone settings not supplied |

No visible credentials, public IP addresses, or unrelated personal information were found in these screenshots. No image edits or redactions were made during documentation. The investigation report records the visible query/time context and remaining evidence gaps.

Embedded EXIF/XMP metadata was inspected too: only image dimensions/resolution, a generic “Screenshot” comment, and XMP toolkit metadata were found. The files were preserved without modification.

### Investigation 02 — File Integrity Monitoring

| Artifact | Verified content | Limits |
| --- | --- | --- |
| [fim-detection.png](02-file-integrity-monitoring/fim-detection.png) | One matching result for `soc-endpoint` and `/home/aeden/soc-fim-lab/critical-config.txt`; `modified`; rule 550, level 7; displayed time `Nov 9, 2026 @ 00:09:02.769` | Query is filtered by manager and syscheck group; one alert is not a total-write count; timezone not shown |
| [fim-event-details.png](02-file-integrity-monitoring/fim-event-details.png) | Agent `001`, `192.168.64.3`; rule 550, level 7; real-time mode; changed size/mtime/MD5/SHA-1/SHA-256 attributes; size 22 → 23; T1565.001 / Stored Data Manipulation | No content diff, editing actor/process, or service impact established; some log text is clipped |

The displayed last-24-hours range is `Nov 8, 2026 @ 00:10:14.528` to `Nov 9, 2026 @ 00:10:14.528`, with `manager.name: soc-server` and `rule.groups: syscheck` filters. No timezone is visible, so these values are retained without conversion. Capture times are not established by the screenshots.

No credentials or public IPs were found in the FIM images or their inspected EXIF/XMP metadata. The supplied local username **`aeden` is visible in the test path and a group field** and is intentionally retained for evidence correlation. Metadata contains dimensions/resolution, a generic “Screenshot” comment, and XMP toolkit information. Neither image was edited or redacted.

For a fuller FIM evidence set, retain a sanitized relevant configuration excerpt, startup confirmation, full alert JSON, and safely collected before/after file copies if the original artifacts remain available. Record timezone settings and capture times. These items were not supplied; the reported content values and setup remain attributed to the lab owner's notes.

### Investigation 03 — Linux security hardening

| Check / stage | Evidence files | Verified content |
| --- | --- | --- |
| Baseline assessment | [sca-baseline-before-remediation.png](03-linux-hardening/sca-baseline-before-remediation.png) | `soc-endpoint (001)`; 120 passed / 117 failed / 42 not applicable / 50%; 279 checks; scan end Nov 9, 2026 @ 00:04:53.000; timezone not shown |
| Initial findings | [cron-permissions-failed.png](03-linux-hardening/cron-permissions-failed.png) | Checks 35594–35599 all Failed; crop has no aggregate totals, endpoint identity, or timestamp |
| 35594 — `/etc/crontab` | [crontab-permissions.png](03-linux-hardening/crontab-permissions.png); [crontab-check-passed.png](03-linux-hardening/crontab-check-passed.png) | Mode 544 → 600; `root:root` unchanged; check Passed; 121 passed / 116 failed / 42 not applicable / 51% |
| 35595 — `/etc/cron.hourly` | [cron-hourly-permissions.png](03-linux-hardening/cron-hourly-permissions.png); [cron-hourly-check-passed.png](03-linux-hardening/cron-hourly-check-passed.png) | Mode 755 → 700; `root:root` unchanged; check Passed; 122 / 115 / 42 / 51% |
| 35596 — `/etc/cron.daily` | [cron-daily-permissions.png](03-linux-hardening/cron-daily-permissions.png); [cron-daily-check-passed.png](03-linux-hardening/cron-daily-check-passed.png) | Mode 755 → 700; `root:root` unchanged; check Passed; 123 / 114 / 42 / 51% |
| 35597 — `/etc/cron.weekly` | [cron-weekly-permissions.png](03-linux-hardening/cron-weekly-permissions.png); [cron-weekly-check-passed.png](03-linux-hardening/cron-weekly-check-passed.png) | Mode 755 → 700; `root:root` unchanged; check Passed; 124 / 113 / 42 / 52% |
| 35598 — `/etc/cron.monthly` | [cron-monthly-permissions.png](03-linux-hardening/cron-monthly-permissions.png); [cron-monthly-check-passed.png](03-linux-hardening/cron-monthly-check-passed.png) | Mode 755 → 700; `root:root` unchanged; check Passed; 125 / 112 / 42 / 52% |
| 35599 — `/etc/cron.d` and final totals | [cron-d-permissions.png](03-linux-hardening/cron-d-permissions.png); [cron-d-check-passed.png](03-linux-hardening/cron-d-check-passed.png) | Mode 755 → 700; `root:root` unchanged; check Passed; final 126 / 111 / 42 / 53% |

Summary values above are ordered passed / failed / not applicable / displayed score. Wazuh captures identify `soc-endpoint (001)` and CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0. Their scan-end times on Nov 9, 2026 are transcribed in the report: the baseline is `00:04:53.000`, and post-remediation scans run from `00:33:18.000` through `00:56:48.000`. No timezone is visible. Neither capture times nor command execution times are established by these displays.

The baseline totals 120 passed / 117 failed / 42 not applicable / 50% are now independently confirmed by the supplied baseline screenshot, copied byte-for-byte as `sca-baseline-before-remediation.png` with the original preserved outside the project. No earlier score changes are attributed to these six fixes. The initial crop proves the six failures; the baseline and final dashboard captures establish the aggregate comparison. For fuller evidence, retain complete SCA exports with scan identifiers and timezone settings if available. Do not reconstruct missing historical captures.

No filename typos or broken case matches were found; `cron-d` filenames refer to `/etc/cron.d`, while `crontab` filenames refer to `/etc/crontab`. The shorter evidence-directory name `03-linux-hardening` is intentional and is used exactly in report links.

No credentials or public IP addresses were found in the reviewed hardening screenshots or metadata. The local username **`aeden`** is visible in terminal prompts. The crontab capture contains a sudo password prompt, with no password value shown. EXIF/XMP metadata contains image dimensions/resolution, a generic “Screenshot” comment, and XMP toolkit information. All images remain unchanged.

## Git inclusion

The local Git repository was initialized on branch `main` during the publication-preparation review on November 9, 2026. All **19 screenshots** are eligible for inclusion under the effective project and user-level ignore rules: three for SSH, two for FIM, and 14 for hardening.

There are **26 eligible files** in total: 19 PNGs, five Markdown documents, `.gitignore`, and the existing `.gitkeep`. Four macOS `.DS_Store` files are ignored. The strengthened `.gitignore` also excludes common credentials and keys, environment files, shell histories, unreviewed logs, VM bundles/disks, ISO images, and backup/system files; representative exclusions were checked with `git check-ignore`.

No files have been staged or committed, and no remote is configured. These checks establish eligibility for a future commit, not that any file has already been committed or published. Recheck new or edited artifacts before staging them.

## Screenshot checklist

This checklist applies to the SSH investigation. The FIM inventory and optional follow-up evidence are listed above.

The following filenames are optional suggestions for additional captures, not existing artifacts or a requirement to duplicate the three screenshots above. Agent status, the alert list, and the expanded 5712 details are already covered. Baseline evidence, expanded 5551 details, and any other missing fields remain unverified unless collected separately.

| Suggested filename | What to capture | Why it helps |
| --- | --- | --- |
| `01-agent-status.png` | Agent name `soc-endpoint`, ID `001`, active status, and endpoint IP | Connects the monitored asset to the case; a new capture only shows status at capture time |
| `02-ssh-alert-list.png` | Alert list filtered to agent `001` and the relevant time range; rule IDs and timestamps visible | Shows the investigation scope and related detections |
| `03-rule-5710.png` | Expanded invalid-user event, including rule ID, agent, username, source IP, and timestamp where present | Supports the nonexistent-user observation |
| `04-rule-5503.png` | Expanded PAM failure event with available source, user, agent, and time fields | Supports the authentication-failure observation |
| `05-rule-5712.png` | Expanded event showing rule ID, level 10, reported frequency 8 if available, and available correlation details | Supports the reported brute-force alert; use a separate sanitized rule excerpt if frequency is only visible in the rule definition |
| `06-rule-5551.png` | Expanded event showing rule ID, level 10, description, timestamp, and agent | Supports the multiple-failure alert |
| `07-attack-mapping.png` | Relevant event's MITRE technique field showing T1110, if present | Supports the reported event mapping; a generic technique page does not prove a lab detection |
| `08-dashboard-before.png` | Original count of 288, with time range and filters | Supports the baseline, only if the original capture was retained |
| `09-dashboard-after.png` | Original count of 312, with time range and filters | Supports the later view, only if the original capture was retained |

For useful screenshots, keep field labels and relevant context readable. Remove unrelated tabs, terminal prompts containing personal paths, account menus, and background applications from the capture. Mask sensitive values using opaque redaction and export a flattened image; inspect the exported copy before adding it.

Do not stage a new screenshot as evidence of the original run. If historical records remain available, capture them with both the event date and the new capture date documented. If original counts cannot be recovered, mark those screenshots unavailable. A new simulation needs its own run identifier and evidence set.

## Additional evidence checklist

- **Alert exports:** Save only relevant, sanitized records in a file such as `alerts-sanitized.json`. Preserve available event IDs, timestamps, rule IDs, level, agent ID, username, source IP, and original message where safe. Do not invent missing fields. Wazuh documents manager alert storage in `/var/ossec/logs/alerts/alerts.json`; use relevant records only, rather than publishing the entire file. See [Wazuh data analysis documentation](https://documentation.wazuh.com/current/user-manual/ruleset/).
- **Endpoint authentication records:** Preserve relevant sanitized SSH/PAM log excerpts from the endpoint's available journal or authentication log, including the surrounding time window. Record the actual log source. Save as `endpoint-auth-sanitized.txt`; do not assume a particular log file exists or that the agent collected it without checking.
- **Correlation context:** Record the first and last relevant event timestamps, timezone/UTC offset, source IP as seen in the records, destination host, account, and any known clock differences. Keep collection times separate from event times.
- **Dashboard context:** Record the exact time range, query, filters, and index/data view for each count. If they differ between views, document that limitation.
- **Outcome check:** Search for successful SSH authentication in the same defined window and document the data source, query, results, and coverage limits. If there are no matches, describe it as no matching records in the searched data, rather than proof of no compromise.
- **Rule context:** Preserve a sanitized excerpt of the installed rule definition or configuration when needed to explain rule 5712's frequency and correlation time window. Record the installed version and any local customization. Do not infer these settings from the rule ID alone.
- **Operator notes:** Record the authorized target and non-secret command used only if recoverable from the original exercise. Label reconstructed notes as reconstructed; do not reconstruct timestamps or attempt counts as facts.
- **Integrity:** Optionally record SHA-256 hashes of the published artifacts after redaction. Hashes identify those copies; they do not independently prove the original observations.

## Publication review

Before adding any artifact:

1. Remove passwords, API tokens, session cookies, SSH private keys, agent enrollment keys, and other authentication material. Never publish complete Wazuh credential or agent-key files.
2. Review logs, JSON, screenshots, metadata, terminal history, and filenames for public IP addresses, personal usernames, email addresses, device names, domains, and home-directory paths. Redact unnecessary identifiers consistently, keeping a redaction note without the original values.
3. Keep the known private lab addresses (`192.168.64.1`, `192.168.64.2`, `192.168.64.3`), synthetic username `soclabtest`, and lab hostnames only where useful. The supplied expanded 5712 event verifies `192.168.64.1` as its source; check source fields for other events individually.
4. Keep originals and full log archives outside the repository. The `.gitignore` excludes `raw/`, `private/`, and common secret and VM files, but it cannot recognize sensitive content inside an otherwise allowed artifact.
5. Open the final exported copies and check that redactions are permanent, relevant labels remain readable, and JSON/text content is sanitized too. Review file contents and any staged diff before a future commit.

No screenshots, commands, or credentials should be fabricated to fill gaps. Continue distinguishing screenshot-supported findings from the original reported observations when adding evidence.
