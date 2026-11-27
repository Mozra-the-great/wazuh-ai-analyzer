# Severity calibration

The model (LLM mode) or the thresholds (decision mode) rate what an alert *says*.
They cannot see what it is *about*: a scheduled file-integrity change after a package
upgrade looks like tampering, a vulnerability alert for a package that was just updated
looks like a live CVE, a dpkg state in the middle of an upgrade looks like a broken
package. `analysis/calibration.py` checks every finding of every backend against facts
of the batch and of the last day, and only ever **lowers** a severity.

Rules that hold for every check:

* Nothing is dropped. A downgraded finding keeps its place, its title and its
  rule ids. The reason is appended to the description (`Automatische
  Plausibilitätsprüfung: ...`), the check that settles the question is put in front of
  the recommendation, and in decision mode the change is recorded in
  `findings.decision["calibration"]` (`rule`, `from`, `to`).
* Evidence of tampering switches a check off. Missing data does as well: a group
  without facts is never downgraded, and a group whose facts were cut off counts as
  unknown wherever the cut-off part could matter (see "Facts").
* A failing check never fails the batch; the pipeline keeps the backend's result and
  logs the error. Every change is logged at INFO (`Calibration: ... (tag)`).
* After a downgrade `overall_risk` may not stay above the most severe finding left, and
  the summary says how many findings were lowered.

## Facts

`ingest/sanitize.group_alerts` adds a `facts` list (at most 60, plus `facts_more` for
the number that did not fit) to the groups of three alert families. Groups of all other
alerts are exactly the groups of `analyzer.py`. Every value is whitelisted or cleaned;
the facts are stored in `batches.raw_groups` and read back through `sanitize_group`.

| kind | source | fields |
|------|--------|--------|
| `fim` | top-level `syscheck` object | `path`, `ev` (added/modified/deleted), `mode`, `chg` (changed attributes), `ind` (indicator, see below) |
| `pkg` | alerts of a `dpkg.log` source (status and action lines) | `pkg`, `st` (state or action), `ver`, `ts` |
| `vuln` | `data.vulnerability` of alerts from `vulnerability-detector` | `cve`, `sev`, `status`, `pkg`, `ver`, `cond` |

The dpkg and vulnerability facts are only built from the log source that really writes
them: the same words in any other log are attacker-writable and give no fact.
When a group has more facts than the cap, the ones that speak against a downgrade are
kept first, also while the alerts are being grouped: file changes with an indicator, the
most severe CVEs, unfinished package states. An indicator or a critical CVE can
therefore never be pushed out by ordinary facts that came earlier. `facts_more` counts
what was left out, and a group with `facts_more` is treated as incomplete where the
missing part matters: no CVE severity from the facts (the rule decides), no `info` for a
package list, no "no package activity" cap for file changes.

## File integrity (#118)

Applies to a finding whose rules are all syscheck rules with facts. Nothing happens if
any file change has an **indicator**: a sensitive path (`authorized_keys`, `sudoers`,
`/etc/ssh`, PAM, `passwd`/`shadow`, cron, systemd units, ...), a path no package installs
to (`/tmp`, `/home`, `/usr/local`, `/opt`, Windows paths), a change of owner, permissions
or attributes, a changed hash without a changed size or mtime, or a modification without
known changed attributes. The same holds if another alert of level 12 or higher exists
for the same agent in the batch.

Without indicator:

* package activity on the agent (any dpkg fact in the batch or in a batch of the last
  24 hours): at most `medium`, recommendation starts with `dpkg -V <package>`;
* no package activity, scheduled mode, path outside the system binary directories: at
  most one step above the rule level (level 7 = `medium`, so `high`);
* no package activity in any other case (in particular a program or library in a
  system directory): the rating stays as it is.

Limit: the check cannot tell which package owns a file. A trojaned binary replaced
during an unrelated upgrade on the same agent is capped at `medium` and the
recommendation tells the reader to verify it with `dpkg -V` first.

## Vulnerabilities (#119)

Applies to a finding whose rules are all vulnerability rules.

* The finding is capped at the most severe CVE it covers (`sev` of the facts, else the
  rule: 23504 medium, 23505 high, 23506 critical). Only a critical CVE yields `critical`.
* All CVEs `Solved`: `info`.
* A CVE with the condition `Package default status` (no fixed version recorded) gets
  a note and the first recommendation "compare the installed version with the
  distribution's security tracker".
* If every such CVE is for a package version the package manager installed in the last
  24 hours: at most `medium` (probable feed lag).

## Transient dpkg states (#120)

Applies to a finding whose groups only hold `half-configured`, `half-installed`,
`unpacked`, `triggers-pending` or `triggers-awaited` facts. If every package has a
final state (`installed`, `not-installed`, `config-files`) at or after the transient one
for the same agent, in the batch or in a batch of the last 24 hours: `info`. Otherwise
the final state is unknown: at most `medium`, recommendation starts with
`dpkg --audit`. A list of packages that was cut off never gives `info`.

## Prompt

For batches with facts the LLM prompt gets the matching notes after the data block (so
the model rates correctly in the first place). A batch without facts gets the prompt of
`analyzer.py` unchanged.

## History

`Repository.recent_fact_batches` reads the `raw_groups` of the last 24 hours that
contain facts (no schema change). Backlog (`history`) batches are checked against their
own alerts only.
