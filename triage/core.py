from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import date

SEVERITIES = ["info", "low", "medium", "high", "critical"]  # lowest to highest


@dataclass(frozen=True)
class Finding:
    tool: str  # "semgrep" or "bandit"
    rule_id: str
    path: str  # normalised
    line: int
    severity: str  # one of SEVERITIES
    cwe: int | None
    message: str
    code: str  # source text of the finding's line, as reported by the tool


@dataclass
class Group:
    key: str  # the issue key shared by its findings
    path: str
    line: int
    severity: str  # highest severity among its findings
    findings: list[Finding] = field(default_factory=list)

    @property
    def tools(self) -> list[str]:
        return sorted({f.tool for f in self.findings})

    @property
    def fingerprints(self) -> list[str]:
        return sorted({fingerprint(f) for f in self.findings})


@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    reason: str
    expires: date
    by: str


# --------------------------------------------------------------------------
# paths and fingerprints
# --------------------------------------------------------------------------

def normalize_path(raw: str, project: str) -> str:
    p = (raw or "").replace("\\", "/")
    if p[:7].lower() == "file://":
        p = p[7:]
    segs = [s for s in p.split("/") if s not in ("", ".")]
    if project and project in segs:
        last = len(segs) - 1 - segs[::-1].index(project)
        segs = segs[last + 1:]
    return "/".join(segs)


def fingerprint(f: Finding) -> str:
    code = " ".join(f.code.split())
    raw = f"{f.tool}|{f.rule_id}|{f.path}|{code}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# loaders
# --------------------------------------------------------------------------

_LEVELS = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def _score(value) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        v = float(value)
    elif isinstance(value, str):
        try:
            v = float(value.strip())
        except ValueError:
            return None
    else:
        return None
    if v != v or not (0 < v <= 10):
        return None
    return v


def _score_to_severity(v: float) -> str:
    if v >= 9.0:
        return "critical"
    if v >= 7.0:
        return "high"
    if v >= 4.0:
        return "medium"
    return "low"


def load_semgrep_sarif(path: str, project: str) -> list[Finding]:
    with open(path, encoding="utf-8-sig") as fh:
        data = json.load(fh)
    findings: list[Finding] = []
    for run in data.get("runs") or []:
        rules_list = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
        rules = {r.get("id"): r for r in rules_list if isinstance(r, dict)}
        for res in run.get("results") or []:
            rid = res.get("ruleId")
            rule = rules.get(rid)
            if rule is None:
                idx = res.get("ruleIndex")
                if isinstance(idx, int) and 0 <= idx < len(rules_list):
                    rule = rules_list[idx]
                else:
                    rule = {}
            props = rule.get("properties") or {}

            score = _score(props.get("security-severity"))
            if score is not None:
                severity = _score_to_severity(score)
            else:
                level = res.get("level")
                if level is None:
                    level = (rule.get("defaultConfiguration") or {}).get("level")
                if level is None:
                    level = "warning"
                severity = _LEVELS.get(level, "medium")

            cwe = None
            for tag in props.get("tags") or []:
                m = re.match(r"CWE-(\d+)", str(tag))
                if m:
                    cwe = int(m.group(1))
                    break

            loc = (res.get("locations") or [{}])[0]
            phys = loc.get("physicalLocation") or {}
            uri = (phys.get("artifactLocation") or {}).get("uri", "")
            region = phys.get("region") or {}
            text = (region.get("snippet") or {}).get("text") or ""
            lines = text.splitlines()
            code = lines[0] if lines else ""

            findings.append(
                Finding(
                    tool="semgrep",
                    rule_id=rid,
                    path=normalize_path(uri, project),
                    line=int(region.get("startLine", 0)),
                    severity=severity,
                    cwe=cwe,
                    message=(res.get("message") or {}).get("text", ""),
                    code=code,
                )
            )
    return findings


def _bandit_code(block: str, line_number: int) -> str:
    for ln in (block or "").splitlines():
        num, _, rest = ln.partition(" ")
        if num.isdigit() and int(num) == line_number:
            return rest
    return ""


def load_bandit(path: str, project: str) -> list[Finding]:
    with open(path, encoding="utf-8-sig") as fh:
        data = json.load(fh)
    findings: list[Finding] = []
    for r in data.get("results") or []:
        sev = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(
            str(r.get("issue_severity", "")).upper(), "info"
        )
        if str(r.get("issue_confidence", "")).upper() == "LOW":
            sev = SEVERITIES[max(SEVERITIES.index(sev) - 1, 0)]

        cwe = None
        issue_cwe = r.get("issue_cwe")
        if isinstance(issue_cwe, dict) and issue_cwe.get("id") is not None:
            try:
                cwe = int(issue_cwe["id"])
            except (TypeError, ValueError):
                cwe = None

        line = int(r.get("line_number", 0))
        findings.append(
            Finding(
                tool="bandit",
                rule_id=r.get("test_id"),
                path=normalize_path(r.get("filename", ""), project),
                line=line,
                severity=sev,
                cwe=cwe,
                message=r.get("issue_text", ""),
                code=_bandit_code(r.get("code", ""), line),
            )
        )
    return findings


# --------------------------------------------------------------------------
# grouping
# --------------------------------------------------------------------------

def issue_key(f: Finding, equivalences: dict[str, str] | None) -> str:
    own = f"{f.tool}:{f.rule_id}"
    if equivalences and own in equivalences:
        return equivalences[own]
    if f.cwe:
        return f"CWE-{f.cwe}"
    return own


def dedupe(findings: list[Finding], equivalences: dict[str, str] | None = None) -> list[Group]:
    buckets: dict[tuple[str, int, str], list[Finding]] = {}
    for f in findings:
        buckets.setdefault((f.path, f.line, issue_key(f, equivalences)), []).append(f)

    groups: list[Group] = []
    for (path, line, key), members in buckets.items():
        members = sorted(members, key=lambda m: (m.tool, m.rule_id, fingerprint(m), m.message))
        top = max(members, key=lambda m: SEVERITIES.index(m.severity)).severity
        groups.append(Group(key=key, path=path, line=line, severity=top, findings=members))

    groups.sort(key=lambda g: (-SEVERITIES.index(g.severity), g.path, g.line, g.key))
    return groups


# --------------------------------------------------------------------------
# suppressions, baseline, gate
# --------------------------------------------------------------------------

_HEX64 = re.compile(r"[0-9a-f]{64}")


def load_suppressions(entries: list[dict]) -> tuple[list[Suppression], list[dict]]:
    valid: list[Suppression] = []
    invalid: list[dict] = []
    for e in entries:
        try:
            fp = e["fingerprint"]
            reason = e["reason"]
            by = e["by"]
            expires = e["expires"]
            if not (isinstance(fp, str) and _HEX64.fullmatch(fp)):
                raise ValueError("fingerprint")
            if not (isinstance(reason, str) and len(reason.strip()) >= 10):
                raise ValueError("reason")
            if not (isinstance(by, str) and by.strip()):
                raise ValueError("by")
            if not isinstance(expires, str):
                raise ValueError("expires")
            exp = date.fromisoformat(expires)
            valid.append(Suppression(fingerprint=fp, reason=reason, expires=exp, by=by))
        except Exception:
            invalid.append(e)
    return valid, invalid


def apply_suppressions(
    groups: list[Group], suppressions: list[Suppression], today: date
) -> tuple[list[Group], list[Group]]:
    live = {s.fingerprint for s in suppressions if s.expires >= today}
    active: list[Group] = []
    suppressed: list[Group] = []
    for g in groups:
        if any(fp in live for fp in g.fingerprints):
            suppressed.append(g)
        else:
            active.append(g)
    return active, suppressed


def diff_baseline(
    groups: list[Group], baseline: set[str]
) -> tuple[list[Group], list[Group], list[str]]:
    baseline = set(baseline)
    new: list[Group] = []
    existing: list[Group] = []
    seen: set[str] = set()
    for g in groups:
        fps = g.fingerprints
        seen.update(fps)
        if any(fp in baseline for fp in fps):
            existing.append(g)
        else:
            new.append(g)
    fixed = sorted(baseline - seen)
    return new, existing, fixed


def gate(new_active: list[Group], fail_on: str) -> bool:
    threshold = SEVERITIES.index(fail_on)
    return not any(SEVERITIES.index(g.severity) >= threshold for g in new_active)
