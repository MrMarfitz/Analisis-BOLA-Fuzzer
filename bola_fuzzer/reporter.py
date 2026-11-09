from datetime import datetime
from html import escape
from pathlib import Path

from bola_fuzzer.models import ScanFinding


HTML_HEAD = """<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BOLA Fuzzer Report</title>
  <style>
    :root { color-scheme: light; --ink:#172033; --muted:#667085; --line:#d8dee8; --bg:#f6f8fb; --panel:#ffffff; --danger:#b42318; --warn:#b54708; --ok:#067647; }
    body { margin:0; font-family: Arial, sans-serif; background:var(--bg); color:var(--ink); }
    header { background:#172033; color:white; padding:28px 36px; }
    main { max-width:1120px; margin:0 auto; padding:28px 24px 48px; }
    h1 { margin:0 0 6px; font-size:28px; }
    h2 { margin:0 0 14px; font-size:19px; }
    .meta { color:#d8dee8; margin:0; }
    .summary { display:grid; grid-template-columns:repeat(4, minmax(0, 1fr)); gap:12px; margin-bottom:18px; }
    .metric, .finding { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px; }
    .metric strong { display:block; font-size:24px; margin-top:4px; }
    .finding { margin:14px 0; }
    .row { display:flex; gap:10px; flex-wrap:wrap; margin:10px 0 14px; }
    .badge { border-radius:999px; padding:5px 9px; font-size:12px; font-weight:700; border:1px solid var(--line); }
    .high { color:var(--danger); border-color:#f4b4ac; background:#fff1f0; }
    .medium { color:var(--warn); border-color:#fedf89; background:#fffaeb; }
    .low, .info { color:var(--ok); border-color:#abefc6; background:#ecfdf3; }
    pre { white-space:pre-wrap; overflow:auto; background:#101828; color:#f2f4f7; border-radius:8px; padding:12px; }
    code { font-family: Consolas, monospace; }
    .grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
    .preview { background:#f8fafc; border:1px solid var(--line); border-radius:8px; padding:12px; min-height:90px; font-size:13px; color:#344054; }
    @media (max-width: 760px) { .summary, .grid { grid-template-columns:1fr; } header { padding:22px; } }
  </style>
</head>
<body>
  <header>
    <h1>BOLA Fuzzer Report</h1>
    <p class="meta">Generated at __GENERATED_AT__</p>
  </header>
  <main>
    <section class="summary">
      <div class="metric">Total Tests<strong>__TOTAL__</strong></div>
      <div class="metric">Potential BOLA<strong>__POTENTIAL__</strong></div>
      <div class="metric">Suspicious<strong>__SUSPICIOUS__</strong></div>
      <div class="metric">Inconclusive/Info<strong>__OTHER__</strong></div>
    </section>
"""


HTML_TAIL = """  </main>
</body>
</html>"""


HTML_FINDING = """
    <article class="finding">
      <h2>{test_name}</h2>
      <div class="row">
        <span class="badge {severity_class}">{status}</span>
        <span class="badge {severity_class}">Severity: {severity}</span>
        <span class="badge">Confidence: {confidence}</span>
        <span class="badge">Object ID: {object_id}</span>
      </div>
      <p><strong>Endpoint:</strong> <code>{endpoint}</code></p>
      <p><strong>Reason:</strong> {reason}</p>
      <p><strong>PoC:</strong></p>
      <pre><code>{poc_curl}</code></pre>
      <div class="grid">
        <div>
          <p><strong>Owner response preview</strong> HTTP {owner_status_code}</p>
          <div class="preview">{owner_response_preview}</div>
        </div>
        <div>
          <p><strong>Attacker response preview</strong> HTTP {attacker_status_code}</p>
          <div class="preview">{attacker_response_preview}</div>
        </div>
      </div>
    </article>
"""


def write_reports(findings: list[ScanFinding], output_dir: str | Path = "reports") -> tuple[Path, Path]:
    report_dir = Path(output_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    from uuid import uuid4
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f") + "-" + uuid4().hex[:8]
    markdown_path = report_dir / f"bola-report-{stamp}.md"
    html_path = report_dir / f"bola-report-{stamp}.html"

    markdown_path.write_text(render_markdown(findings), encoding="utf-8")
    html_path.write_text(render_html(findings), encoding="utf-8")
    return markdown_path, html_path


def render_markdown(findings: list[ScanFinding]) -> str:
    lines = ["# BOLA Fuzzer Report", ""]
    for finding in findings:
        lines.extend(
            [
                f"## {finding.test_name}",
                "",
                f"- Status: {finding.status}",
                f"- Severity: {finding.severity}",
                f"- Confidence: {finding.confidence}",
                f"- Endpoint: `{finding.endpoint}`",
                f"- Object ID: `{finding.object_id}`",
                f"- Reason: {finding.reason}",
                "",
                "### PoC",
                "",
                "```bash",
                finding.poc_curl,
                "```",
                "",
                "### Attacker Response Preview",
                "",
                "```text",
                finding.attacker_response_preview,
                "```",
                "",
            ]
        )
    return "\n".join(lines)


def render_html(findings: list[ScanFinding]) -> str:
    potential = sum(1 for finding in findings if finding.status == "Potential BOLA")
    suspicious = sum(1 for finding in findings if finding.status == "Suspicious")
    other = len(findings) - potential - suspicious
    head = (
        HTML_HEAD.replace("__TOTAL__", str(len(findings)))
        .replace("__POTENTIAL__", str(potential))
        .replace("__SUSPICIOUS__", str(suspicious))
        .replace("__OTHER__", str(other))
        .replace("__GENERATED_AT__", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    body = []
    for finding in findings:
        body.append(
            HTML_FINDING.format(
                test_name=escape(finding.test_name),
                severity_class=escape(finding.severity.lower()),
                status=escape(finding.status),
                severity=escape(finding.severity),
                confidence=escape(finding.confidence),
                object_id=escape(finding.object_id),
                endpoint=escape(finding.endpoint),
                reason=escape(finding.reason),
                poc_curl=escape(finding.poc_curl),
                owner_status_code=finding.owner_status_code,
                attacker_status_code=finding.attacker_status_code,
                owner_response_preview=escape(finding.owner_response_preview),
                attacker_response_preview=escape(finding.attacker_response_preview),
            )
        )
    return head + "".join(body) + HTML_TAIL
