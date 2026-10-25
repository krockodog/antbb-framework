"""Tool-Playbook-Specs: echte, orchestrierte Werkzeuge der Queens.

Zwei Klassen:

- CLI_TOOLS: nicht-interaktive Werkzeuge mit echter CLI. Der Executor ruft sie
  per subprocess mit hartem Timeout auf und schreibt stdout/stderr ins Artefakt.
  Fehlt das Binary oder die Laufzeitumgebung, landet eine ehrliche Note im
  Dossier — niemals Fake-Ergebnisse.

- OPERATOR_TOOLS: interaktive, Docker-basierte oder sonst nicht autonom
  startbare Werkzeuge. Der Executor startet sie NIEMALS selbst, sondern legt
  ein Start-Artefakt (Befehlsvorlage + Pfade + Scope) ins Dossier. Start
  erfolgt ausschließlich durch den Operator, oversight-pflichtig.

Alle Pfade zeigen auf die auf der ProLiant-Box unter /home/lordix/tools/
geklonten Security-Tools. Jedes Red-Playbook hat genau ein Blue-Gegenstück
(siehe RED_BLUE_PAIRS).
"""

from __future__ import annotations

import json

TOOLS_ROOT = "/home/lordix/tools"

# Red-Playbook -> Blue-Gegenmaßnahme (Namenspaare, gespiegelt).
RED_BLUE_PAIRS: list[tuple[str, str]] = [
    ("pentagi", "agent-governance-toolkit"),
    ("garak", "rebuff"),
    ("murphysec", "dockerscan-abwehr"),
    ("cdk", "veinmind-tools"),
    ("kubescape", "kubescape-haertung"),
    ("ai-infra-guard", "mcp-scanner"),
    ("sickhackshark", "defending-code-harness"),
    ("cyberstrikeai", "skillspector"),
]

# Nicht-interaktive CLI-Tools: argv(binary, targets, folder) -> Kommando.
CLI_TOOLS: dict[str, dict] = {
    "murphysec": {
        "tool": "murphysec",
        "repo_path": f"{TOOLS_ROOT}/murphysec",
        "binaries": [f"{TOOLS_ROOT}/murphysec/murphysec", "murphysec"],
        "timeout": 180,
        "cwd": None,
        "argv": lambda b, t, f: [b, "scan", t[0]],
        "summary": "SCA-Scan (Software-Composition-Analysis) auf Scope-Ziel/Repo-Pfad.",
    },
    "cdk": {
        "tool": "CDK",
        "repo_path": f"{TOOLS_ROOT}/CDK",
        "binaries": [f"{TOOLS_ROOT}/CDK/cdk", "cdk"],
        "timeout": 90,
        "cwd": f"{TOOLS_ROOT}/CDK",
        "argv": lambda b, t, f: [b, "evaluate", "--full"],
        "summary": "Container-Enumeration (cdk evaluate --full), Lab-only, read-only.",
    },
    "kubescape": {
        "tool": "kubescape",
        "repo_path": f"{TOOLS_ROOT}/kubescape",
        "binaries": [f"{TOOLS_ROOT}/kubescape/kubescape", "kubescape"],
        "timeout": 240,
        "cwd": None,
        "argv": lambda b, t, f: [b, "scan", "--format", "json",
                                 "--output", str(f / "kubescape-scan.json")],
        "summary": "K8s-Scan nach NSA/CISA-Framework (kubescape scan, JSON-Artefakt).",
    },
    "garak": {
        "tool": "garak",
        "repo_path": f"{TOOLS_ROOT}/garak",
        "binaries": [f"{TOOLS_ROOT}/garak/.venv/bin/garak", "garak"],
        "timeout": 300,
        "cwd": f"{TOOLS_ROOT}/garak",
        "argv": lambda b, t, f: [b, "--target_type", "rest",
                                 "--generator_options", json.dumps(
                                     {"rest": {"RestGenerator": {
                                         "uri": f"http://{t[0]}/v1/chat/completions",
                                         "method": "post"}}}),
                                 "-p", "promptinject",
                                 "--report_prefix", str(f / "garak")],
        "summary": "LLM-Scanner garak (promptinject) gegen REST-Ziel im Scope.",
    },
    "ai-infra-guard": {
        "tool": "AI-Infra-Guard",
        "repo_path": f"{TOOLS_ROOT}/AI-Infra-Guard",
        "binaries": [f"{TOOLS_ROOT}/AI-Infra-Guard/aig", "aig"],
        "timeout": 180,
        "cwd": f"{TOOLS_ROOT}/AI-Infra-Guard",
        "argv": lambda b, t, f: [b, "scan", "--target", f"http://{t[0]}",
                                 "-o", str(f / "ai-infra-guard-scan.txt")],
        "summary": "KI-Infrastruktur-/MCP-Scan (aig scan) gegen HTTP-Ziel im Scope.",
    },
    "kubescape-haertung": {
        "tool": "kubescape",
        "repo_path": f"{TOOLS_ROOT}/kubescape",
        "binaries": [f"{TOOLS_ROOT}/kubescape/kubescape", "kubescape"],
        "timeout": 240,
        "cwd": None,
        "argv": lambda b, t, f: [b, "scan", "--format", "json",
                                 "--output", str(f / "kubescape-haertung-scan.json")],
        "extra_artifact": ("kubescape-haertung-checkliste.md",
                           "# NSA/CISA-Härtung — Umsetzungs-Checkliste\n\n"
                           "Gegenstück zum Red-Playbook `kubescape`.\n\n"
                           "- [ ] Non-root-Container erzwingen (runAsNonRoot)\n"
                           "- [ ] readOnlyRootFilesystem für Workloads\n"
                           "- [ ] Capabilities auf Minimum droppen (drop ALL)\n"
                           "- [ ] Netzwerk-Policies default-deny\n"
                           "- [ ] Secrets aus etcd verschlüsselt / externe Secret-Stores\n"
                           "- [ ] Admission-Controller (OPA/Kyverno) für Policy-Enforcement\n"
                           "- [ ] Audit-Logging aktiviert und ausgewertet\n"
                           "- [ ] Pod Security Standards `restricted` als Baseline\n"),
        "summary": "NSA/CISA-Härtung umsetzen: kubescape-Scan plus Härtungs-Checkliste.",
    },
    "mcp-scanner": {
        "tool": "mcp-scanner",
        "repo_path": f"{TOOLS_ROOT}/mcp-scanner",
        "binaries": [f"{TOOLS_ROOT}/mcp-scanner/.venv/bin/python", "python3"],
        "timeout": 120,
        "cwd": f"{TOOLS_ROOT}/mcp-scanner",
        "argv": lambda b, t, f: [b, "mcp_scanner_entry.py", "remote",
                                 "--server-url", f"http://{t[0]}"],
        "summary": "MCP-Server-Risiken scannen (mcp-scanner remote).",
    },
    "defending-code-harness": {
        "tool": "defending-code-reference-harness",
        "repo_path": f"{TOOLS_ROOT}/defending-code-reference-harness",
        "binaries": ["python3"],
        "timeout": 180,
        "cwd": f"{TOOLS_ROOT}/defending-code-reference-harness",
        "argv": lambda b, t, f: [b, "-m", "harness.cli", "recon", t[0]],
        "summary": "Triage/Patch-Framework (vuln-pipeline recon) für Scope-Ziel.",
    },
    "dockerscan-abwehr": {
        "tool": "dockerscan",
        "repo_path": f"{TOOLS_ROOT}/dockerscan",
        "binaries": [f"{TOOLS_ROOT}/dockerscan/dockerscan", "dockerscan"],
        "timeout": 300,
        "cwd": None,
        "argv": lambda b, t, f: [b, "scan", t[0], "--scanners", "cis,secrets",
                                 "--output", str(f / "dockerscan-report"), "-q"],
        "summary": "Image-Integrität prüfen: CIS-Benchmark + Secrets-Scan (dockerscan).",
    },
}

# Interaktive / Docker- / Sandbox-Tools: kein autonomer Start.
OPERATOR_TOOLS: dict[str, dict] = {
    "pentagi": {
        "tool": "PENTAGI",
        "repo_path": f"{TOOLS_ROOT}/pentagi",
        "start_template": "cd {repo_path} && docker compose up -d",
        "summary": "Autonomer Multi-Agenten-Pentest (Docker-Sandbox).",
        "note": "Nur vom Operator in der Docker-Sandbox starten, oversight-pflichtig.",
    },
    "cyberstrikeai": {
        "tool": "CyberStrikeAI",
        "repo_path": f"{TOOLS_ROOT}/CyberStrikeAI",
        "start_template": "cd {repo_path} && cp config.example.yaml config.yaml && go run ./cmd",
        "summary": "KI-gesteuerte Angriffsplattform (Go).",
        "note": "Nur vom Operator starten (Konfig anpassen), oversight-pflichtig.",
    },
    "sickhackshark": {
        "tool": "SickHackShark",
        "repo_path": f"{TOOLS_ROOT}/SickHackShark",
        "start_template": "cd {repo_path} && docker compose up -d",
        "summary": "CTF-Automatisierung (LangGraph + Kali-Container).",
        "note": "Nur vom Operator via docker compose starten, oversight-pflichtig.",
    },
    "agent-governance-toolkit": {
        "tool": "agent-governance-toolkit",
        "repo_path": f"{TOOLS_ROOT}/agent-governance-toolkit",
        "start_template": "cd {repo_path} && ls agent-governance-*/README*",
        "summary": "Richtlinien: Zero-Trust, Sandboxing, Circuit-Breaker für Agenten.",
        "note": "Policy-Pakete je Client-Integration einbinden (Operator), oversight-pflichtig.",
    },
    "rebuff": {
        "tool": "rebuff",
        "repo_path": f"{TOOLS_ROOT}/rebuff",
        "start_template": "cd {repo_path}/server && docker compose up -d",
        "summary": "Prompt-Injection-Abwehr (Detection + Canary-Tokens).",
        "note": "Server via Docker starten oder SDK einbinden (Operator), oversight-pflichtig.",
    },
    "openshell": {
        "tool": "OpenShell",
        "repo_path": f"{TOOLS_ROOT}/OpenShell",
        "start_template": "cd {repo_path} && cargo build --release",
        "summary": "Agenten-Sandbox mit YAML-Policies.",
        "note": "Sandbox bauen und YAML-Policies hinterlegen (Operator), oversight-pflichtig.",
    },
    "veinmind-tools": {
        "tool": "veinmind-tools",
        "repo_path": f"{TOOLS_ROOT}/veinmind-tools",
        "start_template": "cd {repo_path} && docker build -t veinmind .",
        "summary": "Container-Scan/Abwehr (veinmind Runner + Plugins).",
        "note": "Container-basiert — nur vom Operator starten, oversight-pflichtig.",
    },
    "skillspector": {
        "tool": "SkillSpector",
        "repo_path": f"{TOOLS_ROOT}/SkillSpector",
        "start_template": "cd {repo_path} && docker build -t skillspector .",
        "summary": "Skill-Gate: Agenten-Skills vor Installation prüfen.",
        "note": "Gate vor jeder Skill-Installation laufen lassen (Operator), oversight-pflichtig.",
    },
}


def tool_spec(playbook_id: str) -> dict | None:
    """Spec für ein Tool-Playbook, egal ob CLI oder Operator-Tool."""
    spec = CLI_TOOLS.get(playbook_id)
    if spec is not None:
        return {"mode": "cli", **spec}
    spec = OPERATOR_TOOLS.get(playbook_id)
    if spec is not None:
        return {"mode": "operator", **spec}
    return None
