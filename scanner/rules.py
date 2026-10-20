"""Static checks for common Python security issues, built on the stdlib ast module."""

import ast
import re
from dataclasses import asdict, dataclass

SECRET_NAME = re.compile(r"(password|passwd|secret|token|api_?key)", re.IGNORECASE)


@dataclass
class Finding:
    file: str
    line: int
    rule: str
    severity: str
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


def _call_name(node: ast.Call) -> str:
    """Return a dotted name such as 'subprocess.run' for a call, or '' if unknown."""
    parts = []
    func = node.func
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if not isinstance(func, ast.Name):
        return ""
    parts.append(func.id)
    return ".".join(reversed(parts))


def _keyword(node: ast.Call, name: str):
    return next((kw.value for kw in node.keywords if kw.arg == name), None)


def _is_constant(value, expected) -> bool:
    return isinstance(value, ast.Constant) and value.value is expected


def scan_source(source: str, filename: str = "<string>") -> list[Finding]:
    """Parse Python source and return findings sorted by line number."""
    tree = ast.parse(source, filename=filename)
    findings: list[Finding] = []

    def add(node: ast.AST, rule: str, severity: str, message: str) -> None:
        findings.append(Finding(filename, node.lineno, rule, severity, message))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name in ("eval", "exec"):
                add(node, "PY001", "HIGH", f"Use of {name}() can execute arbitrary code.")
            elif name.startswith("subprocess.") and _is_constant(_keyword(node, "shell"), True):
                add(node, "PY002", "HIGH", "subprocess call with shell=True allows command injection.")
            elif name in ("pickle.load", "pickle.loads"):
                add(node, "PY003", "MEDIUM", "Unpickling untrusted data can execute arbitrary code.")
            elif name == "yaml.load" and _keyword(node, "Loader") is None and len(node.args) < 2:
                add(node, "PY004", "MEDIUM", "yaml.load() without a Loader; use yaml.safe_load().")
            elif name in ("hashlib.md5", "hashlib.sha1"):
                add(node, "PY006", "LOW", f"{name} is a weak hash; use SHA-256 or better.")
            elif name.startswith("requests.") and _is_constant(_keyword(node, "verify"), False):
                add(node, "PY007", "MEDIUM", "TLS certificate verification is disabled (verify=False).")
        elif isinstance(node, ast.Assign):
            value = node.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value:
                for target in node.targets:
                    if isinstance(target, ast.Name) and SECRET_NAME.search(target.id):
                        add(node, "PY005", "HIGH", f"Possible hardcoded secret in '{target.id}'.")

    return sorted(findings, key=lambda f: f.line)
