"""AI-assisted review hook (template).

Plug a language model in here. It receives the source code and the static findings,
and should return extra Finding objects for issues that AST rules cannot see
(for example missing authorization checks or unsafe business logic).

Do not send proprietary or confidential code to a third-party API without permission.
"""

from .rules import Finding


def review(source: str, filename: str, findings: list[Finding]) -> list[Finding]:
    # TODO: call the model of your choice and convert its answer into Finding objects.
    return []
