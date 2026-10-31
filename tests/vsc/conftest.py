import textwrap
from pathlib import Path


def write_yaml(tmp_path, text) -> Path:
    p = tmp_path / "a2agw.yaml"
    p.write_text(textwrap.dedent(text))
    return p


MINIMAL_YAML = "base_url: http://x\n"

VSC_YAML = """\
base_url: http://x
vsc:
  systems:
    - {id: core, repo: ./core}
    - {id: node-coder, repo: ./node-coder, gate: [make, gate], index: [src]}
  checks:
    - {id: contract, systems: [core, node-coder], run: [make, contract]}
"""

VSC_YAML_BAD_CHECK = """\
base_url: http://x
vsc:
  systems:
    - {id: core, repo: ./core}
    - {id: node-coder, repo: ./node-coder}
  checks:
    - {id: contract, systems: [core, x], run: [make, contract]}
"""

VSC_YAML_URL = """\
base_url: http://x
vsc:
  systems:
    - {id: core, repo: "git@github.com:acme/x.git"}
"""
