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


def vsc_config():
    from a2agw.vsc.config import VscConfig

    return VscConfig.model_validate(
        {
            "systems": [
                {"id": "core", "repo": "./core"},
                {"id": "node-coder", "repo": "./node-coder"},
            ],
            "checks": [
                {"id": "sidecar", "systems": ["core", "node-coder"], "run": ["make", "sidecar"]}
            ],
        }
    )


def make_repo(tmp_path, name: str, files: dict[str, str]) -> Path:
    """A throwaway git repository on ``main`` with one initial commit."""
    import subprocess

    repo = tmp_path / name
    repo.mkdir(parents=True)
    for rel, content in files.items():
        f = repo / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content)

    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)

    git("init", "-b", "main")
    git("config", "user.name", "Test")
    git("config", "user.email", "test@example.com")
    git("add", "-A")
    git("commit", "-m", "initial")
    return repo
