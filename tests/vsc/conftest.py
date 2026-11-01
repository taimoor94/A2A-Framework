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


WORKER_AGENT = str(Path(__file__).with_name("worker_agent.py"))


def worker(mode: str, *, reports_usage: bool = True, timeout_s: float = 30.0):
    """A ``WorkerSpec`` running ``worker_agent.py <mode>`` under ``python -I``."""
    import sys

    from a2agw.vsc.workers import WorkerSpec

    return WorkerSpec(
        id="fake",
        command=[sys.executable, "-I", WORKER_AGENT, mode],
        model="fake-1",
        cost_class="cheap",
        reports_usage=reports_usage,
        env={},
        timeout_s=timeout_s,
    )


def worker_task(files: dict[str, str] | None = None, *, failure=None, attempt: int = 1):
    """A ``WorkerTask`` whose prompt ends with the ``---FILES---`` block ``files`` (if any)."""
    import json

    from a2agw.vsc.config import BudgetConfig, SystemConfig
    from a2agw.vsc.plan import PlanStep
    from a2agw.vsc.spec import ExecutableSpec
    from a2agw.vsc.workers import WorkerTask

    instructions = "add the greeting"
    if files is not None:
        instructions += "\n---FILES---\n" + json.dumps({"files": files})
    return WorkerTask(
        job_id="job1",
        step_id="s1",
        attempt=attempt,
        system=SystemConfig(id="core", repo="./core"),
        spec=ExecutableSpec(
            request="greet",
            done="greeting exists",
            systems=["core"],
            acceptance=[],
            budgets=BudgetConfig(),
        ),
        step=PlanStep(id="s1", system="core", instructions=instructions),
        failure=failure,
    )
