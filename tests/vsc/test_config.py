import pytest

from a2agw.config import ConfigError, load_config

from .conftest import MINIMAL_YAML, VSC_YAML, VSC_YAML_BAD_CHECK, VSC_YAML_URL, write_yaml


def test_vsc_section_parses(tmp_path):
    cfg = load_config(write_yaml(tmp_path, VSC_YAML))
    assert [s.id for s in cfg.vsc.systems] == ["core", "node-coder"]
    assert cfg.vsc.checks[0].systems == ["core", "node-coder"]
    assert cfg.vsc.budgets.tokens == 2_000_000
    assert cfg.vsc.planner == "claude" and cfg.vsc.workspace_dir == ".a2agw/vsc"


def test_check_names_unknown_system(tmp_path):
    with pytest.raises(ConfigError, match=r"checks\[0\].systems: unknown system 'x'"):
        load_config(write_yaml(tmp_path, VSC_YAML_BAD_CHECK))


def test_clone_url_rejected(tmp_path):
    with pytest.raises(ConfigError, match="clone URLs are Phase 5b"):
        load_config(write_yaml(tmp_path, VSC_YAML_URL))


def test_https_clone_url_rejected(tmp_path):
    text = VSC_YAML_URL.replace("git@github.com:acme/x.git", "https://github.com/acme/x")
    with pytest.raises(ConfigError, match="clone URLs are Phase 5b"):
        load_config(write_yaml(tmp_path, text))


def test_no_vsc_section_is_none(tmp_path):
    assert load_config(write_yaml(tmp_path, MINIMAL_YAML)).vsc is None


def test_duplicate_system_ids_rejected(tmp_path):
    text = "base_url: http://x\nvsc:\n  systems:\n    - {id: a, repo: .}\n    - {id: a, repo: .}\n"
    with pytest.raises(ConfigError, match="duplicate id 'a'"):
        load_config(write_yaml(tmp_path, text))


def test_auto_approve_unknown_system_rejected(tmp_path):
    text = (
        "base_url: http://x\nvsc:\n  systems:\n    - {id: a, repo: .}\n"
        "  auto_approve:\n    - {system: b, action: merge, target_branch: main}\n"
    )
    with pytest.raises(ConfigError, match=r"auto_approve\[0\].system: unknown system 'b'"):
        load_config(write_yaml(tmp_path, text))


def test_bad_values_rejected_without_echo(tmp_path):
    text = "base_url: http://x\nvsc:\n  systems:\n    - {id: Bad_Id, repo: ., gate: []}\n"
    with pytest.raises(ConfigError) as ei:
        load_config(write_yaml(tmp_path, text))
    msg = str(ei.value)
    assert "vsc.systems.0.id" in msg and "vsc.systems.0.gate" in msg and "Bad_Id" not in msg


def test_check_needs_two_systems_and_budgets_positive(tmp_path):
    text = (
        "base_url: http://x\nvsc:\n  systems:\n    - {id: a, repo: .}\n"
        "  checks:\n    - {id: c, systems: [a], run: [x]}\n  budgets: {attempts: 0}\n"
    )
    with pytest.raises(ConfigError) as ei:
        load_config(write_yaml(tmp_path, text))
    assert "checks.0.systems" in str(ei.value) and "budgets.attempts" in str(ei.value)
