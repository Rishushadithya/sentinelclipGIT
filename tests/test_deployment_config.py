import json

import pytest

from deployment_config import load_deployment_config, services_for_role


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        ("server", (True, False, True)),
        ("agent", (False, True, False)),
        ("both", (True, True, True)),
    ],
)
def test_services_for_role(role, expected):
    assert services_for_role(role) == expected


def test_load_deployment_config_reads_installer_settings(tmp_path):
    path = tmp_path / "deployment.json"
    path.write_text(
        json.dumps({"role": "agent", "api_base": "http://192.168.1.8:5000/api/v1"}),
        encoding="utf-8",
    )

    config = load_deployment_config(path)

    assert config["role"] == "agent"
    assert config["api_base"] == "http://192.168.1.8:5000/api/v1"
    assert config["dashboard_port"] == 8501


def test_load_deployment_config_rejects_unknown_role(tmp_path):
    path = tmp_path / "deployment.json"
    path.write_text('{"role":"unknown"}', encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported SentinelClip role"):
        load_deployment_config(path)