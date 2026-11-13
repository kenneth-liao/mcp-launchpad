from types import SimpleNamespace

import pytest

import mcp_launchpad.state as state_module
from mcp_launchpad.state import ServerState


@pytest.fixture
def state_file(tmp_path, monkeypatch):
    path = tmp_path / "server_state.json"
    monkeypatch.setattr(state_module, "STATE_FILE", path)
    return path


@pytest.fixture
def config():
    return SimpleNamespace(servers={"github": None, "sentry": None})


def test_loads_disabled_servers(state_file, config):
    state_file.write_text('{"disabled_servers": ["github"]}')
    state = ServerState(config)
    assert state.is_disabled("github")
    assert state.is_enabled("sentry")


@pytest.mark.parametrize(
    "contents",
    [
        "{ not json",
        "[]",
        '"just a string"',
        '{"disabled_servers": 5}',
        '{"disabled_servers": [["nested"]]}',
    ],
)
def test_corrupt_state_file_starts_with_no_disabled_servers(state_file, config, contents):
    state_file.write_text(contents)
    state = ServerState(config)
    assert state.get_disabled_servers() == []
    assert state.is_enabled("github")
