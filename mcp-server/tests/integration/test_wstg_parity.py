from rynix_mcp.plugins import rynix_plugin_run
from rynix_mcp.wstg_runner import list_wstg_test_ids


def test_wstg_list_action():
    result = rynix_plugin_run("wstg", options='{"action":"list"}')
    assert result.get("plugin_id") == "wstg"
    assert result.get("count", 0) >= 100


def test_wstg_test_ids_count():
    assert len(list_wstg_test_ids()) == 109
