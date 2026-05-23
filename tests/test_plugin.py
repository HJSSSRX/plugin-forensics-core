from __future__ import annotations

"""forensics-core Cell — tests."""

from plugin import ForensicsCorePlugin


def test_plugin_registers_tools():
    plugin = ForensicsCorePlugin()
    tools = plugin.register_tools()
    assert len(tools) >= 1
    assert all(t.name for t in tools)
    assert all(t.domain for t in tools)
    assert all(t.risk_level in ("LOW", "MEDIUM", "HIGH") for t in tools)


def test_plugin_metadata():
    plugin = ForensicsCorePlugin()
    assert plugin.name == "forensics-core"
    assert plugin.version
    assert plugin.domain == "forensics"
