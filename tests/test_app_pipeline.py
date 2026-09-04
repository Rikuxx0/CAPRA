from pathlib import Path

from streamlit.testing.v1 import AppTest


def test_streamlit_runs_layer1_to_layer2_pipeline():
    app = AppTest.from_file("app.py", default_timeout=15).run()
    hound_uploader = next(
        item for item in app.get("file_uploader") if item.key == "layer1_hound"
    )
    hound_uploader.upload(
        "hound_generic_sample.json",
        Path("examples/layer1/hound_generic_sample.json").read_bytes(),
        "application/json",
    ).run()

    buttons = {button.label: button for button in app.button}
    buttons["Run CAPRA Planner"].click().run(timeout=15)

    assert not app.exception
    assert [item.value for item in app.header] == ["CAPRA Planner", "Plan Results"]
    assert [button.label for button in app.button] == ["Run CAPRA Planner"]
    assert "layer1_fact_graph" in app.session_state
    assert "layer2_attack_operator_graph" in app.session_state
    assert app.session_state["layer1_layer2_handoff_hash"]
    assert any("Fact handoff verified" in item.value for item in app.success)
    assert [tab.label for tab in app.tabs] == [
        "Overview",
        "Facts",
        "Attack operators",
        "Review queue",
        "Export",
    ]


def test_streamlit_accepts_an_existing_fact_graph_in_the_unified_ui():
    app = AppTest.from_file("app.py", default_timeout=15).run()
    app.radio[0].set_value("既存Fact Graph JSON").run()
    fact_uploader = next(
        item
        for item in app.get("file_uploader")
        if item.key == "planner_fact_graph_upload"
    )
    fact_uploader.upload(
        "fact_graph_sample.json",
        Path("examples/layer1/fact_graph_sample.json").read_bytes(),
        "application/json",
    ).run()

    app.button[0].click().run(timeout=15)

    assert not app.exception
    assert "layer1_fact_graph" in app.session_state
    assert "layer2_attack_operator_graph" in app.session_state
    assert "layer1_layer2_handoff_hash" not in app.session_state
    assert any("互換loader" in item.value for item in app.info)
