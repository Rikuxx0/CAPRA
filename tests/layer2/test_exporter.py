import json
from pathlib import Path

from capra.layer2.exporter import (
    export_connections_dataframe,
    export_layer3_candidates_dataframe,
    export_operators_dataframe,
    export_unresolved_dataframe,
    save_attack_operator_graph_json,
)
from capra.layer2.schemas import AttackOperatorGraphModel
from capra.layer2.schemas import AttackOperatorModel
from capra.layer2.exporter import export_attack_operator_graph_json


def test_example_output_validates_and_all_exporters_serialize(tmp_path):
    payload = json.loads(Path("examples/layer2/attack_operator_graph_sample.json").read_text())
    graph = AttackOperatorGraphModel.model_validate(payload)
    assert not export_operators_dataframe(graph).empty
    assert len(export_connections_dataframe(graph)) == 13
    assert export_unresolved_dataframe(graph).empty
    assert not export_layer3_candidates_dataframe(graph).empty
    output = tmp_path / "attack_operator_graph.json"
    save_attack_operator_graph_json(graph, output)
    AttackOperatorGraphModel.model_validate_json(output.read_text())


def test_export_redacts_defensively():
    graph = AttackOperatorGraphModel(
        attack_operators=[
            AttackOperatorModel(
                id="operator",
                operator_type="test",
                origin_kind="iam_direct_edge",
                source_tool="manual",
                status="complete",
                metadata={"safe": "kept", "token": "sensitive"},
            )
        ],
        metadata={"authorization": "sensitive"},
    )

    payload = export_attack_operator_graph_json(graph)

    assert payload["attack_operators"][0]["metadata"]["token"] == "[REDACTED]"
    assert payload["metadata"]["authorization"] == "[REDACTED]"
