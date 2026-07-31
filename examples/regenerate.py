from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from capra.layer1.exporters import export_fact_graph_json
from capra.layer1.graph_builder import build_layer1_fact_graph
from capra.layer1.parsers.grype_parser import parse_grype_json
from capra.layer1.parsers.hound_parser import parse_hound_generic
from capra.layer2.exporter import export_attack_operator_graph_json
from capra.layer2.nvd.cache import NvdCache
from capra.layer2.schemas import AttackOperatorGraphModel, Layer2Config
from capra.layer2.service import build_attack_operator_graph
from capra.layer2.visualization import build_attack_operator_graph_html

EXAMPLES_DIRECTORY = Path(__file__).resolve().parent
OUTPUTS_DIRECTORY = EXAMPLES_DIRECTORY.parent / "outputs"
LAYER1_DIRECTORY = EXAMPLES_DIRECTORY / "layer1"
LAYER2_DIRECTORY = EXAMPLES_DIRECTORY / "layer2"
FIXTURE_FETCHED_AT = datetime(2026, 7, 31, tzinfo=timezone.utc)


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _build_layer1_payload() -> dict[str, Any]:
    nodes, edges = parse_hound_generic(
        _read_json(LAYER1_DIRECTORY / "hound_generic_sample.json")
    )
    vulnerabilities = parse_grype_json(
        _read_json(LAYER1_DIRECTORY / "grype_sample.json")
    )
    graph = build_layer1_fact_graph(
        nodes,
        edges,
        vulnerabilities,
        asset_config=yaml.safe_load(
            (LAYER1_DIRECTORY / "important_assets.yaml").read_text(encoding="utf-8")
        ),
        vulnerability_mapping_config=yaml.safe_load(
            (LAYER1_DIRECTORY / "vulnerability_mapping.yaml").read_text(
                encoding="utf-8"
            )
        ),
        source_files=[
            "grype_sample.json",
            "hound_generic_sample.json",
            "important_assets.yaml",
            "vulnerability_mapping.yaml",
        ],
    )
    return export_fact_graph_json(graph)


def _write_source_specific_examples(fact_graph: dict[str, Any]) -> None:
    nodes_by_id = {node["id"]: node for node in fact_graph["nodes"]}
    destinations = {
        "azurehound": LAYER2_DIRECTORY / "azurehound_edges.json",
        "gcp_hound": LAYER2_DIRECTORY / "gcp_hound_edges.json",
        "clusterhound": LAYER2_DIRECTORY / "clusterhound_edges.json",
    }
    for source_tool, destination in destinations.items():
        edges = [
            edge
            for edge in fact_graph["edges"]
            if edge.get("source_tool") == source_tool
        ]
        node_ids = {
            str(edge[node_key])
            for edge in edges
            for node_key in ("source", "target")
        }
        _write_json(
            destination,
            {
                "nodes": [
                    nodes_by_id[node_id]
                    for node_id in sorted(node_ids)
                    if node_id in nodes_by_id
                ],
                "edges": edges,
            },
        )

    iam_edges = [
        edge
        for edge in fact_graph["edges"]
        if edge.get("source_tool") == "iamhounddog"
    ]
    iam_node_ids = {
        str(edge[node_key])
        for edge in iam_edges
        for node_key in ("source", "target")
    }
    iam_nodes = [
        nodes_by_id[node_id]
        for node_id in sorted(iam_node_ids)
        if node_id in nodes_by_id
    ]
    _write_json(
        LAYER2_DIRECTORY / "iamhounddog_full_match.json",
        {"nodes": iam_nodes, "edges": iam_edges},
    )
    _write_json(
        LAYER2_DIRECTORY / "iamhounddog_partial_match.json",
        {
            "description": "The structural pattern matches, but iam:PassRole is absent.",
            "nodes": iam_nodes,
            "edges": [
                edge
                for edge in iam_edges
                if str(edge.get("permission") or "").lower() != "iam:passrole"
            ],
        },
    )


def _build_layer2_payload(fact_graph: dict[str, Any]) -> dict[str, Any]:
    cve_ids = sorted(
        {
            vulnerability["cve_id"]
            for node in fact_graph["nodes"]
            for vulnerability in node.get("vulnerabilities", [])
            if vulnerability.get("cve_id")
        }
    )
    with tempfile.TemporaryDirectory(prefix="capra-example-nvd-") as directory:
        cache = NvdCache(directory)
        for cve_id in cve_ids:
            cache.write(
                cve_id,
                _read_json(LAYER2_DIRECTORY / "nvd" / f"{cve_id}.json"),
                FIXTURE_FETCHED_AT,
            )
        graph = build_attack_operator_graph(
            fact_graph,
            Layer2Config(
                nvd_mode="cache-only",
                nvd_cache_directory=Path(directory),
                nvd_cache_ttl_seconds=10_000_000_000,
            ),
        )
    payload = export_attack_operator_graph_json(graph)
    payload["metadata"]["generated_at"] = "example"
    payload["metadata"]["processing_time_ms"] = 0
    payload["metadata"]["execution_config"][
        "nvd_cache_directory"
    ] = "examples/layer2/nvd"
    return payload


def _write_layer2_outputs(payload: dict[str, Any]) -> None:
    _write_json(LAYER2_DIRECTORY / "attack_operator_graph_sample.json", payload)
    cve_operators = sorted(
        (
            operator
            for operator in payload["attack_operators"]
            if operator["origin_kind"] == "cve"
        ),
        key=lambda operator: operator["cve_ids"],
    )
    _write_json(LAYER2_DIRECTORY / "cve_operator_example.json", cve_operators[0])

    operator_ids_by_type = {
        operator["operator_type"]: operator["id"]
        for operator in payload["attack_operators"]
    }
    connection = next(
        connection
        for connection in payload["connections"]
        if connection["connection_type"] == "enables"
        and connection["source_operator_id"]
        == operator_ids_by_type["port_forward_to_workload"]
        and connection["target_operator_id"]
        == operator_ids_by_type["remote_code_execution"]
    )
    _write_json(LAYER2_DIRECTORY / "connection_example.json", connection)
    _write_json(
        LAYER2_DIRECTORY / "layer3_candidates.json",
        {
            "layer3_candidates": payload["layer3_candidates"],
            "note": (
                "IDs identify unverified Layer 2 operators; "
                "this file contains no command or payload."
            ),
        },
    )
    manual = next(
        operator
        for operator in payload["attack_operators"]
        if operator["operator_type"] == "access_unauthenticated_kubernetes_api"
    )
    _write_json(LAYER2_DIRECTORY / "manual_verification_required.json", manual)


def _write_repository_outputs(payload: dict[str, Any]) -> None:
    graph = AttackOperatorGraphModel.model_validate(payload)
    OUTPUTS_DIRECTORY.mkdir(parents=True, exist_ok=True)
    _write_json(OUTPUTS_DIRECTORY / "layer2_attack_operator_graph.json", payload)
    (OUTPUTS_DIRECTORY / "layer2_attack_operator_graph.html").write_text(
        build_attack_operator_graph_html(graph),
        encoding="utf-8",
    )


def main() -> None:
    layer1_payload = _build_layer1_payload()
    _write_json(LAYER1_DIRECTORY / "fact_graph_sample.json", layer1_payload)
    _write_json(LAYER2_DIRECTORY / "fact_graph_sample.json", layer1_payload)
    _write_source_specific_examples(layer1_payload)
    layer2_payload = _build_layer2_payload(layer1_payload)
    _write_layer2_outputs(layer2_payload)
    _write_repository_outputs(layer2_payload)


if __name__ == "__main__":
    main()
