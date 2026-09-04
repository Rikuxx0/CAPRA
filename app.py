import hashlib
import json
import os
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st
from pyvis.network import Network

from capra.layer1.parsers.dependency_parser import parse_cross_cloud_dependencies
from capra.layer1.parsers.drawio_parser import parse_drawio_to_layer1
from capra.layer1.parsers.grype_parser import parse_grype_json, parse_grype_sarif
from capra.layer1.parsers.hound_parser import parse_hound_generic
from capra.layer1.redaction import redact_sensitive_data
from capra.layer1.utils.file_loader import load_json_or_yaml
from capra.layer1.utils.ids import generate_node_id
from capra.layer2.exporter import (
    export_connections_dataframe,
    export_layer3_candidates_dataframe,
    export_operators_dataframe,
    export_unresolved_dataframe,
    serialize_attack_operator_graph_json,
)
from capra.layer2.schemas import Layer2Config
from capra.layer2.service import build_attack_operator_graph
from capra.layer2.visualization import build_attack_operator_graph_html
from capra.planner import build_capra_plan

PLANNER_STATE_KEYS = (
    "layer1_fact_graph",
    "layer2_attack_operator_graph",
    "layer1_layer2_handoff_hash",
    "planner_input_mode",
)


def clear_planner_results() -> None:
    for key in PLANNER_STATE_KEYS:
        st.session_state.pop(key, None)


def _fact_graph_frames(
    payload: dict,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    node_rows = []
    vulnerability_rows = []
    for node in payload.get("nodes", []):
        row = dict(node)
        vulnerabilities = row.pop("vulnerabilities", [])
        row.pop("raw_evidence", None)
        row["vulnerability_count"] = len(vulnerabilities)
        node_rows.append(row)
        for vulnerability in vulnerabilities:
            vulnerability_row = dict(vulnerability)
            vulnerability_row["node_id"] = node.get("id")
            vulnerability_row["node_name"] = node.get("name")
            vulnerability_row.pop("raw_evidence", None)
            vulnerability_rows.append(vulnerability_row)

    edge_rows = []
    for edge in payload.get("edges", []):
        row = dict(edge)
        row.pop("raw_evidence", None)
        edge_rows.append(row)

    for vulnerability in payload.get("unmapped_vulnerabilities", []):
        row = dict(vulnerability)
        row["node_id"] = None
        row["node_name"] = None
        row["unmapped"] = True
        row.pop("raw_evidence", None)
        vulnerability_rows.append(row)

    return (
        pd.DataFrame(node_rows),
        pd.DataFrame(edge_rows),
        pd.DataFrame(vulnerability_rows),
    )


def _build_fact_graph_html(payload: dict) -> str:
    network = Network(
        height="520px",
        width="100%",
        bgcolor="#ffffff",
        directed=True,
    )
    for node in payload.get("nodes", []):
        node_id = str(node.get("id") or "")
        if not node_id:
            continue
        color = (
            "#FFDCDC"
            if node.get("is_goal")
            else "#FFF3CD"
            if node.get("goal_candidate")
            else "#DCEBFF"
        )
        network.add_node(
            node_id,
            label=node.get("name") or node_id,
            title=json.dumps(node, ensure_ascii=False),
            color=color,
        )
    for edge in payload.get("edges", []):
        source = edge.get("source")
        target = edge.get("target")
        if not source or not target:
            continue
        network.add_edge(
            source,
            target,
            label=edge.get("type", ""),
            title=json.dumps(edge, ensure_ascii=False),
            color="#C7CED8",
            length=200,
        )
    return network.generate_html(notebook=False)


def _render_metrics(metrics: list[tuple[str, object]]) -> None:
    for offset in range(0, len(metrics), 4):
        columns = st.columns(4)
        for column, (label, value) in zip(columns, metrics[offset : offset + 4]):
            column.metric(label, value)


def _render_planner_results() -> None:
    fact_graph = st.session_state.get("layer1_fact_graph")
    operator_graph = st.session_state.get("layer2_attack_operator_graph")
    if not fact_graph or operator_graph is None:
        return

    fact_metadata = fact_graph.get("metadata", {})
    operator_metadata = operator_graph.metadata
    st.header("Plan Results")
    st.caption("最後に実行したPlannerの結果です。")

    handoff_hash = st.session_state.get("layer1_layer2_handoff_hash")
    if handoff_hash:
        st.success(f"Fact handoff verified: {handoff_hash[:12]}…")
    else:
        st.info("Imported Fact Graphを互換loaderで処理しました。")

    _render_metrics(
        [
            (
                "Fact Nodes",
                fact_metadata.get("node_count", len(fact_graph.get("nodes", []))),
            ),
            (
                "Fact Edges",
                fact_metadata.get("edge_count", len(fact_graph.get("edges", []))),
            ),
            ("CVEs", fact_metadata.get("vulnerability_count", 0)),
            ("Operators", operator_metadata.get("operator_count", 0)),
            ("Connections", operator_metadata.get("connection_count", 0)),
            ("Unresolved", operator_metadata.get("unresolved_count", 0)),
            (
                "Manual verification",
                operator_metadata.get("manual_verification_count", 0),
            ),
            (
                "Layer 3 Candidates",
                operator_metadata.get("layer3_candidate_count", 0),
            ),
        ]
    )

    warnings = operator_metadata.get("warnings", [])
    if warnings:
        st.warning("; ".join(warnings))

    overview_tab, facts_tab, operators_tab, review_tab, export_tab = st.tabs(
        ["Overview", "Facts", "Attack operators", "Review queue", "Export"]
    )
    with overview_tab:
        summary_column, classification_column = st.columns(2)
        with summary_column:
            st.subheader("Source summary")
            st.json(operator_metadata.get("source_tool_edge_counts", {}))
        with classification_column:
            st.subheader("Fact classification")
            st.json(operator_metadata.get("edge_classification_counts", {}))
        st.subheader("Attack Operator Graph")
        st.components.v1.html(
            build_attack_operator_graph_html(operator_graph),
            height=565,
            width=max,
        )

    nodes_df, edges_df, vulnerabilities_df = _fact_graph_frames(fact_graph)
    with facts_tab:
        st.subheader("Fact Graph")
        st.components.v1.html(_build_fact_graph_html(fact_graph), height=540)
        st.subheader("Nodes")
        st.dataframe(nodes_df, use_container_width=True)
        st.subheader("Edges")
        st.dataframe(edges_df, use_container_width=True)
        st.subheader("Vulnerabilities")
        st.dataframe(vulnerabilities_df, use_container_width=True)

    operators_df = export_operators_dataframe(operator_graph)
    with operators_tab:
        st.subheader("All operators")
        st.dataframe(operators_df, use_container_width=True)
        iam_operators = (
            operators_df[operators_df["origin_kind"] != "cve"]
            if not operators_df.empty
            else operators_df
        )
        cve_operators = (
            operators_df[operators_df["origin_kind"] == "cve"]
            if not operators_df.empty
            else operators_df
        )
        st.subheader("IAM / RBAC operators")
        st.dataframe(iam_operators, use_container_width=True)
        st.subheader("CVE operators")
        st.dataframe(cve_operators, use_container_width=True)
        st.subheader("Connections")
        st.dataframe(
            export_connections_dataframe(operator_graph),
            use_container_width=True,
        )

    with review_tab:
        st.subheader("Unresolved items")
        st.dataframe(
            export_unresolved_dataframe(operator_graph),
            use_container_width=True,
        )
        manual_operators = (
            operators_df[operators_df["manual_verification_required"]]
            if not operators_df.empty
            else operators_df
        )
        st.subheader("Manual verification")
        st.dataframe(manual_operators, use_container_width=True)
        st.subheader("Layer 3 candidates")
        st.dataframe(
            export_layer3_candidates_dataframe(operator_graph),
            use_container_width=True,
        )

    with export_tab:
        st.download_button(
            "Download Fact Graph JSON",
            data=json.dumps(fact_graph, indent=2, ensure_ascii=False),
            file_name="fact_graph.json",
            mime="application/json",
        )
        st.download_button(
            "Download Attack Operator Graph JSON",
            data=serialize_attack_operator_graph_json(operator_graph),
            file_name="attack_operator_graph.json",
            mime="application/json",
        )


st.set_page_config(page_title="CAPRA Planner", layout="wide")
st.title("CAPRA: Cloud Attack Path Risk Analyzer")
st.header("CAPRA Planner")
st.caption(
    "観測データをFact Graphへ正規化し、未検証のAttack Operator候補まで一括生成します。"
)

input_mode = st.radio(
    "Input mode",
    ["ソースファイル", "既存Fact Graph JSON"],
    horizontal=True,
    on_change=clear_planner_results,
)

layer1_nodes = []
layer1_edges = []
layer1_vulnerabilities = []
layer1_asset_config = {}
layer1_mapping_config = {}
layer1_source_files = []
layer1_input_hashes = {}
layer1_parse_errors = []
selected_layer1_goals = []
fact_graph_upload = None


def record_source_input(upload) -> bytes:
    content = upload.getvalue()
    layer1_source_files.append(upload.name)
    layer1_input_hashes[upload.name] = hashlib.sha256(content).hexdigest()
    return content


if input_mode == "ソースファイル":
    st.subheader("Inputs")
    input_column_1, input_column_2 = st.columns(2)
    with input_column_1:
        layer1_grype = st.file_uploader(
            "Grype JSON/SARIF",
            type=["json", "sarif"],
            key="layer1_grype",
        )
        layer1_hound = st.file_uploader(
            "Hound generic JSON",
            type=["json"],
            key="layer1_hound",
        )
        layer1_assets = st.file_uploader(
            "重要資産候補 YAML/JSON",
            type=["yaml", "yml", "json"],
            key="layer1_assets",
        )
    with input_column_2:
        layer1_mapping = st.file_uploader(
            "任意のCVE-to-node mapping YAML/JSON",
            type=["yaml", "yml", "json"],
            key="layer1_mapping",
        )
        layer1_drawio = st.file_uploader(
            "任意のDraw.io XML/.drawio",
            type=["xml", "drawio"],
            key="layer1_drawio",
        )
        layer1_dependencies = st.file_uploader(
            "任意のクラウド間依存関係 YAML/JSON",
            type=["yaml", "yml", "json"],
            key="layer1_dependencies",
        )

    try:
        if layer1_grype:
            grype_text = record_source_input(layer1_grype).decode("utf-8")
            grype_data = json.loads(grype_text)
            layer1_vulnerabilities = (
                parse_grype_sarif(grype_data, source_file=layer1_grype.name)
                if layer1_grype.name.lower().endswith(".sarif")
                or "runs" in grype_data
                else parse_grype_json(grype_data, source_file=layer1_grype.name)
            )
        if layer1_hound:
            hound_data = json.loads(
                record_source_input(layer1_hound).decode("utf-8")
            )
            hound_nodes, hound_edges = parse_hound_generic(
                hound_data,
                source_file=layer1_hound.name,
            )
            layer1_nodes.extend(hound_nodes)
            layer1_edges.extend(hound_edges)
        if layer1_assets:
            layer1_asset_config = load_json_or_yaml(
                record_source_input(layer1_assets).decode("utf-8"),
                layer1_assets.name,
            )
        if layer1_mapping:
            layer1_mapping_config = load_json_or_yaml(
                record_source_input(layer1_mapping).decode("utf-8"),
                layer1_mapping.name,
            )
        if layer1_drawio:
            drawio_nodes, drawio_edges = parse_drawio_to_layer1(
                record_source_input(layer1_drawio).decode("utf-8"),
                source_file=layer1_drawio.name,
            )
            layer1_nodes.extend(drawio_nodes)
            layer1_edges.extend(drawio_edges)
        if layer1_dependencies:
            dependency_data = load_json_or_yaml(
                record_source_input(layer1_dependencies).decode("utf-8"),
                layer1_dependencies.name,
            )
            dependency_nodes, dependency_edges = parse_cross_cloud_dependencies(
                dependency_data,
                source_file=layer1_dependencies.name,
            )
            layer1_nodes.extend(dependency_nodes)
            layer1_edges.extend(dependency_edges)
    except Exception as exc:
        layer1_parse_errors.append(str(exc))

    asset_goal_candidates = [
        asset.get("id")
        or generate_node_id(
            asset.get("name"),
            asset.get("type", "unknown"),
            asset.get("cloud", "unknown"),
        )
        for asset in layer1_asset_config.get("assets", []) or []
    ]
    node_goal_candidates = [node.id for node in layer1_nodes if node.goal_candidate]
    selected_layer1_goals = st.multiselect(
        "今回Goalとして扱う重要資産候補",
        options=sorted(set(asset_goal_candidates + node_goal_candidates)),
        help="未選択でもPlannerは実行できます。Goalは明示選択したNodeだけに設定します。",
    )
else:
    st.subheader("Input")
    fact_graph_upload = st.file_uploader(
        "Fact Graph JSON",
        type=["json"],
        key="planner_fact_graph_upload",
    )
    st.caption("旧形式を含むFact Graphは互換loaderで正規化して処理します。")

if layer1_parse_errors:
    st.error("Input parse error: " + "; ".join(layer1_parse_errors))

with st.expander("Planner settings / Additional rules"):
    config_column_1, config_column_2, config_column_3 = st.columns(3)
    with config_column_1:
        nvd_mode = st.selectbox("NVD mode", ["cache-only", "cache-then-fetch"])
        nvd_cache_directory = st.text_input("NVD cache directory", "cache/nvd")
        max_hops = st.number_input(
            "最大ホップ数",
            min_value=1,
            max_value=20,
            value=6,
        )
        max_matches = st.number_input(
            "Ruleごとの最大マッチ件数",
            min_value=1,
            value=100,
        )
    with config_column_2:
        max_operators = st.number_input(
            "最大Operator数",
            min_value=1,
            value=1000,
        )
        max_connections = st.number_input(
            "最大Connection数",
            min_value=1,
            value=5000,
        )
        max_candidates = st.number_input(
            "最大Layer 3候補数",
            min_value=1,
            value=500,
        )
        max_upload_mb = st.number_input(
            "最大アップロードサイズ (MiB)",
            min_value=1,
            value=10,
        )
    with config_column_3:
        source_tools = st.multiselect(
            "対象source_tool（未選択はすべて）",
            [
                "hound_generic",
                "iamhounddog",
                "azurehound",
                "gcp_hound",
                "clusterhound",
                "bloodhound_kube",
                "nvd",
                "grype",
            ],
        )
        operator_types_text = st.text_area(
            "対象operator_type（任意、カンマ区切り）",
            help="空欄の場合はすべてのOperator typeを対象にします。",
        )

    st.markdown("##### Additional rule YAML")
    rule_column_1, rule_column_2 = st.columns(2)
    with rule_column_1:
        hound_generic_rule_uploads = st.file_uploader(
            "Generic Hound Edge mapping YAML",
            type=["yaml", "yml"],
            accept_multiple_files=True,
            key="layer2_hound_generic_rules",
        )
        azurehound_rule_uploads = st.file_uploader(
            "AzureHound Edge mapping YAML",
            type=["yaml", "yml"],
            accept_multiple_files=True,
            key="layer2_azurehound_rules",
        )
        gcp_hound_rule_uploads = st.file_uploader(
            "GCPHound Edge mapping YAML",
            type=["yaml", "yml"],
            accept_multiple_files=True,
            key="layer2_gcp_hound_rules",
        )
    with rule_column_2:
        clusterhound_rule_uploads = st.file_uploader(
            "ClusterHound Edge mapping YAML",
            type=["yaml", "yml"],
            accept_multiple_files=True,
            key="layer2_clusterhound_rules",
        )
        iamhounddog_rule_uploads = st.file_uploader(
            "IAMHoundDog Pattern Rule YAML",
            type=["yaml", "yml"],
            accept_multiple_files=True,
            key="layer2_iamhounddog_rules",
        )
        cve_rule_uploads = st.file_uploader(
            "CVE Operator Rule YAML",
            type=["yaml", "yml"],
            accept_multiple_files=True,
            key="layer2_cve_operator_rules",
        )

run_planner = st.button(
    "Run CAPRA Planner",
    type="primary",
    use_container_width=True,
)

if run_planner:
    rule_upload_groups = {
        "hound_generic": hound_generic_rule_uploads,
        "azurehound": azurehound_rule_uploads,
        "gcp_hound": gcp_hound_rule_uploads,
        "clusterhound": clusterhound_rule_uploads,
        "iamhounddog": iamhounddog_rule_uploads,
        "cve": cve_rule_uploads,
    }
    rule_temp_paths = {rule_type: [] for rule_type in rule_upload_groups}
    try:
        if layer1_parse_errors:
            raise ValueError("Resolve input parse errors before running the Planner")
        max_upload_bytes = int(max_upload_mb) * 1024 * 1024
        total_rule_bytes = sum(
            len(upload.getvalue())
            for uploads in rule_upload_groups.values()
            for upload in uploads
        )
        if total_rule_bytes > max_upload_bytes:
            raise ValueError(
                "Combined rule YAML files exceed the configured upload-size limit"
            )
        for rule_type, uploads in rule_upload_groups.items():
            for rule_upload in uploads:
                with tempfile.NamedTemporaryFile(
                    delete=False,
                    suffix=".yaml",
                ) as rule_file:
                    rule_file.write(rule_upload.getvalue())
                    rule_temp_paths[rule_type].append(rule_file.name)

        selected_operator_types = [
            item.strip()
            for item in operator_types_text.split(",")
            if item.strip()
        ]
        planner_config = Layer2Config(
            nvd_mode=nvd_mode,
            nvd_cache_directory=Path(nvd_cache_directory),
            max_hops=int(max_hops),
            max_matches_per_rule=int(max_matches),
            max_total_operators=int(max_operators),
            max_connections=int(max_connections),
            max_candidates=int(max_candidates),
            max_uploaded_file_size=max_upload_bytes,
            selected_source_tools=source_tools,
            selected_operator_types=selected_operator_types,
            hound_generic_rule_paths=[
                Path(path) for path in rule_temp_paths["hound_generic"]
            ],
            azurehound_rule_paths=[
                Path(path) for path in rule_temp_paths["azurehound"]
            ],
            gcp_hound_rule_paths=[
                Path(path) for path in rule_temp_paths["gcp_hound"]
            ],
            clusterhound_rule_paths=[
                Path(path) for path in rule_temp_paths["clusterhound"]
            ],
            iamhounddog_rule_paths=[
                Path(path) for path in rule_temp_paths["iamhounddog"]
            ],
            cve_operator_rule_paths=[
                Path(path) for path in rule_temp_paths["cve"]
            ],
        )

        if input_mode == "ソースファイル":
            if not layer1_source_files:
                raise ValueError("入力ファイルを少なくとも1つアップロードしてください")
            plan = build_capra_plan(
                layer1_nodes,
                layer1_edges,
                layer1_vulnerabilities,
                planner_config,
                asset_config=layer1_asset_config,
                vulnerability_mapping_config=layer1_mapping_config,
                selected_goal_ids=set(selected_layer1_goals),
                source_files=layer1_source_files,
                input_hashes=layer1_input_hashes,
            )
            fact_graph = plan.fact_graph
            operator_graph = plan.attack_operator_graph
            handoff_hash = plan.handoff_hash
        else:
            if not fact_graph_upload:
                raise ValueError("Fact Graph JSONをアップロードしてください")
            fact_bytes = fact_graph_upload.getvalue()
            if len(fact_bytes) > max_upload_bytes:
                raise ValueError(
                    "Fact Graph JSON exceeds the configured upload-size limit"
                )
            fact_graph = redact_sensitive_data(
                json.loads(fact_bytes.decode("utf-8"))
            )
            operator_graph = build_attack_operator_graph(
                fact_graph,
                planner_config,
            )
            handoff_hash = None

        st.session_state["layer1_fact_graph"] = fact_graph
        st.session_state["layer2_attack_operator_graph"] = operator_graph
        st.session_state["planner_input_mode"] = input_mode
        if handoff_hash:
            st.session_state["layer1_layer2_handoff_hash"] = handoff_hash
        else:
            st.session_state.pop("layer1_layer2_handoff_hash", None)
        st.success("CAPRA Planner completed.")
    except json.JSONDecodeError as exc:
        st.error(f"Fact Graph JSON parse error: {exc}")
    except Exception as exc:
        st.error(f"Planner failed: {exc}")
    finally:
        for paths in rule_temp_paths.values():
            for rule_temp_path in paths:
                if os.path.exists(rule_temp_path):
                    os.remove(rule_temp_path)

_render_planner_results()
