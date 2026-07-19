import streamlit as st
import json
import pandas as pd
from pyvis.network import Network
import tempfile
import os
from pathlib import Path

from capra.layer1.exporters import (
    export_edges_dataframe,
    export_fact_graph_json,
    export_nodes_dataframe,
    export_vulnerabilities_dataframe,
)
from capra.layer1.graph_builder import build_layer1_fact_graph
from capra.layer1.parsers.drawio_parser import parse_drawio_to_layer1
from capra.layer1.parsers.grype_parser import parse_grype_json, parse_grype_sarif
from capra.layer1.parsers.hound_parser import parse_hound_generic
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

# --- UI settings ---
st.set_page_config(page_title="CAPRA", layout="wide")
st.title("CAPRA: Cloud Attack Path Risk Analyzer")
st.header("Layer 1: Fact Extraction")

st.caption("Grype、Hound系JSON、重要資産候補定義を共通Fact Graphへ統合します。Draw.ioは任意入力です。")

layer1_grype = st.file_uploader("Grype JSON/SARIF", type=["json", "sarif"], key="layer1_grype")
layer1_hound = st.file_uploader("Hound generic JSON", type=["json"], key="layer1_hound")
layer1_assets = st.file_uploader("重要資産候補 YAML/JSON", type=["yaml", "yml", "json"], key="layer1_assets")
layer1_mapping = st.file_uploader("任意のCVE-to-node mapping YAML/JSON", type=["yaml", "yml", "json"], key="layer1_mapping")
layer1_drawio = st.file_uploader("任意のDraw.io XML/.drawio", type=["xml", "drawio"], key="layer1_drawio")

layer1_nodes = []
layer1_edges = []
layer1_vulnerabilities = []
layer1_asset_config = {}
layer1_mapping_config = {}
layer1_source_files = []
layer1_parse_errors = []

try:
    if layer1_grype:
        grype_text = layer1_grype.getvalue().decode("utf-8")
        grype_data = json.loads(grype_text)
        layer1_vulnerabilities = (
            parse_grype_sarif(grype_data)
            if layer1_grype.name.lower().endswith(".sarif") or "runs" in grype_data
            else parse_grype_json(grype_data)
        )
        layer1_source_files.append(layer1_grype.name)
    if layer1_hound:
        hound_data = json.loads(layer1_hound.getvalue().decode("utf-8"))
        hound_nodes, hound_edges = parse_hound_generic(hound_data)
        layer1_nodes.extend(hound_nodes)
        layer1_edges.extend(hound_edges)
        layer1_source_files.append(layer1_hound.name)
    if layer1_assets:
        layer1_asset_config = load_json_or_yaml(layer1_assets.getvalue().decode("utf-8"), layer1_assets.name)
        layer1_source_files.append(layer1_assets.name)
    if layer1_mapping:
        layer1_mapping_config = load_json_or_yaml(layer1_mapping.getvalue().decode("utf-8"), layer1_mapping.name)
        layer1_source_files.append(layer1_mapping.name)
    if layer1_drawio:
        drawio_nodes, drawio_edges = parse_drawio_to_layer1(layer1_drawio.getvalue().decode("utf-8"))
        layer1_nodes.extend(drawio_nodes)
        layer1_edges.extend(drawio_edges)
        layer1_source_files.append(layer1_drawio.name)
except Exception as exc:
    layer1_parse_errors.append(str(exc))

asset_goal_candidates = [
    asset.get("id") or generate_node_id(asset.get("name"), asset.get("type", "unknown"), asset.get("cloud", "unknown"))
    for asset in layer1_asset_config.get("assets", []) or []
]
node_goal_candidates = [node.id for node in layer1_nodes if node.goal_candidate]
goal_options = sorted(set(asset_goal_candidates + node_goal_candidates))
selected_layer1_goals = st.multiselect(
    "今回Goalとして扱う重要資産候補",
    options=goal_options,
    help="未選択でもFact Graphは生成できます。重要資産候補はデフォルトでは固定Goalになりません。",
)

if layer1_parse_errors:
    st.error("Layer 1 input parse error: " + "; ".join(layer1_parse_errors))

if st.button("Build Layer 1 Fact Graph"):
    if not (layer1_grype or layer1_hound or layer1_assets or layer1_drawio):
        st.warning("Layer 1入力を少なくとも1つアップロードしてください。")
    else:
        try:
            fact_graph = build_layer1_fact_graph(
                layer1_nodes,
                layer1_edges,
                layer1_vulnerabilities,
                asset_config=layer1_asset_config,
                vulnerability_mapping_config=layer1_mapping_config,
                selected_goal_ids=set(selected_layer1_goals),
                source_files=layer1_source_files,
            )
            fact_json = export_fact_graph_json(fact_graph)
            st.session_state["layer1_fact_graph"] = fact_json
            nodes_df = export_nodes_dataframe(fact_graph)
            edges_df = export_edges_dataframe(fact_graph)
            vulns_df = export_vulnerabilities_dataframe(fact_graph)

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Nodes", fact_json["metadata"]["node_count"])
            m2.metric("Edges", fact_json["metadata"]["edge_count"])
            m3.metric("CVEs", fact_json["metadata"]["vulnerability_count"])
            m4.metric("Unmapped CVEs", fact_json["metadata"]["unmapped_vulnerability_count"])

            st.subheader("Layer 1 Node Table")
            st.dataframe(nodes_df)
            st.subheader("Layer 1 Edge Table")
            st.dataframe(edges_df)
            st.subheader("Layer 1 Vulnerability Table")
            st.dataframe(vulns_df)

            st.subheader("Layer 1 Fact Graph")
            layer1_net = Network(height="520px", width="100%", bgcolor="#ffffff", directed=True)
            for node_id, data in fact_graph.nodes(data=True):
                color = "#FFDCDC" if data.get("is_goal") else "#FFF3CD" if data.get("goal_candidate") else "#DCEBFF"
                layer1_net.add_node(node_id, label=data.get("name", node_id), title=json.dumps(data, ensure_ascii=False), color=color)
            for source, target, data in fact_graph.edges(data=True):
                layer1_net.add_edge(
                    source,
                    target,
                    label=data.get("type", ""),
                    title=json.dumps(data, ensure_ascii=False),
                    color="#C7CED8",
                )
            with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
                layer1_net.save_graph(tmp_file.name)
                html_content = open(tmp_file.name, "r", encoding="utf-8").read()
                st.components.v1.html(html_content, height=540)
                os.remove(tmp_file.name)

            st.download_button(
                "Download Layer 1 Fact Graph JSON",
                data=json.dumps(fact_json, indent=2, ensure_ascii=False),
                file_name="layer1_fact_graph.json",
                mime="application/json",
            )
        except Exception as exc:
            st.error(f"Layer 1 graph build failed: {exc}")


st.divider()
st.header("Layer 2: Attack Operator Modeling")
st.caption("Fact Graphを攻撃操作候補へ変換します。Layer 2は攻撃成功を判定せず、コマンドやペイロードも生成しません。")

layer2_fact_upload = st.file_uploader("Layer 1 Fact Graph JSON", type=["json"], key="layer2_fact_graph")
layer2_rule_upload = st.file_uploader("任意のIAMHoundDog Rule YAML", type=["yaml", "yml"], key="layer2_iamhounddog_rule")

config_column_1, config_column_2, config_column_3 = st.columns(3)
with config_column_1:
    layer2_nvd_mode = st.selectbox("NVD mode", ["cache-only", "cache-then-fetch"])
    layer2_cache_directory = st.text_input("NVD cache directory", "cache/nvd")
    layer2_max_hops = st.number_input("最大ホップ数", min_value=1, max_value=20, value=6)
    layer2_max_matches = st.number_input("Ruleごとの最大マッチ件数", min_value=1, value=100)
with config_column_2:
    layer2_max_operators = st.number_input("最大Operator数", min_value=1, value=1000)
    layer2_max_connections = st.number_input("最大Connection数", min_value=1, value=5000)
    layer2_max_candidates = st.number_input("最大Layer 3候補数", min_value=1, value=500)
    layer2_max_upload_mb = st.number_input("最大アップロードサイズ (MiB)", min_value=1, value=10)
with config_column_3:
    layer2_source_tools = st.multiselect(
        "対象source_tool（未選択はすべて）",
        ["iamhounddog", "azurehound", "gcp_hound", "clusterhound", "nvd", "grype"],
    )
    layer2_operator_types_text = st.text_area(
        "対象operator_type（任意、カンマ区切り）",
        help="空欄の場合はすべてのOperator typeを対象にします。",
    )

if st.button("Build Layer 2 Attack Operator Graph"):
    rule_temp_path = None
    try:
        max_upload_bytes = int(layer2_max_upload_mb) * 1024 * 1024
        if layer2_fact_upload:
            fact_bytes = layer2_fact_upload.getvalue()
            if len(fact_bytes) > max_upload_bytes:
                raise ValueError("Layer 1 Fact Graph JSON exceeds the configured upload-size limit")
            layer2_fact_data = json.loads(fact_bytes.decode("utf-8"))
        else:
            layer2_fact_data = st.session_state.get("layer1_fact_graph")
        if not layer2_fact_data:
            st.warning("Layer 1 Fact Graph JSONをアップロードするか、Layer 1を先に実行してください。")
        else:
            if layer2_rule_upload:
                rule_bytes = layer2_rule_upload.getvalue()
                if len(rule_bytes) > max_upload_bytes:
                    raise ValueError("IAMHoundDog rule YAML exceeds the configured upload-size limit")
                with tempfile.NamedTemporaryFile(delete=False, suffix=".yaml") as rule_file:
                    rule_file.write(rule_bytes)
                    rule_temp_path = rule_file.name
            selected_operator_types = [item.strip() for item in layer2_operator_types_text.split(",") if item.strip()]
            layer2_config = Layer2Config(
                nvd_mode=layer2_nvd_mode,
                nvd_cache_directory=Path(layer2_cache_directory),
                max_hops=int(layer2_max_hops),
                max_matches_per_rule=int(layer2_max_matches),
                max_total_operators=int(layer2_max_operators),
                max_connections=int(layer2_max_connections),
                max_candidates=int(layer2_max_candidates),
                max_uploaded_file_size=max_upload_bytes,
                selected_source_tools=layer2_source_tools,
                selected_operator_types=selected_operator_types,
                iamhounddog_rule_path=Path(rule_temp_path) if rule_temp_path else None,
            )
            layer2_graph = build_attack_operator_graph(layer2_fact_data, layer2_config)
            st.session_state["layer2_attack_operator_graph"] = layer2_graph
            metadata = layer2_graph.metadata

            metrics = [
                ("Fact Nodes", metadata["fact_node_count"]),
                ("Fact Edges", metadata["fact_edge_count"]),
                ("Operators", metadata["operator_count"]),
                ("IAM Operators", metadata["iam_operator_count"]),
                ("CVE Operators", metadata["cve_operator_count"]),
                ("Connections", metadata["connection_count"]),
                ("Unresolved", metadata["unresolved_count"]),
                ("Manual verification", metadata["manual_verification_count"]),
                ("NVD cache hits", metadata["nvd_cache_hit_count"]),
                ("NVD cache misses", metadata["nvd_cache_miss_count"]),
                ("NVD fetch failures", metadata["nvd_fetch_failure_count"]),
                ("Processing ms", metadata["processing_time_ms"]),
            ]
            for offset in range(0, len(metrics), 4):
                columns = st.columns(4)
                for column, (label, value) in zip(columns, metrics[offset : offset + 4]):
                    column.metric(label, value)

            st.subheader("source_tool別Edge数")
            st.json(metadata["source_tool_edge_counts"])
            st.subheader("Edge classification別件数")
            st.json(metadata["edge_classification_counts"])
            if metadata["warnings"]:
                st.warning("; ".join(metadata["warnings"]))
            operators_df = export_operators_dataframe(layer2_graph)
            st.subheader("Attack Operator一覧")
            st.dataframe(operators_df)
            st.subheader("IAM由来Operator一覧")
            st.dataframe(operators_df[operators_df["origin_kind"] != "cve"] if not operators_df.empty else operators_df)
            st.subheader("CVE由来Operator一覧")
            st.dataframe(operators_df[operators_df["origin_kind"] == "cve"] if not operators_df.empty else operators_df)
            st.subheader("Connection一覧")
            st.dataframe(export_connections_dataframe(layer2_graph))
            st.subheader("Unresolved items")
            st.dataframe(export_unresolved_dataframe(layer2_graph))
            st.subheader("Manual verification一覧")
            st.dataframe(operators_df[operators_df["manual_verification_required"]] if not operators_df.empty else operators_df)
            st.subheader("Layer 3候補一覧")
            st.dataframe(export_layer3_candidates_dataframe(layer2_graph))
            st.subheader("Attack Operator Graph")
            st.components.v1.html(build_attack_operator_graph_html(layer2_graph), height=580)
            st.download_button(
                "Download Attack Operator Graph JSON",
                data=serialize_attack_operator_graph_json(layer2_graph),
                file_name="attack_operator_graph.json",
                mime="application/json",
            )
    except json.JSONDecodeError as exc:
        st.error(f"Layer 2 JSON parse error: {exc}")
    except Exception as exc:
        st.error(f"Layer 2 graph build failed: {exc}")
    finally:
        if rule_temp_path and os.path.exists(rule_temp_path):
            os.remove(rule_temp_path)
