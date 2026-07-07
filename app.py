import streamlit as st
import json
import pandas as pd
from pyvis.network import Network
import tempfile
import os

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

# --- UI settings ---
st.set_page_config(page_title="CAPRA Layer 1", layout="wide")
st.title("CAPRA Layer 1: Fact Extraction")

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
