from __future__ import annotations

import json

from pyvis.network import Network

from .schemas import AttackOperatorGraphModel, AttackOperatorModel

ORIGIN_COLORS = {
    "cve": "#F6B3B3",
    "iam_direct_edge": "#AFCBFF",
    "iam_pattern": "#B7E4C7",
}
FACT_NODE_COLOR = "#E8EDF3"
FACT_NODE_PREFIX = "fact_node:"
CONTEXT_EDGE_COLOR = "#8A94A3"
DETAIL_PANEL_ID = "capra-node-detail-panel"


def _build_operator_label(operator: AttackOperatorModel) -> str:
    operator_type = str(operator.operator_type or "unknown")
    source_node = str(operator.source_node or "-")
    target_node = str(operator.target_node or "-")
    return f"{operator_type}\nsource: {source_node}\ntarget: {target_node}"


def _fact_node_visual_id(node_id: str) -> str:
    return f"{FACT_NODE_PREFIX}{node_id}"


def _inject_click_detail_panel(html: str, node_details: dict[str, object]) -> str:
    details_json = json.dumps(node_details, ensure_ascii=False, sort_keys=True)
    details_json = (
        details_json.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )
    panel = f"""
<style>
  #{DETAIL_PANEL_ID} {{
    position: fixed;
    top: 16px;
    right: 16px;
    z-index: 1000;
    width: min(640px, calc(100vw - 32px));
    max-height: calc(100vh - 32px);
    overflow: auto;
    padding: 14px;
    border: 1px solid #C7CED8;
    border-radius: 8px;
    background: rgba(255, 255, 255, 0.98);
    box-shadow: 0 4px 18px rgba(0, 0, 0, 0.18);
  }}
  #{DETAIL_PANEL_ID}[hidden] {{
    display: none;
  }}
  #{DETAIL_PANEL_ID} .capra-detail-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 10px;
  }}
  #{DETAIL_PANEL_ID} pre {{
    margin: 0;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    font-size: 12px;
  }}
</style>
<aside id="{DETAIL_PANEL_ID}" hidden>
  <div class="capra-detail-header">
    <strong id="capra-node-detail-title">Node details</strong>
    <button id="capra-node-detail-close" type="button">閉じる</button>
  </div>
  <pre id="capra-node-detail-content"></pre>
</aside>
<script>
  const capraNodeDetails = {details_json};
  const capraDetailPanel = document.getElementById("{DETAIL_PANEL_ID}");
  const capraDetailTitle = document.getElementById("capra-node-detail-title");
  const capraDetailContent = document.getElementById("capra-node-detail-content");
  const capraDetailClose = document.getElementById("capra-node-detail-close");

  network.once("stabilizationIterationsDone", function () {{
    network.setOptions({{ physics: false }});
  }});

  network.on("click", function (params) {{
    if (!params.nodes || params.nodes.length === 0) {{
      return;
    }}
    const nodeId = params.nodes[0];
    const details = capraNodeDetails[nodeId];
    if (!details) {{
      return;
    }}
    capraDetailTitle.textContent = nodeId;
    capraDetailContent.textContent = JSON.stringify(details, null, 2);
    capraDetailPanel.hidden = false;
  }});

  capraDetailClose.addEventListener("click", function () {{
    capraDetailPanel.hidden = true;
  }});
</script>
"""
    if "</body>" in html:
        return html.replace("</body>", f"{panel}</body>", 1)
    return f"{html}{panel}"


def build_attack_operator_graph_html(graph: AttackOperatorGraphModel) -> str:
    network = Network(height="560px", width="100%", bgcolor="#ffffff", directed=True)
    node_details: dict[str, object] = {}

    fact_node_ids = sorted(
        {
            node_id
            for operator in graph.attack_operators
            for node_id in (operator.source_node, operator.target_node)
            if node_id
        }
    )
    for node_id in fact_node_ids:
        visual_id = _fact_node_visual_id(node_id)
        node_details[visual_id] = {
            "kind": "fact_node",
            "node_id": node_id,
        }
        network.add_node(
            visual_id,
            label=node_id,
            color=FACT_NODE_COLOR,
            shape="ellipse",
        )

    for operator in graph.attack_operators:
        node_details[operator.id] = operator.model_dump(mode="json")
        color = ORIGIN_COLORS.get(operator.origin_kind, "#D9D9D9")
        if operator.status == "partial":
            color = "#FFE08A"
        if operator.manual_verification_required:
            color = "#D7B5F5"
        network.add_node(
            operator.id,
            label=_build_operator_label(operator),
            color=color,
            shape="box",
        )
        if operator.source_node:
            network.add_edge(
                _fact_node_visual_id(operator.source_node),
                operator.id,
                label="source",
                title="Fact Graph source_node for this operator",
                color=CONTEXT_EDGE_COLOR,
                arrows="to",
                dashes=True,
            )
        if operator.target_node:
            network.add_edge(
                operator.id,
                _fact_node_visual_id(operator.target_node),
                label="target",
                title="Fact Graph target_node for this operator",
                color=CONTEXT_EDGE_COLOR,
                arrows="to",
                dashes=True,
            )

    for connection in graph.connections:
        color = "#5B8FF9" if connection.connection_type == "enables" else "#9B6BCB"
        network.add_edge(
            connection.source_operator_id,
            connection.target_operator_id,
            label=connection.connection_type,
            title=connection.reason,
            color=color,
            arrows="to",
        )
    network.set_options(
        '{"physics":{"stabilization":{"iterations":150},"barnesHut":{"springLength":50,'
        '"springConstant":0.01,"avoidOverlap":0.8}},"interaction":{"hover":false},'
        '"edges":{"smooth":{"type":"dynamic"}}}'
    )
    return _inject_click_detail_panel(
        network.generate_html(notebook=False),
        node_details,
    )
