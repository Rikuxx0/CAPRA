from __future__ import annotations

import colorsys
import hashlib
import json

from pyvis.network import Network

from .schemas import AttackOperatorGraphModel, AttackOperatorModel

STATUS_BORDER_COLORS = {
    "complete": "#2D6A4F",
    "partial": "#C77D00",
    "unresolved": "#B02A37",
}
FACT_NODE_COLOR = "#E8EDF3"
FACT_NODE_PREFIX = "fact_node:"
CONTEXT_EDGE_COLOR = "#8A94A3"
DETAIL_PANEL_ID = "capra-node-detail-panel"
LEGEND_PANEL_ID = "capra-attack-type-legend"


def _build_operator_label(operator: AttackOperatorModel) -> str:
    operator_type = str(operator.operator_type or "unknown")
    source_node = str(operator.source_node or "-")
    target_node = str(operator.target_node or "-")
    return (
        f"攻撃種別: {operator_type}\n"
        f"状態: {operator.status}\n"
        f"source_tool: {operator.source_tool}\n"
        f"source: {source_node}\n"
        f"target: {target_node}"
    )


def _operator_type_color(operator_type: str) -> str:
    digest = hashlib.sha256(str(operator_type or "unknown").encode("utf-8")).digest()
    hue = int.from_bytes(digest[:2], "big") / 65535
    red, green, blue = colorsys.hls_to_rgb(hue, 0.82, 0.58)
    return f"#{round(red * 255):02X}{round(green * 255):02X}{round(blue * 255):02X}"


def _fact_node_visual_id(node_id: str) -> str:
    return f"{FACT_NODE_PREFIX}{node_id}"


def _inject_click_detail_panel(
    html: str,
    node_details: dict[str, object],
    attack_type_colors: dict[str, str],
) -> str:
    details_json = json.dumps(node_details, ensure_ascii=False, sort_keys=True)
    attack_types_json = json.dumps(attack_type_colors, ensure_ascii=False, sort_keys=True)
    details_json = (
        details_json.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )
    attack_types_json = (
        attack_types_json.replace("&", "\\u0026")
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
  #{LEGEND_PANEL_ID} {{
    position: fixed;
    left: 16px;
    bottom: 16px;
    z-index: 900;
    max-width: min(420px, calc(100vw - 32px));
    max-height: 40vh;
    overflow: auto;
    padding: 12px 14px;
    border: 1px solid #C7CED8;
    border-radius: 8px;
    background: rgba(255, 255, 255, 0.96);
    box-shadow: 0 3px 12px rgba(0, 0, 0, 0.14);
    font-size: 12px;
  }}
  #{LEGEND_PANEL_ID} .capra-legend-items {{
    display: grid;
    gap: 6px;
    margin-top: 8px;
  }}
  #{LEGEND_PANEL_ID} .capra-legend-item {{
    display: flex;
    align-items: center;
    gap: 7px;
  }}
  #{LEGEND_PANEL_ID} .capra-legend-swatch {{
    width: 14px;
    height: 14px;
    flex: 0 0 14px;
    border: 1px solid #5F6875;
    border-radius: 3px;
  }}
</style>
<aside id="{DETAIL_PANEL_ID}" hidden>
  <div class="capra-detail-header">
    <strong id="capra-node-detail-title">Node details</strong>
    <button id="capra-node-detail-close" type="button">閉じる</button>
  </div>
  <pre id="capra-node-detail-content"></pre>
</aside>
<aside id="{LEGEND_PANEL_ID}">
  <strong>攻撃種別</strong>
  <div class="capra-legend-items" id="capra-attack-type-legend-items"></div>
</aside>
<script>
  const capraNodeDetails = {details_json};
  const capraAttackTypeColors = {attack_types_json};
  const capraDetailPanel = document.getElementById("{DETAIL_PANEL_ID}");
  const capraDetailTitle = document.getElementById("capra-node-detail-title");
  const capraDetailContent = document.getElementById("capra-node-detail-content");
  const capraDetailClose = document.getElementById("capra-node-detail-close");
  const capraLegendItems = document.getElementById("capra-attack-type-legend-items");

  Object.entries(capraAttackTypeColors).forEach(function ([attackType, color]) {{
    const item = document.createElement("div");
    item.className = "capra-legend-item";
    const swatch = document.createElement("span");
    swatch.className = "capra-legend-swatch";
    swatch.style.backgroundColor = color;
    const label = document.createElement("span");
    label.textContent = attackType;
    item.appendChild(swatch);
    item.appendChild(label);
    capraLegendItems.appendChild(item);
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

  function capraStopPhysics() {{
    network.setOptions({{ physics: {{ enabled: false }} }});
  }}

  network.once("stabilizationIterationsDone", capraStopPhysics);
  window.setTimeout(capraStopPhysics, 5000);
</script>
"""
    if "</body>" in html:
        return html.replace("</body>", f"{panel}</body>", 1)
    return f"{html}{panel}"


def build_attack_operator_graph_html(graph: AttackOperatorGraphModel) -> str:
    network = Network(height="550px", width="100%", bgcolor="#ffffff", directed=True)
    node_details: dict[str, object] = {}
    attack_type_colors = {
        operator_type: _operator_type_color(operator_type)
        for operator_type in sorted({operator.operator_type for operator in graph.attack_operators})
    }

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
        background_color = attack_type_colors[operator.operator_type]
        border_color = STATUS_BORDER_COLORS.get(operator.status, "#5F6876")
        network.add_node(
            operator.id,
            label=_build_operator_label(operator),
            color={
                "background": background_color,
                "border": border_color,
                "highlight": {
                    "background": background_color,
                    "border": border_color,
                },
            },
            borderWidth=4 if operator.manual_verification_required else 2,
            shadow={"enabled": operator.manual_verification_required, "color": "#7B2CBF"},
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
        # Older exports may contain reverse ``requires`` connections. They are
        # compatibility data, not forward causal edges, so do not render them.
        if connection.connection_type != "enables":
            continue
        network.add_edge(
            connection.source_operator_id,
            connection.target_operator_id,
            label=connection.connection_type,
            title=connection.reason,
            color="#5B8FF9",
            arrows="to",
        )
    network.set_options(
        '{"layout":{"hierarchical":{"enabled":false}},'
        '"physics":{"enabled":true,"solver":"barnesHut",'
        '"stabilization":{"enabled":true,"iterations":250,"updateInterval":25,"fit":true},'
        '"barnesHut":{"gravitationalConstant":-10000,"centralGravity":0.2,'
        '"springLength":190,"springConstant":0.04,"damping":0.35,"avoidOverlap":0.6}},'
        '"interaction":{"hover":false,"dragNodes":true,"dragView":true,"zoomView":true,'
        '"navigationButtons":true},"edges":{"smooth":{"enabled":true,"type":"continuous",'
        '"roundness":0.25}}}'
    )
    return _inject_click_detail_panel(
        network.generate_html(notebook=False),
        node_details,
        attack_type_colors,
    )
