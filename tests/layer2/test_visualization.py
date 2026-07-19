from capra.layer2 import visualization
from capra.layer2.schemas import AttackOperatorGraphModel, AttackOperatorModel
from capra.layer2.visualization import _build_operator_label


def test_operator_label_shows_source_and_target_nodes():
    operator = AttackOperatorModel(
        id="operator-1",
        operator_type="create_service_account_key",
        origin_kind="iam_direct_edge",
        source_tool="gcp_hound",
        source_node="gcp:user:analyst",
        target_node="gcp:serviceaccount:reporter",
        status="complete",
    )

    assert _build_operator_label(operator) == (
        "create_service_account_key\n"
        "source: gcp:user:analyst\n"
        "target: gcp:serviceaccount:reporter"
    )


def test_operator_label_marks_missing_source_node():
    operator = AttackOperatorModel(
        id="operator-2",
        operator_type="buffer_overflow",
        origin_kind="cve",
        source_tool="nvd",
        target_node="gcp:serviceaccount:reporter",
        status="partial",
    )

    assert _build_operator_label(operator) == (
        "buffer_overflow\n"
        "source: -\n"
        "target: gcp:serviceaccount:reporter"
    )


def test_visualization_reuses_fact_nodes_and_connects_operator_context(monkeypatch):
    class RecordingNetwork:
        instance = None

        def __init__(self, *args, **kwargs):
            self.nodes = []
            self.edges = []
            RecordingNetwork.instance = self

        def add_node(self, node_id, **attributes):
            self.nodes.append((node_id, attributes))

        def add_edge(self, source, target, **attributes):
            self.edges.append((source, target, attributes))

        def set_options(self, options):
            self.options = options

        def generate_html(self, notebook=False):
            return "<html></html>"

    monkeypatch.setattr(visualization, "Network", RecordingNetwork)
    graph = AttackOperatorGraphModel(
        attack_operators=[
            AttackOperatorModel(
                id="operator-1",
                operator_type="create_service_account_key",
                origin_kind="iam_direct_edge",
                source_tool="gcp_hound",
                source_node="gcp:user:analyst",
                target_node="gcp:serviceaccount:reporter",
                status="complete",
            ),
            AttackOperatorModel(
                id="operator-2",
                operator_type="buffer_overflow",
                origin_kind="cve",
                source_tool="nvd",
                target_node="gcp:serviceaccount:reporter",
                status="partial",
            ),
        ]
    )

    visualization.build_attack_operator_graph_html(graph)
    network = RecordingNetwork.instance
    fact_nodes = [
        node_id
        for node_id, _ in network.nodes
        if node_id.startswith(visualization.FACT_NODE_PREFIX)
    ]

    assert fact_nodes == [
        "fact_node:gcp:serviceaccount:reporter",
        "fact_node:gcp:user:analyst",
    ]
    assert (
        "fact_node:gcp:user:analyst",
        "operator-1",
        "source",
    ) in {
        (source, target, attributes.get("label"))
        for source, target, attributes in network.edges
    }
    assert (
        "operator-1",
        "fact_node:gcp:serviceaccount:reporter",
        "target",
    ) in {
        (source, target, attributes.get("label"))
        for source, target, attributes in network.edges
    }
    assert (
        "operator-2",
        "fact_node:gcp:serviceaccount:reporter",
        "target",
    ) in {
        (source, target, attributes.get("label"))
        for source, target, attributes in network.edges
    }
    assert all("title" not in attributes for _, attributes in network.nodes)


def test_visualization_opens_details_on_click_without_hover_tooltips():
    graph = AttackOperatorGraphModel(
        attack_operators=[
            AttackOperatorModel(
                id="operator-1",
                operator_type="buffer_overflow",
                origin_kind="cve",
                source_tool="nvd",
                target_node="gcp:serviceaccount:reporter",
                status="partial",
            )
        ]
    )

    html = visualization.build_attack_operator_graph_html(graph)

    assert 'network.on("click"' in html
    assert f'id="{visualization.DETAIL_PANEL_ID}" hidden' in html
    assert "width: min(640px, calc(100vw - 32px))" in html
    assert "capraDetailPanel.hidden = false" in html
    assert "capraDetailPanel.hidden = true" in html
    assert '"hover": false' in html or '\\"hover\\": false' in html
    assert '"operator_type": "buffer_overflow"' in html
    assert 'network.once("stabilizationIterationsDone"' in html
    assert "network.setOptions({ physics: false })" in html
