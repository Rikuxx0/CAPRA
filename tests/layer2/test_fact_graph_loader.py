from capra.layer2.fact_graph_loader import load_fact_graph


def test_fact_graph_loader_normalizes_old_schema_and_redacts():
    graph, unresolved, warnings = load_fact_graph(
        {
            "nodes": [{"id": "a", "vulnerabilities": [], "raw_evidence": {"token": "value"}}, {"id": "b"}],
            "edges": [{"source": "a", "target": "b", "type": "AZAddSecret", "source_tool": "unknown", "raw_evidence": {"password": "pw"}}],
            "metadata": {"schema_status": "provisional", "source_files": ["old.json"]},
        }
    )
    assert not warnings
    assert graph.edges[0]["source_tool"] == "azurehound"
    assert graph.edges[0]["fact_id"].startswith("fact:")
    assert graph.edges[0]["source_file"] == "old.json"
    assert graph.edges[0]["raw_evidence"]["password"] == "[REDACTED]"
    assert graph.nodes[0]["raw_evidence"]["token"] == "[REDACTED]"
    assert not unresolved


def test_invalid_edge_and_unknown_source_are_preserved_as_unresolved():
    graph, unresolved, _ = load_fact_graph(
        {"nodes": [{"id": "a"}], "edges": [{"source": "a", "type": "mystery"}, {"source": "a", "target": "b", "type": "mystery"}]}
    )
    assert len(graph.edges) == 1
    assert {item.type for item in unresolved} == {"invalid_fact_edge", "unknown_source_tool"}
