# CAPRA hybrid architecture example

The example dataset models one connected AWS, Amazon EKS, Google Cloud, and Azure environment. It is synthetic, but the CVE, package, affected-version, fixed-version, CVSS, and CWE data are aligned with official vulnerability records.

## Architecture

```text
AWS developer
  -> AssumeRole -> DevOpsRole
  -> EC2LaunchPolicy -> bootstrap-runner
  -> PassRole -> EKSNodeRole
       |-> network -> checkout-api Pod
       |     |-> mounted checkout ServiceAccount
       |     |     |-> exec / port-forward -> payment-api Pod
       |     |     |-> read -> payment-db Secret
       |     |     `-> create workload -> prod-eks
       |     |-> access -> EC2 IMDS
       |     `-> OpenSSL 1.1.1m / CVE-2022-0778
       |-> network -> payment-api Pod
       |     `-> log4j-core 2.14.1 / CVE-2021-44228
       `-> impersonate -> GCP analytics-exporter ServiceAccount
             |-> read -> analytics-api-key Secret
             `-> modify policy -> audit-archive Bucket

Public Internet Client
  `-> unauthenticated access candidate -> prod-eks API

Azure release-engineer
  `-> add secret -> deployment-bot application
        `-> add member -> production-operators group
```

The Layer 1 fixture contains 21 nodes, 21 directed multi-edges, two mapped vulnerabilities, and three entry points. Parallel Kubernetes edges between the same ServiceAccount and Pod are intentionally included to exercise `MultiDiGraph` handling.

## Input files

- `layer1/hound_generic_sample.json`: IAMHoundDog, Generic Hound, ClusterHound, GCPHound, and AzureHound facts in one normalized graph input.
- `layer1/grype_sample.json`: OpenSSL and Log4j findings in Grype JSON form.
- `layer1/grype_sample.sarif`: The same two findings in SARIF form.
- `layer1/important_assets.yaml`: Critical and high-value assets plus entry points.
- `layer1/vulnerability_mapping.yaml`: Explicit package/CVE-to-Pod mappings.
- `layer1/architecture.drawio`: Optional, minimal architecture-diagram input.
- `layer1/cross_cloud_edges.yaml`: Optional AWS/GCP/Azure/Kubernetes dependency facts. They are not classified as attack paths in Layer 1.
- `layer1/fact_graph_sample.json`: Generated Layer 1 output.
- `layer2/nvd/*.json`: Compact, offline NVD response fixtures.
- `layer2/fact_graph_sample.json`: Layer 2 input, identical to the generated Layer 1 output.
- `layer2/attack_operator_graph_sample.json`: Generated Layer 2 output with 17 Operators and 13 forward, subject-specific Capability connections.
- `layer2/connection_example.json`: A valid forward `network_reachability` produces/requires connection.
- `layer2/invalid_node_match_only.json`: A DoS and credential-acquisition pair that must not connect from Node context alone.
- `layer2/iamhounddog_full_match.json` / `iamhounddog_partial_match.json`: Complete and missing-permission pattern inputs.
- `layer2/cve_operator_example.json`, `manual_verification_required.json`, `unresolved_item.json`, `layer3_candidates.json`: Focused output examples.

Layer 2 never treats `target_node == source_node` as sufficient causality. Forward `enables` connections require matching `effects`/`preconditions` or matching `produces`/`requires` artifacts, including the same `subject_node_id`. `requires` remains an Operator attribute and is not emitted as a reverse connection.

## Vulnerability consistency

| CVE | Component | Installed | Fixed | CVSS | Layer 2 type |
| --- | --- | --- | --- | --- | --- |
| CVE-2022-0778 | OpenSSL | 1.1.1m | 1.1.1n | 7.5 High | `denial_of_service` |
| CVE-2021-44228 | log4j-core | 2.14.1 | 2.15.0 | 10.0 Critical | `remote_code_execution` |

Sources:

- [NVD CVE-2022-0778](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-0778)
- [OpenSSL 1.1.1 release notes](https://mirror.openssl-library.org/news/openssl-1.1.1-notes/)
- [NVD CVE-2021-44228](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228)
- [Apache Log4j security page](https://logging.apache.org/security.html#CVE-2021-44228)

## Validation

Run `pytest` from the repository root. The suite checks that the Layer 1 fixture remains readable by the Layer 2 loader and that the saved Layer 1/Layer 2 Fact Graph inputs remain identical. New Fact Graph output can also be built and downloaded from the Streamlit UI.
