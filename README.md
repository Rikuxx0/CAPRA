# CAPRA: Cloud Attack Path Risk Analyzer

CAPRA は、クラウド環境の脆弱性情報、IAM/RBAC の関係、重要資産候補、任意の構成図・クラウド間依存情報を共通の **Layer 1 Fact Graph** に正規化し、Layer 2 で攻撃操作候補とその依存関係をモデル化するプロトタイプです。現在の Streamlit アプリでは、Layer 1 の Fact Extraction と Layer 2 の Attack Operator Graph 生成を実行できます。

## Layer 1: 事実抽出レイヤー

Layer 1は、クラウド環境から得た観測事実を共通のFact Graphへ正規化します。攻撃可能性の判定やAttack Operator生成は行わず、Layer 2が利用できる入力を作ることだけを担当します。

```text
Grype / Hound / 重要資産 / CVE mapping / Draw.io / クラウド間依存
                              ↓
                     Layer 1 Fact Graph
                              ↓
                    Layer 2 loaderへ入力
```

### 入力

| 入力 | 用途 |
| --- | --- |
| Grype JSON/SARIF | CVE、package、version、severityの抽出 |
| Hound generic JSON | AWS/GCP/Azure/KubernetesのIAM/RBAC・構成関係 |
| 重要資産 YAML/JSON | Goal候補とEntry Pointの指定 |
| CVE-to-node mapping（任意） | CVEと対象Nodeの明示対応 |
| Draw.io（任意） | 構成図のNodeと補助的な`network_access` |
| クラウド間依存 YAML/JSON（任意） | Providerをまたぐ構成・依存関係 |

Hound入力は`nodes`/`edges`形式を使用します。`source_tool`は`hound_generic`、`iamhounddog`、`gcp_hound`、`azurehound`、`clusterhound`、`bloodhound_kube`などへ正規化します。製品固有の生形式に対する専用parserは今後追加する想定です。

クラウド間依存関係は、例えば次のように記述します。

```yaml
dependencies:
  - source: "aws:secret:gcp-analytics-reference"
    target: "gcp:serviceaccount:analytics-exporter"
    type: "stores_reference_to"
    source_tool: "manual"
```

これは構成上のFactを示すだけで、攻撃経路の成立を意味しません。

### GoalとEntry Point

- `goal_candidate=True`: 重要資産候補
- `is_goal=True`: 今回ユーザーが明示的に選択したGoal
- `is_entry=True`: 侵害済み主体や公開Serviceなどの分析開始地点

重要資産を自動的にGoalにはしません。入力データ内の`is_goal`も選択結果として信用せず、今回の分析で選択されたNodeだけをGoalにします。

### CVE mapping

CVEは次の順でNodeへ対応付けます。

1. 明示的なCVE-to-node mapping
2. `raw_evidence`内のtarget/image/container/location
3. package/artifact名とNode名・IDの部分一致
4. 対応できない場合は`unmapped_vulnerabilities`へ保持

同一findingは重複排除し、対応できないCVEも破棄しません。

### Fact Graph

実装は既存の並列Factとの互換性を保つため`nx.MultiDiGraph`を使用します。

```text
nodes
  └─ id, name, type, cloud, is_entry, is_goal,
     goal_candidate, asset_category, vulnerabilities, raw_evidence
edges
  └─ fact_id, source, target, type, permission, provider,
     source_tool, source_file, original_edge_type, raw_evidence
unmapped_vulnerabilities
metadata
  └─ schema_version, source_files, source_tools, cloud_providers,
     input_hashes, node/edge/vulnerability counts, schema_status
```

主な統合規則は次のとおりです。

- Node IDは`cloud:type:name`を基本として安定生成
- Edge IDがなければprovenanceを含む安定した`fact_id`を生成
- 同一Node IDは属性とEvidenceを失わずmerge
- 同一`fact_id`だけを重複排除
- 異なる観測元の同じ関係は並列Factとして保持
- 同じ入力から決定的なJSONを生成
- Layer 2が直接読み込める既存JSON構造を維持

`raw_evidence`はprovenance確認のため保持します。ただしsecret、password、token、API key、Credential、private key、authorization等の値は再帰的に`[REDACTED]`へ置換します。入力ファイルのSHA-256は`metadata.input_hashes`に保存します。

### Streamlit UI

```bash
pip install -r requirements.txt
streamlit run app.py
```

GUIでは入力をアップロードして`Build Layer 1 Fact Graph`を実行します。Node、Edge、CVE、Unmapped CVE、Entry Point、Goal candidate、Selected Goalの件数、各一覧、Fact Graph、JSON downloadを表示します。

ノード色はGoalが赤、Goal候補が黄、その他が青です。EdgeはLayer 1でリスクを判定しないため、意味を持たせずグレーで表示します。

### サンプルとテスト

サンプルは`examples/layer1/`にあります。

- `grype_sample.json` / `grype_sample.sarif`
- `hound_generic_sample.json`
- `important_assets.yaml`
- `vulnerability_mapping.yaml`
- `architecture.drawio`
- `cross_cloud_edges.yaml`
- `fact_graph_sample.json`

```bash
python -m pytest -p no:cacheprovider -q
python -m py_compile app.py capra/layer1/*.py capra/layer1/parsers/*.py capra/layer1/utils/*.py
```

現在は全体で`85 passed`、構文検査、Streamlitのヘッドレス起動確認に成功しています。

### Layer 1の境界

Layer 1では、Attack Operator生成、NVD APIアクセス、CVE攻撃種別分類、攻撃経路探索、攻撃成立判定、リスク／ベイズ計算、LLM利用、ペイロード生成、攻撃実行を行いません。これらはLayer 2以降の責務です。

## Layer 2: 攻撃操作グラフ生成レイヤー

Layer 2は、Layer 1 Fact GraphのCVEとIAM/RBAC Factを、共通形式のAttack Operatorへ決定的に変換します。Operator間では、成立条件または生成・要求Capabilityが一致する依存関係だけを接続し、Layer 3が検証できる候補を出力します。

```text
Layer 1 Fact Graph
        ↓
CVE rules / source-specific Hound adapters / IAMHoundDog patterns
        ↓
Attack Operators ── effects/preconditions・produces/requiresで接続
        ↓
Attack Operator Graph + unresolved items + Layer 3 candidate IDs
```

### 入力

| 入力 | 用途 |
| --- | --- |
| Layer 1 Fact Graph JSON | Node、Edge、CVE、provenanceの読み込み |
| NVD cache（任意） | CVE description、CVSS、CWE、CPE、reference tagの補完 |
| Hound Edge mapping YAML（任意） | source tool固有のAttack Edge変換規則の追加 |
| IAMHoundDog pattern YAML（任意） | 複数Edge・権限から成立するOperator patternの追加 |
| CVE Operator Rule YAML（任意） | NVD descriptionからoperator typeへの分類規則の追加 |

`source_tool`や`fact_id`などが欠けた旧形式は、推定できる値だけを補完します。推定不能な対象、未知Edge、NVD取得失敗、条件不足、上限到達は破棄せず`unresolved_items`へ保持します。

### Attack Operator変換

- `nvd`: CVEをdescription ruleで分類し、CVE/CWE、CVSS、入力Fact IDをEvidenceとして保持
- `hound_generic`: AssumeRoleとnetwork Factを未検証のpartial Operatorへ変換
- `azurehound` / `gcp_hound` / `clusterhound`: source固有の明示的なAttack Edgeだけを変換
- `iamhounddog`: 同じ`source_tool`内の有向multi-edge patternと必要権限を上限付きで照合

全Operatorは`AttackOperatorModel`へ統合され、安定したID、source/target node、preconditions/effects、produces/requires、status、Evidence、provenanceを持ちます。`complete`はモデル化に必要なFactが揃っている状態であり、攻撃成功や実環境での検証完了を意味しません。

CVE対象が判明していても、到達性と脆弱バージョンの稼働はLayer 2では確認しないため、通常は`partial`かつ`verification_status="unverified"`です。NVD referenceにExploit tagがある場合も候補として記録するだけで、リンク先やExploit codeにはアクセスしません。

### Operator間の接続

Connectionは次の2規則だけで生成します。

1. 先行Operatorの`effects`が後続Operatorの`preconditions`を満たす場合、condition付き`enables`を生成
2. 先行Operatorの`produces`が後続Operatorの`requires`を満たす場合、順方向の`enables`を生成

Artifact接続では`artifact_type`と`subject_node_id`が一致し、生成側のpropertiesが要求側を満たす必要があります。空または`unknown`の対象は接続しません。

`target_node == source_node`というだけでは接続しません。例えばDoSとService Account取得が同じPodを参照しても、DoSがIdentityやresource controlを生成しなければ依存関係は成立しません。Nodeの共有はUI上の資産contextとしてだけ表示します。

### Attack Operator Graph

```text
attack_operators
  └─ id, operator_type, origin_kind, source_tool, source/target node,
     preconditions, effects, produces, requires, status, evidence
connections
  └─ id, source/target operator, enables, artifact/condition, reason
unresolved_items
layer3_candidates
  └─ complete/partialかつunverifiedなOperator ID
metadata
  └─ input hash, rule versions/hashes, cache統計、各種件数、実行設定
```

OperatorとConnectionのIDは入力Fact、Rule、CapabilityまたはConditionから安定生成します。実行日時と処理時間を除けば、同じFact Graph、Rule、NVD cacheから同じJSONを生成します。Evidence、metadata、Artifact properties内のsecret、password、token、API key等は再帰的に`[REDACTED]`へ置換します。

内部Graphは`nx.MultiDiGraph`です。`requires`は後続Operatorの属性として保持し、逆向きConnectionは生成しません。Layer 3には完全なGraphと候補Operator IDの一覧を渡し、Layer 2側では候補の実行可否を決定しません。

### Streamlit UI

GUIではLayer 1の結果を再利用するかFact Graph JSONをアップロードし、NVD mode/cache、探索上限、source tool、operator type、追加Ruleを指定して`Build Layer 2 Attack Operator Graph`を実行します。

Fact、Operator、CVE/IAM、Complete/Partial/Unresolved、Manual verification、Connection、Layer 3 candidateの件数、各一覧、Attack Operator Graph、JSON downloadを表示します。Operatorは種類ごとに色分けし、資産Nodeとのsource/target contextは破線で表示します。この表示用contextはJSONのConnectionには追加しません。

Python APIは次のように利用できます。

```python
from capra.layer2.schemas import Layer2Config
from capra.layer2.service import build_attack_operator_graph

result = build_attack_operator_graph(
    fact_graph_dict,
    Layer2Config(nvd_mode="cache-only"),
)
```

### サンプルとテスト

サンプルは`examples/layer2/`にあります。

- `fact_graph_sample.json`
- `nvd_response_*.json`
- `attack_operator_graph_sample.json`
- `connection_example.json`
- `manual_verification_required.json`
- `invalid_node_match_only.json`
- `layer3_candidates.json`

```bash
python -m pytest -p no:cacheprovider -q
python -m py_compile app.py capra/layer2/*.py capra/layer2/adapters/*.py capra/layer2/nvd/*.py capra/layer2/patterns/*.py
```

テストは実NVD APIへアクセスせず、cache fixtureまたはmock clientを使用します。現在は全体で`85 passed`で、Node一致だけの誤接続、source toolをまたぐpattern照合、秘密情報の出力、無制限な探索が発生しないことも検証しています。

### Layer 2の境界

Layer 2では、実環境への検証通信、攻撃成立判定、Goal指向探索、リスク／ベイズ計算、LLMによるOperator選択、TTPやペイロード生成、Exploit取得、Trusted Executor、攻撃実行を行いません。Layer 2の責務は、入力Factと明示Ruleから未検証のAttack Operator Graphを構築し、Evidenceと未解決条件を保ったままLayer 3へ渡すことです。
