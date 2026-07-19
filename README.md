# CAPRA: Cloud Attack Path Risk Analyzer

CAPRA は、クラウド環境の脆弱性情報、IAM/RBAC の関係、重要資産候補、任意の構成図情報を共通の **Layer 1 Fact Graph** に正規化し、Layer 2 で攻撃操作候補とその依存関係をモデル化するプロトタイプです。現在の Streamlit アプリでは、Layer 1 の Fact Extraction と Layer 2 の Attack Operator Graph 生成を実行できます。

## Layer 1: 事実抽出レイヤー

Layer 1は、脆弱性診断、IAM/RBAC、重要資産、任意の構成図から得られる情報を事実データとして抽出し、共通スキーマを持つ `NetworkX` 有向グラフへ統合します。攻撃が成立するかの判定は行わず、Layer 2以降が利用できるFact Graphを生成することが役割です。

Layer 1全体の実装は `capra/layer1/` にあり、Streamlitからの呼び出しと入力ファイルの振り分けはリポジトリ直下の `app.py` が担当します。中心となる処理の起点は `capra/layer1/graph_builder.py` の `build_layer1_fact_graph()` です。

```text
入力ファイル
  ├─ Grype JSON/SARIF ────────────── parse_grype_json() / parse_grype_sarif()
  ├─ Hound generic JSON ──────────── parse_hound_generic()
  ├─ 重要資産 YAML/JSON ──────────── load_json_or_yaml()
  ├─ 任意CVE-to-node mapping ─────── load_json_or_yaml()
  └─ 任意Draw.io XML/.drawio ────── parse_drawio_to_layer1()
                         ↓
                 build_layer1_fact_graph()
                  ├─ apply_asset_markers()
                  ├─ attach_vulnerabilities_to_nodes()
                  └─ build_fact_graph()
                         ↓
              NetworkX Layer 1 Fact Graph
                         ↓
                  export_fact_graph_json()
```

### 入力

#### 1. 脆弱性診断レポート（Grype JSON / SARIF）

Grypeでコンテナイメージやファイルシステムを検査した結果を、JSONまたはSARIF形式で入力します。入力UIとJSON/SARIFの判定は `app.py` にあり、パース処理は `capra/layer1/parsers/grype_parser.py` が担当します。

- `parse_grype_json()`: `matches[*].vulnerability` と `matches[*].artifact` からスキャナID、CVE ID、パッケージ名、導入バージョン、修正版、severityを取り出し、`VulnerabilityModel` へ変換します。
- `parse_grype_sarif()`: `runs[*].results` と `tool.driver.rules` を対応付け、`ruleId`、message、rule propertiesからCVE、パッケージ、severityを抽出します。
- `_extract_cve_id()`: 文字列、辞書、配列を再帰的に走査し、`CVE-\d{4}-\d{4,}` に一致するIDを抽出します。Grypeの主IDがGHSAなどの場合も、`aliases`、`relatedVulnerabilities`、rule/result内にあるCVEを検出します。

元のスキャナIDは `VulnerabilityModel.id` に保持し、検出できたCVEは `cve_id` に分けて格納します。GrypeはLayer 1で脆弱性の存在を抽出するための入力であり、NVDへの問い合わせや脆弱性種別から攻撃操作への変換はLayer 2が担当します。

#### 2. Hound系ツールで得られるIAM攻撃パス

Hound系ツールが出力したクラウド資産、IAM/RBAC主体、権限、所属、構成関係、攻撃エッジをJSONで入力します。現在のLayer 1ではHound製品ごとの生形式を直接処理するのではなく、`nodes` / `edges` を持つgeneric JSONを `capra/layer1/parsers/hound_parser.py` で読み込みます。`data.nodes` / `data.edges`、`graph.nodes` / `graph.edges` の入れ子にも対応します。

- `parse_hound_generic()`: 入力からノードとエッジを抽出し、`NodeModel` と `EdgeModel` のlistを返します。エッジの端点だけに存在するIDは、推定ノードとして補完します。
- `_extract_graph_container()`: `nodes` / `edges` が格納された階層を判定します。
- `_parse_node()`: `name`、`label`、`displayName`、`type`、`kind`、`labels` などの表記差を吸収し、ノードIDやcloudがない場合は補完します。
- `_parse_edge()`: `source` / `from` / `start`、`target` / `to` / `end` などの表記差を吸収し、権限名、provider、`source_tool`、元のEdge種別、raw evidenceを `EdgeModel` に保持します。
- `normalize_edge_type()`: `AssumeRole`、`sts:AssumeRole`、`iam:PassRole` などを `assume_role`、`pass_role_or_act_as` などの共通Edge種別へ正規化します。
- `infer_provider()`: ARN、Service Account、Azure subscription、Kubernetes関連文字列などから `aws` / `gcp` / `azure` / `k8s` を推定します。

`capra/layer1/adapters/` にはAWS、GCP、Azure、Kubernetes用のファイルがありますが、現時点では将来のsource固有変換用プレースホルダーです。現在のHound共通スキーマ変換は `parsers/hound_parser.py` が実装しています。Hound固有の攻撃Edgeの意味付けとAttack Operatorへの変換はLayer 2の各Adapterが担当します。

#### 3. 重要資産ノード

Admin Role、Secret Manager、DB、Kubernetes Cluster Admin、Production Storageなど、分析上保護対象としたい資産をYAMLまたはJSONで入力します。ファイルの読み込みは `capra/layer1/utils/file_loader.py` の `load_json_or_yaml()`、ノードへの反映は `capra/layer1/asset_marker.py` が担当します。

入力では主に次の2つのlistを扱います。

- `assets`: 重要資産候補として `goal_candidate=True` を付けます。
- `entry_points`: 外部ユーザーや公開サービスなどの侵入起点として `is_entry=True` を付けます。

主要な関数は以下です。

- `apply_asset_markers()`: 重要資産候補とEntry Pointを既存ノードへ重ね合わせます。Streamlitで今回のGoalとして選択されたIDだけに `is_goal=True` を設定します。
- `_asset_to_node()`: YAML/JSONの資産定義を `NodeModel` に変換します。IDがない場合はcloud、type、nameから生成します。
- `_find_match()`: ID一致を優先し、続いてname、type、cloudが一致する既存ノードを探します。
- `_merge_node()`: 既存ノードの情報を残しながら、`is_entry`、`is_goal`、`goal_candidate`、`asset_category`、raw evidenceを統合します。

重要資産候補と今回の分析Goalは分離されています。`goal_candidate=True` は重要資産として登録された状態、`is_goal=True` はその中から今回の到達目標として選択された状態を表します。

#### 4. 任意入力：Draw.io構成図

クラウド構成図やネットワーク接続を補助的に取り込む場合、Draw.io XMLまたは `.drawio` を入力します。処理は `capra/layer1/parsers/drawio_parser.py` が担当します。

- `parse_drawio_to_layer1()`: Draw.io内のノードと接続線を `NodeModel` / `EdgeModel` に変換します。
- `_parse_drawio_xml()`: `mxCell vertex="1"` をノード、`mxCell edge="1"` をエッジとして抽出します。
- `_clean_drawio_label()`: HTML entityを戻し、HTMLタグや `<br>` を除去してラベルを正規化します。
- `_infer_node_traits()`: ラベル中の `db`、`secret`、`admin`、`internet`、`api` などから、ノード種別、重要資産候補、Entry Pointを補助的に推定します。

Draw.ioの接続線は `type="network_access"`、`permission="drawio:connected"`、`source_tool="drawio"` のEdgeとして取り込みます。構成図のラベルだけを使う推定であるため、正確なIAM権限や資産属性についてはHound入力と重要資産定義を優先します。

#### 5. 補助入力：CVE-to-node mapping

Grypeの脆弱性を特定ノードへ明示的に対応付けたい場合、任意のYAML/JSON mappingを入力できます。ファイルは `load_json_or_yaml()` で読み込まれ、`vulnerability_mappings` の各Ruleを `capra/layer1/vuln_mapper.py` が使用します。`cve_id` や `package_name` を条件に、`node_id` または `node_name` を指定できます。

### 処理

#### 1. ノード・エッジ抽出

各parserは入力ツール固有の構造を、`capra/layer1/schemas.py` にある次のPydantic modelへ変換します。

- `NodeModel`: 資産やIAM主体を表し、ID、name、type、cloud、Entry/Goal属性、脆弱性、raw evidenceを保持します。
- `EdgeModel`: source/target、関係種別、permission、provider、`source_tool`、`source_file`、元のEdge種別、raw evidenceを保持します。
- `VulnerabilityModel`: スキャナID、CVE ID、パッケージ、導入・修正バージョン、severity、入力元、raw evidenceを保持します。
- `FactGraphModel`: ノード、エッジ、未対応付け脆弱性、metadataをまとめるJSON向けスキーマです。

`NodeModel` と `EdgeModel` はcloud/providerを `aws` / `gcp` / `azure` / `k8s` / `hybrid` / `unknown` に正規化します。ノードのtypeとasset category、Edge typeは小文字へ正規化します。

ID生成は `capra/layer1/utils/ids.py` が担当します。

- `slugify()`: 文字列を小文字化し、IDで使用できる文字へ正規化します。
- `generate_node_id()`: `cloud:type:name` 形式の安定したノードIDを生成します。
- `generate_vulnerability_id()`: 入力にIDがない脆弱性へparser名、位置、hintを使ったIDを付けます。

#### 2. Hound出力を共通スキーマに変換

Hound入力は `parse_hound_generic()` によって `NodeModel` / `EdgeModel` へ変換されます。ノードやEdgeのフィールド名、Edge type、providerの表記差を正規化し、入力に含まれる生データを `raw_evidence` として残します。

この段階では、`assume_role`、`read_secret`、`modify_policy`、`create_access_key`、`pass_role_or_act_as`、`network_access`、`attached_policy`、`member_of`、`has_permission` などの事実関係へ統一するだけです。攻撃操作への変換や攻撃成立判定は行いません。

#### 3. CVE情報を各ノードに紐づけ

`capra/layer1/vuln_mapper.py` の `attach_vulnerabilities_to_nodes()` が、Grypeから得た `VulnerabilityModel` を次の優先順でノードへ対応付けます。

1. `_match_by_mapping()` が任意の `vulnerability_mapping.yaml` / JSONにある明示Ruleを確認します。
2. `_match_by_target_hint()` がGrypeの `raw_evidence` にある `target`、`image`、`container`、`location` などとノード名・IDを比較します。
3. `_match_by_partial_name()` がpackage名、artifact名、purlとノード名・IDの部分一致を確認します。
4. 一致しない脆弱性は破棄せず `unmapped_vulnerabilities` に保持します。

対応付けられた脆弱性は対象ノードの `vulnerabilities` 配列へ追加されます。この処理は入力情報に基づく暫定的な名寄せであり、確実な対応付けが必要な場合は明示mappingを使用します。

severityは `capra/layer1/severity.py` の `normalize_severity()` で次の文字列ラベルへ正規化します。これは脆弱性自体のラベルであり、ノード全体のリスクスコアではありません。

```text
critical        -> Critical
high            -> High
medium/moderate -> Medium
low/note        -> Low
info            -> Negligible
unknown/error   -> Unknown
```

`informational` は `Negligible`、`warning` は `Medium` として扱います。

#### 4. 重要資産ノードを定義

`build_layer1_fact_graph()` は最初に `apply_asset_markers()` を呼び出し、HoundやDraw.ioから抽出したノードへ重要資産・Entry Point情報を反映します。重要資産ファイルにしか存在しない資産も、新しい `NodeModel` としてFact Graphへ追加されます。

同じノードが複数入力に存在する場合は、`capra/layer1/graph_builder.py` の `_merge_node_dict()` が次の規則で統合します。

```text
is_entry        = existing.is_entry OR incoming.is_entry
is_goal         = existing.is_goal OR incoming.is_goal
goal_candidate  = existing.goal_candidate OR incoming.goal_candidate
vulnerabilities = existing.vulnerabilities + incoming.vulnerabilities
raw_evidence    = existing.raw_evidence と incoming.raw_evidence を統合
```

`asset_category` は、追加情報が `unknown` でない場合に更新します。

#### 5. 構成要素のグラフ化

Layer 1のオーケストレーションは `capra/layer1/graph_builder.py` が担当します。

- `build_layer1_fact_graph()`: 重要資産マーク、脆弱性対応付け、グラフ構築を順番に実行し、未対応付け脆弱性、入力ファイル名、schema statusをグラフmetadataへ保存します。
- `build_fact_graph()`: `NodeModel` をNetworkX node、`EdgeModel` を有向edgeとして `nx.DiGraph` に追加します。同じノードIDはマージし、同じsource、target、type、permissionのEdgeは重複排除します。Edgeの端点ノードが不足している場合は推定ノードを追加します。
- `_merge_node_dict()`: Hound、重要資産、Draw.ioなど複数入力から得た同一ノードの属性を統合します。

`app.py` は `build_layer1_fact_graph()` が返したグラフをPyVisの `Network` へ渡し、ブラウザ上に有向グラフとして表示します。ノードには資産名、Edgeには正規化したEdge typeを表示します。

### 出力：事実データを紐づけたグラフ

最終出力は、資産・IAM主体をノード、権限・構成・ネットワーク関係をEdgeとし、対応する脆弱性と重要資産属性をノードへ紐づけたLayer 1 Fact Graphです。

出力処理は `capra/layer1/exporters.py` が担当します。

- `export_fact_graph_json()`: NetworkXグラフを `nodes`、`edges`、`unmapped_vulnerabilities`、`metadata` を持つJSON互換辞書へ変換します。
- `export_nodes_dataframe()`: ノード属性とノードごとの脆弱性件数を表形式へ変換します。
- `export_edges_dataframe()`: Edgeの関係種別、permission、provider、provenanceを表形式へ変換します。
- `export_vulnerabilities_dataframe()`: ノードへ紐づいた脆弱性と未対応付け脆弱性を1つの表へ変換します。
- `save_fact_graph_json()`: Fact GraphをUTF-8のJSONファイルとして保存します。

Fact Graph JSONの基本構造は次のとおりです。

```text
nodes
  └─ id, name, type, cloud, is_entry, is_goal, goal_candidate,
     asset_category, vulnerabilities, raw_evidence
edges
  └─ source, target, type, permission, provider, source_tool,
     source_file, original_edge_type, raw_evidence
unmapped_vulnerabilities
metadata
  └─ schema_version, source_files, node_count, edge_count,
     vulnerability_count, mapped_vulnerability_count,
     unmapped_vulnerability_count, schema_status
```

脆弱性件数は次のように集計します。

```text
vulnerability_count          = mapped_vulnerability_count + unmapped_vulnerability_count
mapped_vulnerability_count   = ノードへ付与できた脆弱性数
unmapped_vulnerability_count = ノードへ付与できず保持した脆弱性数
```

このJSONがLayer 2の入力となり、脆弱性由来・IAM由来のAttack Operator生成に利用されます。

## 実行方法

### インストール

```bash
pip install -r requirements.txt
```

### Streamlit アプリの起動

```bash
streamlit run app.py
```

画面で Grype JSON/SARIF、Hound generic JSON、重要資産 YAML/JSON、任意の CVE-to-node mapping YAML/JSON、任意の Draw.io XML をアップロードし、`Build Layer 1 Fact Graph` を押すと、ノード表、エッジ表、脆弱性表、簡易グラフ、Fact Graph JSON のダウンロードが表示されます。上部メトリクスの `CVEs` はマップ済みと未マップの合計、`Unmapped CVEs` はノードへ対応付けできなかった件数です。

### ゴールノードのカラー指定
Streamlit 上の `Layer 1 Fact Graph` では、ノードの色をリスクスコアではなく、重要資産の状態に基づいて暫定的に変更しています。

```text
is_goal=True          -> 赤: 今回の分析で Goal として選択された重要資産
goal_candidate=True   -> 黄: Goal 候補だが、今回の Goal には未選択の資産
その他のノード        -> 青: 通常ノード
```

判定順は `is_goal` が最優先で、次に `goal_candidate`、どちらでもない場合は通常ノードとして表示します。現時点では、脆弱性件数、severity、攻撃経路上にあるかどうかでは色を変えていません。後続レイヤーでリスクスコアや攻撃経路が実装された場合、この色分けは変更する想定です。

エッジの色は、現時点では `type`、`permission`、severity などでは判定していません。意味のある色分けに見えないよう、すべてのエッジを薄いグレー `#C7CED8` で固定表示しています。エッジ上のラベルには `network_access`、`assume_role`、`read_secret` などのエッジ種別だけを表示しています。

## サンプル入力

サンプルは `examples/layer1/` にあります。

- `grype_sample.json`
- `grype_sample.sarif`
- `hound_generic_sample.json`
- `important_assets.yaml`
- `vulnerability_mapping.yaml`
- `fact_graph_sample.json`

## テスト

```bash
pytest
```

現在のテストでは、Grype parser、Hound parser、Fact Graph builder、Layer 1 schema の基本動作を確認しています。Grype parser では、`vulnerability.id` が GHSA 形式で `aliases` に CVE が含まれるケースも確認しています。

## 現在の制約

- Layer 1 は Fact Graph 生成までを担当し、攻撃経路探索や総合リスクスコアリングはまだ行いません。
- Hound generic JSON の形式は暫定です。AWS / GCP / Azure / Kubernetes 固有の adapter は `capra/layer1/adapters/` に追加できる構成です。
- Draw.io からの種別推定はキーワードベースの補助機能です。正確な資産分類には Hound 系入力や重要資産 YAML を優先してください。

## Layer 2: 攻撃ベクターのモデル化による攻撃操作グラフ生成レイヤー

Layer 2 は Layer 1 Fact Graph の脆弱性と IAM/RBAC の事実を、攻撃者が実行できる可能性のある共通形式の `AttackOperatorModel` へ変換し、Operator 間の依存関係を `Attack Operator Graph` として構造化します。ここでの `complete` はモデル化に必要な情報が揃ったという意味であり、攻撃成功を意味しません。

実装済みの処理フローは次のとおりです。

1. NVD 情報から脆弱性種別を抽出し、脆弱性由来の攻撃操作へ変換します。
2. Hound 系の IAM 権限・構成関係・攻撃エッジを、IAM 由来の攻撃操作へ変換します。
3. 脆弱性由来と IAM 由来の攻撃操作を、共通形式の `AttackOperatorModel` へ統合します。
4. 攻撃操作同士を `enables` / `requires` で接続し、`Attack Operator Graph` を生成します。

Layer の境界は次のとおりです。

- Layer 1: 入力ツールの事実を `nodes` / `edges` / `vulnerabilities` へ正規化します。
- Layer 2: ルールと Adapter で攻撃操作候補を生成し、`enables` / `requires` で接続します。
- Layer 3: 実環境で成立条件を検証する将来レイヤーです。Layer 2 は検証コマンド、攻撃手順、ペイロードを生成・実行しません。

### Layer 2の実装構成と処理順序

Layer 2 全体の起点は `capra/layer2/service.py` の `build_attack_operator_graph()` です。この関数が Fact Graph の読み込み、NVD・Hound Adapter の実行、共通形式への統合、Operator 間の接続、Layer 3候補の抽出、metadata の集計を順番に制御します。

```text
build_attack_operator_graph()
  ├─ load_fact_graph()
  ├─ Hound Adapter.convert()
  ├─ convert_cves()
  ├─ _deduplicate_operators()
  ├─ build_operator_connections()
  └─ extract_layer3_candidates()
       ↓
AttackOperatorGraphModel
```

#### 1. NVD情報から脆弱性種別を抽出し、脆弱性由来の攻撃操作へ変換

中心となるファイルは次のとおりです。

- `capra/layer2/nvd_adapter.py`: CVEごとのNVD情報取得、脆弱性種別の分類、`AttackOperatorModel` への変換を担当します。
- `capra/layer2/nvd/parser.py`: NVD CVE APIレスポンスからDescription、CVSS、CWE、CPEの製品・バージョン、Referenceを抽出します。
- `capra/layer2/nvd/cache.py`: `cache/nvd/{CVE-ID}.json` の読み書き、TTL判定、破損検出、atomic writeを担当します。
- `capra/layer2/nvd/client.py`: NVD CVE APIだけにアクセスし、timeout、retry、rate limit、任意の `NVD_API_KEY` を扱います。
- `capra/layer2/nvd/models.py`: 正規化後のNVD情報を表す `NvdRecordModel` と `NvdReferenceModel` を定義します。
- `capra/layer2/rules/cve_operator_rules.yaml`: NVDの英語Descriptionに含まれる語句と `operator_type` の対応を定義します。

主要な関数は以下です。

- `convert_cves()`: ノード配下の `vulnerabilities` と `unmapped_vulnerabilities` を列挙し、CVE IDを正規化してcacheを確認します。設定が `cache-then-fetch` の場合だけcache miss、stale、corrupt時にNVD APIへ問い合わせます。NVDレコードを取得できないCVEや不正なCVE IDは、処理から捨てず `unresolved_items` に残します。
- `parse_nvd_response()`: NVDレスポンスを検証し、英語Description、CVSS v3.1/v3.0/v2、CWE、CPE、Reference tagを `NvdRecordModel` へ変換します。Reference tagに `Exploit` があるかもここで判定しますが、Reference URL自体にはアクセスしません。
- `load_cve_rules()`: `cve_operator_rules.yaml` を読み込み、同時にRule versionと内容hashを取得します。語句は長いものから評価するように並べ、より具体的な語句を優先します。
- `classify_description()`: NVD Descriptionを小文字化し、Ruleの `phrase` が含まれるかを決定的に照合します。例えば `command injection` は `command_injection`、`privilege escalation` は `privilege_escalation` へ変換します。該当Ruleがない場合は `exploit_vulnerable_component` を使用します。
- `NvdCache.read()` / `NvdCache.write()`: cacheの有効性確認と保存を行います。書き込みは一時ファイルを同一directoryに作成してから置換するため、途中で不完全なJSONが残りにくい構成です。
- `NvdClient.fetch()`: `cveId` を指定してNVD CVE APIを呼び出します。API keyはリクエストheaderにだけ設定され、Operator、metadata、evidence、cacheには明示的に追加されません。

`convert_cves()` が作るOperatorは `origin_kind="cve"`、`source_tool="nvd"` です。対象ノードがある場合でも、実環境の到達性や稼働バージョンはLayer 2では確認しないため、通常は `status="partial"`、`verification_status="unverified"` になります。`requires` には対象ノードへの `network_reachability` を設定し、CVE/CWE、CVSS、Rule ID、入力Fact IDを根拠として保持します。ノードへ未対応付けのCVEは対象を決められないため `status="unresolved"` になります。

#### 2. Hound系のIAM権限・構成関係・攻撃エッジを、IAM由来の攻撃操作へ変換

Hound系入力は、単一Edge自体が攻撃操作を表す形式と、複数Edge・権限の組み合わせで攻撃操作が成立するIAMHoundDog形式を分けて処理します。

直接Edge変換の中心ファイルは次のとおりです。

- `capra/layer2/adapters/direct_base.py`: AzureHound、GCPHound、ClusterHoundに共通するRule読込、Edge分類、Operator生成を `DirectEdgeAdapter` として実装します。
- `capra/layer2/adapters/azurehound_adapter.py`: `source_tool="azurehound"` と `rules/azurehound_edges.yaml` を共通Adapterへ設定します。
- `capra/layer2/adapters/gcp_hound_adapter.py`: `source_tool="gcp_hound"` と `rules/gcp_hound_edges.yaml` を設定します。
- `capra/layer2/adapters/clusterhound_adapter.py`: `source_tool="clusterhound"` と `rules/clusterhound_edges.yaml` を設定します。
- `capra/layer2/rules/azurehound_edges.yaml`: `AZAddSecret` などのAzureHound Edge mappingを定義します。
- `capra/layer2/rules/gcp_hound_edges.yaml`: `CanCreateKeys`、`CanImpersonate` などのGCPHound Edge mappingを定義します。
- `capra/layer2/rules/clusterhound_edges.yaml`: RBAC、Service Account、workload、Secret、host/node、exposureに関するClusterHound Edge mappingを定義します。

`DirectEdgeAdapter.convert()` は `source_tool` が一致するEdgeを安定した順序で処理し、YAML mappingの `classification` を確認します。`ATTACK_EDGE` だけを `origin_kind="iam_direct_edge"` のOperatorへ変換し、`RELATIONSHIP` と `PERMISSION` は分類統計には記録しますがOperator生成の対象にはしません。未定義Edgeは推測で変換せず `unresolved_items` に保存します。Ruleに `missing_conditions` があるEdgeは `partial`、ないEdgeは `complete` としてモデル化します。Hound AdapterはLayer 1由来のEdgeを `raw_evidence` としてそのまま引き継ぎ、Hound固有の秘密値検出や置換は行いません。

IAMHoundDogの中心ファイルは次のとおりです。

- `capra/layer2/adapters/iamhounddog_adapter.py`: pattern ruleを実行し、match結果を `origin_kind="iam_pattern"` のOperatorへ変換します。
- `capra/layer2/patterns/loader.py`: IAMHoundDog Rule YAMLを読み込み、Pydantic modelで検証し、Rule versionとhashを返します。
- `capra/layer2/patterns/models.py`: patternの各step、Operator定義、Rule全体のスキーマを定義します。
- `capra/layer2/patterns/matcher.py`: ノード種別、Edge方向・順序、binding、required permissionを使う有向multi-edge pattern照合を実装します。
- `capra/layer2/rules/iamhounddog_patterns.yaml`: 既定のIAMHoundDog pattern ruleを定義します。任意Rule YAMLを指定した場合はこの既定ファイルの代わりに読み込みます。

`match_rule()` は同じ `source_tool` のEdgeから隣接リストを作り、Ruleの `from_type`、`edge_type`、`to_type` を先頭から順番にたどります。`bind_from_as` / `bind_to_as` で主体や対象Roleを名前付きで保持し、`_find_permissions()` がpath上の主体とbindingされたノードについて `required_permissions` を確認します。`iam:PassRole` はbindingされた `target_role` に向く権限Edgeだけを有効とします。`max_hops` と `max_matches_per_rule` により探索量を制限します。

`IamHoundDogAdapter.convert()` はpatternが成立したmatchをOperatorへ変換します。必要権限がすべて存在すれば `complete`、不足していれば不足権限を `missing_conditions` に入れた `partial` とします。pattern不成立、hop上限、未知Edgeは `unresolved_items` またはwarningとして保持します。

Hound Edgeの共通分類は `capra/layer2/edge_classifier.py` の `normalize_edge_key()` と `classify_edge()` が担当します。表記を小文字の比較用keyへ正規化したうえで、Edgeを `RELATIONSHIP`、`PERMISSION`、`ATTACK_EDGE`、`UNKNOWN` のいずれかへ分類します。

#### 3. 脆弱性由来とIAM由来の攻撃操作を共通形式へ統合

共通形式は `capra/layer2/schemas.py` に定義しています。

- `AttackOperatorModel`: CVE、IAM direct edge、IAM patternの全Operatorが使用する共通モデルです。
- `OperatorArtifactModel`: Operatorが生成または要求する `credential`、`identity`、`permission`、`resource_control`、`network_reachability`、`data_access` を表します。
- `AdapterResult`: 各AdapterがOperator、unresolved item、warning、統計を呼び出し元へ返す形式です。
- `AttackOperatorGraphModel`: 最終的なOperator、Connection、unresolved item、Layer 3候補、metadataをまとめます。
- `Layer2Config`: NVD mode/cache、探索上限、出力上限、対象tool/type、任意IAMHoundDog Rule pathを定義します。

入力の正規化は `capra/layer2/fact_graph_loader.py` の `load_fact_graph()` が担当します。Layer 1 Fact Graphを `FactGraphInput` へ変換し、`source_tool` のalias、Edgeの `fact_id`、`original_edge_type`、`source_file` などを補完します。入力不備や判定不能な `source_tool` は `unresolved_items` に残し、入力全体のhashも計算します。入力境界ではsource toolに依存しない共通の安全対策を適用しますが、Hound Adapter内にHound固有のredaction処理はありません。

統合処理は `capra/layer2/service.py` の `build_attack_operator_graph()` が担当します。この関数は各Hound Adapterの `convert()` とNVDの `convert_cves()` が返した `AttackOperatorModel` を1つのlistへ集約します。その後、`_deduplicate_operators()` がOperator IDをkeyとして重複を除き、ID順に並べます。`selected_source_tools`、`selected_operator_types`、`max_total_operators` もここで適用し、上限超過分はwarningと `unresolved_items` に記録します。

Operator IDは `capra/layer2/ids.py` の `generate_operator_id()` が生成します。`operator_type`、`origin_kind`、source/target node、ソート済みsource fact IDs、mapping rule IDをcanonical JSONにし、SHA-256から安定したIDを作ります。このため、NVD由来とIAM由来で生成経路が異なっても、共通のID規則と共通スキーマで比較・接続できます。

#### 4. 攻撃操作同士を接続し、攻撃操作グラフを生成

Operator間の接続は `capra/layer2/operator_graph_builder.py` が担当します。

- `build_operator_connections()`: OperatorをID順に比較し、`enables` / `requires` Connectionを生成します。
- `_artifact_matches()`: `produces` と `requires` のartifact type、対象ノード、要求propertiesが一致するかを判定します。
- `build_networkx_operator_graph()`: Operatorをnode、Connectionをedgeとする `NetworkX MultiDiGraph` を生成します。
- `extract_layer3_candidates()`: `complete` または `partial`、`verification_status="unverified"`、かつ検証対象ノードを持つOperatorをLayer 3候補として抽出します。

接続規則は2種類あります。

1. 先行Operatorの `target_node` と後続Operatorの `source_node` が一致した場合、先行Operatorから後続Operatorへ `enables` を作ります。
2. 先行Operatorの `produces` artifactが後続Operatorの `requires` artifactを満たす場合、先行から後続へ `enables`、後続から先行へ `requires` を作ります。


`enables` / `requires` は、同じ依存関係を読む向きによって表したConnectionです。`enables` は「このOperatorの結果によって、次のOperatorを実行できる可能性が生まれる」という順方向の関係です。`requires` はその逆向きで、「このOperatorを考えるには、前段のOperatorが作るartifactが必要になる」という依存元への関係です。

例えば、あるOperatorが`identity(gcp:serviceaccount:reporter)` を `produces` し、別のOperatorが同じ `identity(gcp:serviceaccount:reporter)` を `requires` している場合、前者から後者へ `enables`、後者から前者へ `requires` を作ります。これは「前者の実行が後者を可能にする」と同時に、「後者は前者の成果物に依存している」ことを、グラフ上で両方向からたどれるようにするためです。Layer 2ではこのConnectionは依存関係のモデル化であり、実環境で攻撃が成功することや、検証済みであることを意味しません。

artifact接続では、`artifact_type` と `subject_node_id` が一致し、要求側 `properties` のすべてを生成側が満たす必要があります。`unknown` や空の対象ノードは接続に使用しません。Connection IDは `capra/layer2/ids.py` の `generate_connection_id()` が接続元、接続先、種別、artifactから決定的に生成し、`max_connections` に達した場合は安全に打ち切ってwarningを残します。
`build_attack_operator_graph()` は生成したConnectionとLayer 3候補をOperator群とともにまとめ、最終的な `AttackOperatorGraphModel` を返します。JSON出力は `capra/layer2/exporter.py`、Streamlit用のPyVis可視化は `capra/layer2/visualization.py` が担当します。可視化では共通形式のOperatorをnode、`enables` / `requires` を有向edgeとして表示します。

`capra/layer2/visualization.py` の `_build_operator_label()` は、Operator nodeのラベルを `operator_type`、`source_node`、`target_node` の3行で構成します。これにより、グラフ上で操作の種類だけでなく、元のFact Graph上の操作主体と対象資産も確認できます。CVE由来Operatorのように `source_node` が存在しない場合は `source: -` と表示し、`target_node` は対象資産IDを表示します。

```text
create_service_account_key
source: gcp:user:analyst
target: gcp:serviceaccount:reporter

buffer_overflow
source: -
target: gcp:serviceaccount:reporter
```

さらに、可視化ではOperatorが参照する `source_node` / `target_node` ごとにLayer 1 Fact Graph由来の資産ノードを楕円で追加します。同じノードIDが複数Operatorから参照される場合は1つの表示ノードを再利用し、次の向きで破線のcontext edgeを表示します。

```text
source Fact node ── source ──▶ Attack Operator ── target ──▶ target Fact node
```

例えば `gcp:serviceaccount:reporter` がIAM由来OperatorとCVE由来Operatorの両方の `target_node` である場合、両Operatorは同じ `gcp:serviceaccount:reporter` 資産ノードへ接続されます。これにより因果関係を示すOperator間Connectionがない場合でも、それぞれが同じ資産を対象としていることをUI上で確認できます。

この資産ノードと `source` / `target` edgeは人がグラフを読みやすくするための表示専用要素です。`attack_operator_graph.json` の `attack_operators` や `connections` には追加せず、`enables` / `requires` の意味や決定的な分析結果は変更しません。

ノードの詳細はホバーでは表示しません。Operator nodeまたはFact nodeをクリックすると、グラフ右上の詳細パネルが開きます。Operatorの場合は `source_tool`、source/target node、preconditions/effects、artifact、CVE/CWE、status、evidence、metadataなどのJSONを表示し、Fact nodeの場合は元のノードIDを表示します。詳細パネルは最大640px幅で、狭い画面では左右の余白を残して画面幅に合わせます。「閉じる」ボタンを押すまで表示されるため、マウス移動だけでポップアップが開いてグラフを隠すことはありません。この処理は `capra/layer2/visualization.py` の `_inject_click_detail_panel()` がPyVis生成HTMLへ追加しています。

グラフのphysicsは初期配置を安定させる間だけ有効です。`stabilizationIterationsDone` イベント後にphysicsを自動停止するため、表示後にノードが回転・漂流し続けることはありません。停止後もノードを手動でドラッグして配置を調整できます。

### 入出力

入力は Layer 1 が出力する Fact Graph JSON です。`nodes`、`edges`、ノード配下の `vulnerabilities`、`unmapped_vulnerabilities`、`metadata` を読み込みます。古い JSON で `fact_id`、`source_tool`、`source_file`、`original_edge_type` が欠けていても、推定可能な値だけ補完し、残りは `unknown` または `unresolved_items` に保持します。`raw_evidence` の provenance は維持しますが、Secret、Token、Password、Access Key などは再帰的に `[REDACTED]` へ置換します。

出力 `attack_operator_graph.json` の主なフィールドは次のとおりです。

```text
schema_version
attack_operators       # CVE / IAM direct edge / IAM pattern の共通形式
connections            # enables / requires
unresolved_items       # 未知Edge、NVD失敗、条件不足、上限到達など
layer3_candidates      # Layer 3へ渡せる未検証Operator ID
metadata               # 入力hash、Rule、件数、cache統計、実行設定
```

Operator は preconditions/effects、produces/requires artifact、source fact IDs/files、mapping rule、CVE/CWE、`verification_status=unverified` を保持します。出力配列と ID は決定的です。Operator ID は operator type、origin、source/target node、ソート済み fact ID、rule ID の canonical JSON SHA-256 から生成します。Connection と unresolved ID も内容ベースの SHA-256 です。実行日時と処理時間を除けば、同じ Fact Graph、Rule、NVD cache から同じ結果を得られます。

### source_tool ごとの変換

- `azurehound`: `AZAddSecret`、`AZAddMembers`、`AZMGGrantRole` を direct Operator に変換し、`AZContains` は関係として保持します。
- `gcp_hound`: `CanCreateKeys`、`CanImpersonate`、Secret read、Blob/JWT sign、Bucket policy modify を direct Operator に変換します。所有・包含 edge は関係です。`CanListKeys` は鍵のメタデータ列挙だけでは credential を取得しないため、暫定的に `PERMISSION` として扱い Operator を生成しません。
- `clusterhound`: RBAC 昇格、Service Account、workload control、Secret、host/node、exposure edge を source 固有の Operator に変換します。`entryPoint` 単独では Operator を生成しません。`unauthAPIAccess`、`unauthKubeletAccess`、`accessIMDS` は到達性や認証状態が未確認なので manual verification 必須の partial Operator です。
- `iamhounddog`: 単一 Edge ではなく、`rules/iamhounddog_patterns.yaml` の有向 multi-edge pattern と必要権限を、最大 hop/match 上限内で照合します。
- `nvd`: ノードへ紐づいた CVE を NVD Description rule で分類します。CVSS は補助 metadata、CWE は分類補助、Reference tags は公開 Exploit 候補 metadata として保持します。

Rule と Edge mapping は研究 PoC 用の暫定定義です。未対応または意味を確定できない Edge は推測で変換せず、`unresolved_items` へ保存します。新しい IAMHoundDog rule は `capra/layer2/rules/iamhounddog_patterns.yaml` の `rules` に、ノード種別、Edge 方向/順序、binding、required permissions、Operator artifacts を追加します。Rule ごとに一意な `id` と `version` を設定し、対応テストも追加してください。

### NVD cache と公開 Exploit 候補

NVD cache は既定で `cache/nvd/{CVE-ID}.json` に保存し、TTL、directory、次の mode を設定できます。

- `cache-only`: 有効な cache だけを利用し、miss は unresolved にします。`NVD_API_KEY` なしで完全に動作します。
- `cache-then-fetch`: cache miss/stale/corrupt 時に NVD CVE API だけへ timeout/retry/rate limit 付きで問い合わせ、atomic write します。

API key は必要な場合だけ環境変数に設定します。

```bash
export NVD_API_KEY="..."
```

この値は JSON、metadata、evidence、UI、ログ、cache に保存されません。NVD Reference tag に `Exploit` がある場合は `public_exploit_candidate=true` と `manual_verification_required=true` にしますが、URL先へアクセスせず、`verified` にもしません。CAPRA Layer 2 は Exploit code を取得、保存、解析、実行しません。

### Streamlit と Python API

```bash
streamlit run app.py
```

Layer 1を実行したセッションでは結果をそのまま再利用できます。Layer 2だけを使う場合は Fact Graph JSON をアップロードし、NVD mode/cache、探索上限、source tool、operator type を選んで `Build Layer 2 Attack Operator Graph` を押します。件数、Adapter別結果、unresolved、manual verification、Layer 3候補、PyVis graphを確認し、`attack_operator_graph.json` をダウンロードできます。

UIから独立した API は次のとおりです。

```python
from capra.layer2.schemas import Layer2Config
from capra.layer2.service import build_attack_operator_graph

result = build_attack_operator_graph(fact_graph_dict, Layer2Config(nvd_mode="cache-only"))
```

`capra.layer2.exporter` は JSON save/export と Operator/Connection/Unresolved/Layer 3 candidate の DataFrame export を提供します。

### Layer 2サンプルとテスト

入力、NVD response fixture、各 Hound edge、完全/部分 IAM pattern、manual verification、unresolved、Connection、Layer 3 candidate、完成出力は `examples/layer2/` にあります。実際の NVD cache は Git 管理外です。

```bash
pytest
python -m py_compile app.py capra/layer1/*.py capra/layer1/parsers/*.py capra/layer1/utils/*.py capra/layer2/*.py capra/layer2/adapters/*.py capra/layer2/nvd/*.py capra/layer2/patterns/*.py
```

テストは実 NVD APIへアクセスせず、cache fixture または mock clientを使用します。Layer 2は無制限な経路探索をせず、`max_hops`、Rule match、Operator、Connection、Layer 3 candidate、upload size の上限を超えたデータを warning/metadata/unresolved として返します。
