# CAPRA: Cloud Attack Path Risk Analyzer

CAPRA は、クラウド環境の脆弱性情報、IAM/RBAC の関係、重要資産候補、任意の構成図情報を共通の **Layer 1 Fact Graph** に正規化するためのプロトタイプです。現在の Streamlit アプリは Layer 1 の Fact Extraction に集中しており、後続レイヤーで攻撃経路分析やリスク評価を行うための入力データを生成します。

## Layer 1 で実装した内容

Layer 1 では、複数形式のセキュリティ情報を同じスキーマに変換し、`NetworkX` の有向グラフとして統合する処理を実装しています。

### 1. 共通スキーマへの正規化

以下の 3 種類のモデルを `pydantic` で定義し、入力形式の違いを吸収しています。

- `NodeModel`: クラウド資産、IAM 主体、サービス、DB、Secret などのノードを表します。
- `EdgeModel`: IAM 権限、RBAC 関係、ネットワーク接続などの関係を表します。
- `VulnerabilityModel`: CVE、パッケージ名、導入バージョン、修正版、深刻度などを表します。

`cloud` は `aws` / `gcp` / `azure` / `k8s` / `hybrid` / `unknown` に正規化し、それ以外の値は `unknown` として扱います。`type` や `asset_category` は小文字化して比較しやすい形にしています。

### 2. Grype JSON / SARIF の脆弱性パース

`capra/layer1/parsers/grype_parser.py` で、Grype の JSON と SARIF を `VulnerabilityModel` に変換します。

- JSON の場合は `matches[*].vulnerability` と `matches[*].artifact` から CVE、パッケージ名、導入バージョン、修正版、severity を抽出します。
- SARIF の場合は `runs[*].results` と `tool.driver.rules` を参照し、`ruleId`、message、rule properties から CVE、パッケージ名、severity を抽出します。
- CVE は `CVE-\d{4}-\d{4,}` の正規表現で検出します。

### 3. Hound 系 JSON のノード・エッジパース

`capra/layer1/parsers/hound_parser.py` で、Hound 系ツールの出力を想定した暫定 JSON 形式を読み込みます。

- 入力の `nodes` / `edges`、または `data.nodes` / `data.edges`、`graph.nodes` / `graph.edges` に対応します。
- ノード ID がない場合は、`cloud:type:name` 形式の安定した ID を生成します。
- エッジ種別は `AssumeRole`、`sts:AssumeRole`、`iam:PassRole` などの表記揺れを `assume_role`、`pass_role_or_act_as` などに正規化します。
- エッジだけに登場してノード一覧に存在しない ID は、推定ノードとして自動追加します。

### 4. Draw.io XML の補助的なトポロジ取り込み

`capra/layer1/parsers/drawio_parser.py` で、任意入力の Draw.io XML / `.drawio` を読み込みます。

- `mxCell vertex="1"` をノード、`mxCell edge="1"` をエッジとして抽出します。
- HTML タグや `<br>` を除去し、ラベルを正規化します。
- Draw.io の接続線は `network_access` エッジとして扱います。
- ラベルに `db`、`database`、`secret`、`admin`、`internet`、`api` などのキーワードが含まれる場合、暫定的にノード種別や重要資産候補を推定します。

### 5. 重要資産候補と Entry Point のマージ

`capra/layer1/asset_marker.py` で、`important_assets.yaml` などから重要資産候補と Entry Point を既存ノードへマージします。

- `assets` は `goal_candidate=True` として扱います。
- `entry_points` は `is_entry=True` として扱います。
- 同じ ID のノード、または `name` / `type` / `cloud` が一致するノードは同一資産としてマージします。
- Streamlit UI で選択された重要資産だけを `is_goal=True` にします。候補であることと、今回の分析で Goal として扱うことを分離しています。

## スコアリング実装について

Layer 1 では、旧 AttackRoute_Scanner のような攻撃パス探索や総合リスクスコア計算は実装していません。現在の独自ロジックは、後続レイヤーに渡す Fact Graph を安定して作るための正規化、名寄せ、重複排除、暫定スコア付けです。

### Severity の正規化

脆弱性の severity は、文字列ラベルを 0.0 から 1.0 の暫定スコアに変換します。

```text
Critical   -> 1.0
High       -> 0.8
Medium     -> 0.5
Low        -> 0.2
Negligible -> 0.1
Unknown    -> 0.0
```

`moderate` は `Medium`、`info` / `informational` は `Negligible`、`warning` は `Medium` として扱います。この値は現時点では脆弱性の正規化指標であり、ノード全体のリスクスコアではありません。

### エッジ強度の暫定スコア

Hound 系の関係には、後続レイヤーで攻撃経路の重みとして利用できるように `strength` を付与しています。

```text
modify_policy       -> 0.70
create_access_key   -> 0.65
pass_role_or_act_as -> 0.60
read_secret         -> 0.50
assume_role         -> 0.45
write_data          -> 0.55
read_data           -> 0.35
network_access      -> 0.30
attached_policy     -> 0.25
member_of           -> 0.20
unknown             -> 0.10
```

これは確率ではなく、権限関係の攻撃利用しやすさを表す暫定的な重みです。現時点では Layer 1 内で経路計算には使っていません。

### ノードマージ規則

同じノード ID が複数入力から得られた場合は、以下の規則で統合します。

```text
importance      = max(existing.importance, incoming.importance)
is_entry        = existing.is_entry OR incoming.is_entry
is_goal         = existing.is_goal OR incoming.is_goal
goal_candidate  = existing.goal_candidate OR incoming.goal_candidate
vulnerabilities = existing.vulnerabilities + incoming.vulnerabilities
raw_evidence    = existing.raw_evidence と incoming.raw_evidence を統合
```

`asset_category` は、新しい値が `unknown` でない場合に上書きします。これにより、Hound、Draw.io、重要資産 YAML など複数の入力に同じ資産が出てきても、情報を失わずに 1 ノードへ集約できます。

### 脆弱性とノードの対応付けアルゴリズム

`capra/layer1/vuln_mapper.py` では、Grype から得た脆弱性をノードへ付与するため、以下の順番でマッチングします。

1. `vulnerability_mapping.yaml` の明示ルールを優先します。`cve_id`、`package_name`、`node_id`、`node_name` を使って対応付けます。
2. Grype の `raw_evidence` に含まれる `target`、`image`、`container`、`location` などのヒントが、ノード名またはノード ID に含まれるかを確認します。
3. パッケージ名、artifact 名、purl と、ノード名またはノード ID の部分一致を確認します。
4. どれにも一致しない脆弱性は `unmapped_vulnerabilities` として保持します。

この処理は完全な資産特定ではなく、Fact Graph 生成段階での暫定的な名寄せです。確実に対応付けたい場合は、明示的な mapping ファイルを使う前提です。

### ID 生成規則

入力に ID がないノードは、以下の形式で ID を生成します。

```text
node_id = slugify(cloud) + ":" + slugify(type) + ":" + slugify(name)
```

`slugify` は小文字化し、英数字、`:`、`_`、`.`、`/`、`-` 以外を `-` に変換します。これにより、同じ名前・種別・クラウドの資産は同じ ID になりやすくなります。

## 実行方法

### インストール

```bash
pip install -r requirements.txt
```

### Streamlit アプリの起動

```bash
streamlit run app.py
```

画面で Grype JSON/SARIF、Hound generic JSON、重要資産 YAML/JSON、任意の CVE-to-node mapping YAML/JSON、任意の Draw.io XML をアップロードし、`Build Layer 1 Fact Graph` を押すと、ノード表、エッジ表、脆弱性表、簡易グラフ、Fact Graph JSON のダウンロードが表示されます。

### 可視化カラーの暫定仕様

Streamlit 上の `Layer 1 Fact Graph` では、ノードの色をリスクスコアではなく、重要資産の状態に基づいて暫定的に変更しています。

```text
is_goal=True          -> 赤: 今回の分析で Goal として選択された重要資産
goal_candidate=True   -> 黄: Goal 候補だが、今回の Goal には未選択の資産
その他のノード        -> 青: 通常ノード
```

判定順は `is_goal` が最優先で、次に `goal_candidate`、どちらでもない場合は通常ノードとして表示します。現時点では、脆弱性件数、severity、edge strength、攻撃経路上にあるかどうかでは色を変えていません。後続レイヤーでリスクスコアや攻撃経路が実装された場合、この色分けは変更する想定です。

エッジの色は、現時点では `type`、`permission`、`strength`、severity などでは判定していません。意味のある色分けに見えないよう、すべてのエッジを薄いグレー `#C7CED8` で固定表示しています。エッジ上のラベルには `network_access`、`assume_role`、`read_secret` などのエッジ種別だけを表示しています。

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

現在のテストでは、Grype parser、Hound parser、Fact Graph builder、Layer 1 schema の基本動作を確認しています。

## 現在の制約

- Layer 1 は Fact Graph 生成までを担当し、攻撃経路探索や総合リスクスコアリングはまだ行いません。
- Hound generic JSON の形式は暫定です。AWS / GCP / Azure / Kubernetes 固有の adapter は `capra/layer1/adapters/` に追加できる構成です。
- Draw.io からの種別推定はキーワードベースの補助機能です。正確な資産分類には Hound 系入力や重要資産 YAML を優先してください。