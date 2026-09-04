# CAPRA: Cloud Attack Path Risk Analyzer

CAPRAは、クラウド環境から収集した脆弱性情報とIAM/RBAC・構成情報を整理し、確認すべきAttack Operator候補とその依存関係を可視化するStreamlitベースのPlannerです。

入力データは最初にFact Graphへ正規化され、そのFactだけを使ってAttack Operator Graphが生成されます。AWS、Google Cloud、Azure、Kubernetesをまたぐ情報も、共通のグラフとして扱えます。

> [!IMPORTANT]
> CAPRAが出力するのは未検証の分析候補です。攻撃の成功、脆弱性の悪用可能性、実環境への到達性を保証するものではありません。CAPRAは攻撃コードの取得・生成・実行や、実環境への検証通信を行いません。

## 目次

- [CAPRAでできること](#capraでできること)
- [クイックスタート](#クイックスタート)
- [サンプルデータで試す](#サンプルデータで試す)
- [画面の使い方](#画面の使い方)
- [入力ファイルの準備](#入力ファイルの準備)
- [結果の読み方](#結果の読み方)
- [NVD情報の利用](#nvd情報の利用)
- [出力ファイル](#出力ファイル)
- [トラブルシューティング](#トラブルシューティング)
- [安全性と現在の制限](#安全性と現在の制限)
- [開発者向け情報](#開発者向け情報)

## CAPRAでできること

CAPRAは、次の処理を`Run CAPRA Planner`の1回の実行で行います。

```text
Grype / Hound / 重要資産 / Draw.io / クラウド間依存
                            │
                            ▼
                  Factの正規化・統合・秘匿化
                            │
                            ▼
                    Layer 1 Fact Graph
                            │
                    schema・hashを検証
                            │
                            ▼
                 Layer 2 Attack Operators
                            │
           effects / capabilitiesの一致だけを接続
                            │
                            ▼
          可視化・要確認項目・Layer 3候補・JSON出力
```

主な機能は以下のとおりです。

- Grype JSON/SARIFからCVE、パッケージ、バージョン、重要度を抽出
- Hound系のJSONからAWS、Google Cloud、Azure、KubernetesのNodeとEdgeを正規化
- 重要資産候補、Entry Point、分析ごとのGoalを管理
- 任意のDraw.io構成図とクラウド間依存関係を補助Factとして統合
- NVDキャッシュを使ったCVEのAttack Operator候補への変換
- source tool固有のルールによるIAM/RBAC Operatorの生成
- Fact GraphとAttack Operator Graphの可視化
- 未解決項目、手動確認対象、Layer 3候補の一覧化
- Fact Graph JSONとAttack Operator Graph JSONのダウンロード

## クイックスタート

### 1. 必要な環境

- Python 3.10以上
- `pip`
- Webブラウザ
- インターネット接続（初回の依存パッケージ導入時のみ。NVDをオンライン取得する場合にも必要）

### 2. セットアップ

リポジトリのルートで、仮想環境を作成して依存パッケージをインストールします。

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Windows PowerShell:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### 3. CAPRAを起動

```bash
streamlit run app.py
```

ブラウザが自動で開かない場合は、ターミナルに表示されたURLへアクセスします。通常は`http://localhost:8501`です。終了するときは、起動したターミナルで`Ctrl+C`を押します。

## サンプルデータで試す

最初は同梱のサンプルを使うと、入力から出力までの流れを確認できます。サンプルは架空のハイブリッドクラウド環境であり、実環境の秘密情報は含みません。

### ソースファイルから実行する

1. `Input mode`で`ソースファイル`を選択します。
2. 次のファイルをアップロードします。

| 画面の入力欄 | 使用するサンプル |
| --- | --- |
| Grype JSON/SARIF | `examples/layer1/grype_sample.json` |
| Hound generic JSON | `examples/layer1/hound_generic_sample.json` |
| 重要資産候補 YAML/JSON | `examples/layer1/important_assets.yaml` |
| CVE-to-node mapping YAML/JSON | `examples/layer1/vulnerability_mapping.yaml` |
| Draw.io XML/.drawio | `examples/layer1/architecture.drawio`（任意） |
| クラウド間依存関係 YAML/JSON | `examples/layer1/cross_cloud_edges.yaml`（任意） |

3. `今回Goalとして扱う重要資産候補`から、今回の分析対象を1つ以上選択します。未選択でも実行できます。
4. `Planner settings / Additional rules`を開きます。
5. 最初は`NVD mode`を`cache-only`、`NVD cache directory`を初期値の`cache/nvd`にします。
6. その他の設定は初期値のまま、`Run CAPRA Planner`を押します。
7. `CAPRA Planner completed.`と表示されたら、結果タブを順に確認します。

空のキャッシュを使った最初の実行では、IAM/RBAC由来のOperatorを確認でき、CVEはNVD情報不足としてReview queueに残ります。CVE由来のOperatorも生成する場合は、インターネット接続を確認して`cache-then-fetch`で再実行してください。取得結果は`cache/nvd`へ保存されます。

### 既存Fact Graphから実行する

1. `Input mode`で`既存Fact Graph JSON`を選択します。
2. `examples/layer1/fact_graph_sample.json`をアップロードします。
3. `NVD cache directory`は初期値の`cache/nvd`を使用します。
4. `Run CAPRA Planner`を押します。

このモードではFact Graphを再構築せず、互換loaderで読み込んでAttack Operator Graphを生成します。

サンプル環境の構成と各ファイルの詳細は、[`examples/README.md`](examples/README.md)を参照してください。

## 画面の使い方

### Input mode

入力方式を次の2種類から選びます。

| モード | 用途 |
| --- | --- |
| `ソースファイル` | Grype、Hound、重要資産などの元データから一括でPlanを作る |
| `既存Fact Graph JSON` | CAPRAで以前作成したFact Graph、または互換形式のJSONを再利用する |

入力方式を切り替えると、異なる入力の結果が混ざらないよう、画面内に保存されていた前回結果は破棄されます。

### Inputs

`ソースファイル`モードでは、少なくとも1ファイルが必要です。個々の入力は任意ですが、意味のあるIAM/RBAC分析にはHound情報、CVE分析にはGrype情報と対象Nodeが必要です。

| 入力 | 役割 | 対応形式 |
| --- | --- | --- |
| Grype | 脆弱性findingを取り込む | JSON、SARIF |
| Hound generic | NodeとIAM/RBAC・構成Edgeを取り込む | JSON |
| 重要資産候補 | Goal候補、資産分類、Entry Pointを追加する | YAML、JSON |
| CVE-to-node mapping | CVEと対象Nodeを明示的に対応付ける | YAML、JSON |
| Draw.io | 構成図のNodeと接続を補助Factとして追加する | XML、`.drawio` |
| クラウド間依存関係 | Providerをまたぐ構成上の依存を追加する | YAML、JSON |

### Goalの選択

`goal_candidate`は重要資産の候補、`is_goal`は今回の分析で明示的に選択した対象です。重要資産候補が自動的にGoalになることはありません。

| 属性 | 意味 |
| --- | --- |
| `goal_candidate=true` | Goalとして選べる重要資産候補 |
| `is_goal=true` | 今回ユーザーが明示的に選んだGoal |
| `is_entry=true` | 侵害済み主体や外部公開点などの分析開始地点 |

### Planner settings / Additional rules

通常は初期値で実行できます。大量データを扱う場合や、対象を絞り込む場合に変更します。

| 設定 | 説明 |
| --- | --- |
| `NVD mode` | オフラインキャッシュのみ、またはキャッシュ後にNVD取得を試す |
| `NVD cache directory` | CVEごとのNVDキャッシュを保存・参照するディレクトリ |
| `最大ホップ数` | IAMHoundDogパターン探索の深さの上限 |
| `Ruleごとの最大マッチ件数` | 1ルールが生成できる候補数の上限 |
| `最大Operator数` | 1回の実行で保持するOperator総数の上限 |
| `最大Connection数` | Operator間Connectionの上限 |
| `最大Layer 3候補数` | 次段へ渡す候補ID数の上限 |
| `最大アップロードサイズ` | Fact Graphまたは追加Ruleファイルに適用する上限 |
| `対象source_tool` | 指定したsource toolだけを変換対象にする。未選択ならすべて |
| `対象operator_type` | カンマ区切りでOperator種別を絞り込む。空欄ならすべて |

`Additional rule YAML`には、標準ルールへ追加する独自ルールをアップロードできます。標準ルールを編集せずに組織固有のEdgeやパターンを追加したい場合に使用します。

### Run CAPRA Planner

ボタンを押すと、入力の解析、Fact Graphの構築、Layer間handoffの検証、Attack Operator生成、Connection生成が順番に実行されます。

結果はStreamlitのsession stateに保持されるため、タブの移動やダウンロードによる再描画後も、最後に成功したPlanを確認できます。

### 結果タブ

| タブ | 内容 |
| --- | --- |
| `Overview` | データソース別件数、Fact分類、Attack Operator Graph |
| `Facts` | Fact Graph、Node、Edge、脆弱性の一覧 |
| `Attack operators` | 全Operator、IAM/RBAC、CVE、Connectionの一覧 |
| `Review queue` | 未解決項目、手動確認対象、Layer 3候補 |
| `Export` | Fact Graph JSONとAttack Operator Graph JSONの保存 |

### グラフの操作

Fact GraphとAttack Operator Graphでは、次の操作ができます。

- ノードをドラッグして配置を変更
- 背景をドラッグして表示範囲を移動
- マウスホイールまたはトラックパッドで拡大・縮小
- Attack Operator Graphのノードをクリックして詳細JSONを表示
- `閉じる`を押して詳細パネルを閉じる

Attack Operator Graphは初回表示時だけ物理レイアウトを安定化し、その後はノードを自由に移動できる状態になります。

## 入力ファイルの準備

実運用データを入力する前に、`examples/layer1/`のファイルをテンプレートとしてコピーすることを推奨します。

### Hound generic JSON

`nodes`と`edges`を持つJSONを使用します。Edgeの`source`と`target`はNode IDと一致させてください。Edgeにしか現れないIDはNodeとして補完されますが、属性が不足するため明示的なNode定義を推奨します。

```json
{
  "nodes": [
    {
      "id": "aws:user:developer",
      "name": "developer",
      "type": "principal",
      "cloud": "aws",
      "is_entry": true
    },
    {
      "id": "aws:role:DevOpsRole",
      "name": "DevOpsRole",
      "type": "role",
      "cloud": "aws"
    }
  ],
  "edges": [
    {
      "fact_id": "iam-001",
      "source": "aws:user:developer",
      "target": "aws:role:DevOpsRole",
      "type": "assume_role",
      "permission": "sts:AssumeRole",
      "source_tool": "iamhounddog"
    }
  ]
}
```

主な`source_tool`は`hound_generic`、`iamhounddog`、`azurehound`、`gcp_hound`、`clusterhound`、`bloodhound_kube`です。

`source_tool`は単なる表示用ラベルではなく、Layer 2で使用する変換adapterを選ぶために使われます。元データを生成したtoolに合わせて指定してください。

### 重要資産候補 YAML/JSON

`assets`にGoal候補、`entry_points`に分析開始地点を指定します。

```yaml
assets:
  - id: "gcp:secret:analytics-api-key"
    name: "analytics-api-key"
    type: "secret"
    cloud: "gcp"
    goal_candidate: true
    asset_category: "high"

entry_points:
  - id: "aws:user:developer"
    name: "developer"
    type: "principal"
    cloud: "aws"
```

### CVE-to-node mapping YAML/JSON

自動対応付けが曖昧な場合は、CVEとNodeの対応を明示します。

```yaml
vulnerability_mappings:
  - node_id: "k8s:pod:payment-api"
    cve_id: "CVE-2021-44228"
    package_name: "log4j-core"
```

CVEは次の順序でNodeへ対応付けられます。

1. CVE-to-node mappingの明示ルール
2. Grype evidence内のtarget、image、container、location
3. package名またはartifact名とNode名・IDの部分一致
4. 対応できなければ`unmapped_vulnerabilities`へ保持

### クラウド間依存関係 YAML/JSON

クラウドをまたぐ参照や構成上の依存を`dependencies`へ記述します。

```yaml
dependencies:
  - source: "aws:secret:gcp-analytics-reference"
    target: "gcp:serviceaccount:analytics-exporter"
    type: "stores_reference_to"
    source_tool: "manual"
```

この入力は構成上のFactを追加するものです。記述しただけでAttack Operatorや攻撃経路として成立するわけではありません。

### Draw.io

`.drawio`またはXML形式のファイルを使用します。CAPRAは図中のvertexをNode、接続線を`network_access`の補助Factとして読み込みます。

Draw.ioのラベルからNode種別を簡易推定するため、`database`、`secret`、`admin`、`internet`、`service`など、役割が分かる名前を付けてください。Draw.ioだけではcloudや権限の意味を十分に確定できないため、Hound情報を主入力として併用することを推奨します。

### Fact Graph JSON

Fact Graphの基本構造は以下のとおりです。完全な例は[`examples/layer1/fact_graph_sample.json`](examples/layer1/fact_graph_sample.json)を参照してください。

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
     input_hashes, node/edge/vulnerability counts
```

Node IDと`fact_id`は一意である必要があります。Edgeの`source`と`target`は、同じFact Graph内に存在するNode IDを参照してください。

## 結果の読み方

### 画面上部の件数

| 項目 | 意味 |
| --- | --- |
| `Fact Nodes` | 統合後の資産・主体などのNode数 |
| `Fact Edges` | 観測された権限・関係・構成Fact数 |
| `CVEs` | Fact Graphに保持された脆弱性数 |
| `Operators` | ルールから生成されたAttack Operator候補数 |
| `Connections` | 条件またはCapabilityが一致したOperator間接続数 |
| `Unresolved` | 情報不足、未知Edge、上限到達などの未解決件数 |
| `Manual verification` | 人による確認が必要なOperator数 |
| `Layer 3 Candidates` | 将来のRuntime Validationへ渡せる未検証候補数 |

`Fact handoff verified`が表示された場合、Layer 1からLayer 2へ渡したFact Graphのschemaとhashが検証されています。既存Fact Graphモードでは互換loaderを経由したことを示すメッセージが表示されます。

### Fact Graph

Fact Graphは観測事実のグラフです。Edgeが表示されていても、攻撃が成立するという意味ではありません。

- Goal：今回明示的に選択した重要資産
- Goal candidate：重要資産候補
- Entry Point：分析開始地点
- `raw_evidence`：元データとprovenance。画面の表では省略し、JSONには保持

同じ2つのNode間に異なる観測元のFactがある場合、`MultiDiGraph`の並列Edgeとして保持されます。同じ`fact_id`だけが重複排除されます。

### Attack Operator

| status | 解釈 |
| --- | --- |
| `complete` | そのOperatorをモデル化するためのFactが揃っている |
| `partial` | 候補は作れたが、到達性や実行条件などが不足している |
| `unresolved` | Operatorとして確定できない情報が残っている |

`complete`は攻撃成功や実環境での検証完了を意味しません。現在生成される候補の`verification_status`は原則として`unverified`です。

### Attack Operator Graph

Attack Operator Graphには2種類の接続が表示されます。

- Operator間の実線`enables`：先行Operatorのeffectまたは生成Capabilityが、後続Operatorの条件を満たす候補
- 資産NodeとOperator間の破線`source` / `target`：どのFact Nodeに関係するかを示す表示用context

破線のcontextは、ダウンロードされるOperator間Connectionには追加されません。また、`target_node == source_node`というNode IDの一致だけではOperator同士を接続しません。

### Review queue

分析結果は、特に次の順で確認することを推奨します。

1. `Unresolved items`で、未知Edge、NVD cache miss、条件不足、件数上限を確認
2. `Manual verification`で、人による根拠確認が必要なOperatorを確認
3. `Layer 3 candidates`で、将来のRuntime Validationへ渡す候補を確認
4. 各Operatorの`source_fact_ids`と`raw_evidence`をFact Graphへ照合

## NVD情報の利用

### cache-only

ローカルキャッシュだけを使用します。外部通信がなく、同じ入力とキャッシュから再現しやすいため、通常はこちらを推奨します。

キャッシュファイル名は`CVE-YYYY-NNNN.json`形式で、取得日時とNVDレスポンスを保持します。`examples/layer2/nvd`にあるJSONはparser検証用の生レスポンスfixtureであり、実行時キャッシュではありません。Plannerの`NVD cache directory`には、初期値の`cache/nvd`など、実行時キャッシュ用のディレクトリを指定してください。

### cache-then-fetch

有効なキャッシュがなければ、NVD APIから情報を取得してキャッシュへ保存します。このモードでは外部通信が発生します。

NVD API keyを使う場合は、CAPRAの起動前に環境変数へ設定します。

macOS / Linux:

```bash
export NVD_API_KEY="your-api-key"
streamlit run app.py
```

Windows PowerShell:

```powershell
$env:NVD_API_KEY="your-api-key"
streamlit run app.py
```

API keyや認証情報を入力ファイル、追加ルール、Git履歴へ保存しないでください。

## 出力ファイル

`Export`タブから次のJSONをダウンロードできます。

### fact_graph.json

正規化したNode、Edge、対応済み・未対応の脆弱性、入力元、schema version、入力hashを含みます。後から`既存Fact Graph JSON`モードで再利用できます。

### attack_operator_graph.json

次の情報を含みます。

```text
attack_operators
  └─ operator_type, source/target node, preconditions, effects,
     produces, requires, status, verification_status, evidence
connections
  └─ source/target operator, enables, artifactまたはcondition, reason
unresolved_items
layer3_candidates
metadata
  └─ input hash, rule version/hash, cache統計、件数、実行設定
```

OperatorとConnectionのIDは、正規化した入力とルールから安定生成されます。実行日時と処理時間を除けば、同じFact Graph、ルール、NVDキャッシュから同じJSONを生成する設計です。

## トラブルシューティング

### `入力ファイルを少なくとも1つアップロードしてください`

`ソースファイル`モードでファイルが選択されていません。少なくとも1つアップロードしてください。既存のFact Graphを使う場合は、Input modeを切り替えます。

### `Fact Graph JSON parse error`

JSONの構文を確認してください。末尾の余分なカンマ、コメント、文字コードの問題がよくある原因です。完全なサンプルと比較してください。

### Operatorが0件になる

次を確認します。

- Hound Edgeに正しい`source_tool`が設定されているか
- Edgeの`type`または`permission`が標準ルールに存在するか
- `対象source_tool`や`対象operator_type`で除外していないか
- CVEの場合、対象NodeへのmappingとNVDキャッシュが存在するか
- `Review queue`に未知Edgeや条件不足が記録されていないか

未知Edgeは破棄されず、原則として`Unresolved items`に残ります。組織固有のEdgeであれば、対応する追加Rule YAMLを指定してください。

### CVEがNodeに紐付かない

`Facts`タブの脆弱性一覧で`unmapped`を確認し、CVE-to-node mappingへ`node_id`、`cve_id`、必要に応じて`package_name`を追加します。

### NVD cache missまたはfetch failureが出る

- `NVD cache directory`のパスがリポジトリルートから見て正しいか確認
- `cache-only`では対象CVEのファイルが存在するか確認
- `cache-then-fetch`ではネットワーク、API制限、`NVD_API_KEY`を確認
- 期限切れ・破損キャッシュは再取得するか、正しいキャッシュへ置き換える

### 件数の一部が切り捨てられる

`warnings`または`Unresolved items`で`limit reached`を確認します。入力規模を確認したうえで、Planner settingsのOperator、Connection、候補、ホップ、ルールマッチ上限を段階的に増やしてください。

### グラフが重なる、ノードが離れて見える

初期安定化後にノードをドラッグして配置を調整できます。背景ドラッグとズームも利用できます。大規模なグラフは、`対象source_tool`または`対象operator_type`で表示対象を絞ると確認しやすくなります。

## 安全性と現在の制限

### 秘密情報の扱い

CAPRAはEvidence、出力、metadata内の`secret`、`password`、`token`、`api key`、`credential`、`private key`、`authorization`などの値を再帰的に`[REDACTED]`へ置換します。

ただし、未知のフィールド名や自由記述内の秘密情報を完全に検出できるとは限りません。実データを入力する前に不要な機密情報を削除し、ダウンロードしたJSONも共有前に確認してください。

### Layer 1の境界

Layer 1はFactの正規化だけを行います。Attack Operator生成、NVDアクセス、攻撃経路探索、攻撃成立判定、リスク計算、LLM利用、ペイロード生成、攻撃実行は行いません。

### Layer 2の境界

Layer 2は決定的なルールに基づく候補生成です。実環境への検証通信、攻撃成功判定、Goal指向探索、リスク・ベイズ計算、LLMによるOperator選択、TTPやペイロード生成、Exploit取得・実行は行いません。

Operator間では、次の場合だけ順方向の`enables`を生成します。

1. 先行Operatorの`effects`が後続Operatorの`preconditions`を満たす
2. 先行Operatorの`produces`が後続Operatorの`requires`を満たす

Capability接続では`artifact_type`と`subject_node_id`の一致が必要です。Nodeが同じという理由だけでOperatorを接続することはありません。

### 現在の対応範囲

- 入力parserはGrype JSON/SARIF、汎用Hound JSON、Draw.io、手動YAML/JSONを対象としています。
- 製品固有のHound生形式には、追加の正規化やadapterが必要になる場合があります。
- `bloodhound_kube`はsource toolとして保持できますが、未対応Edgeは要確認項目になります。
- Runtime Validationは将来のLayer 3の責務であり、現在のアプリには含まれません。

## 開発者向け情報

### プロジェクト構成

```text
app.py                    Streamlit UI
capra/planner.py          Layer 1からLayer 2への検証付きhandoff
capra/layer1/             Factのparser、schema、graph、export
capra/layer2/             adapter、rule、Operator graph、NVD、export
examples/layer1/          入力サンプルとFact Graphサンプル
examples/layer2/          NVD cacheとOperator Graphサンプル
tests/                    pytestテスト
```

### Python API

現在schemaのFact Graphから直接Planを生成できます。

```python
import json
from pathlib import Path

from capra.layer2.schemas import Layer2Config
from capra.planner import build_plan_from_layer1

fact_graph = json.loads(
    Path("examples/layer1/fact_graph_sample.json").read_text(encoding="utf-8")
)

result = build_plan_from_layer1(
    fact_graph,
    Layer2Config(
        nvd_mode="cache-only",
        nvd_cache_directory=Path("cache/nvd"),
    ),
)

print(result.handoff_hash)
print(len(result.attack_operator_graph.attack_operators))
```

parserからLayer 1も構築する場合は`build_capra_plan()`を使用します。引数には`NodeModel`、`EdgeModel`、`VulnerabilityModel`の配列を渡します。

### テスト

```bash
python -m pytest -p no:cacheprovider -q
```

構文だけを確認する場合:

```bash
python -m py_compile \
  app.py capra/planner.py \
  capra/layer1/*.py capra/layer1/parsers/*.py capra/layer1/utils/*.py \
  capra/layer2/*.py capra/layer2/adapters/*.py capra/layer2/nvd/*.py \
  capra/layer2/patterns/*.py
```

テストは実NVD APIへアクセスせず、キャッシュfixtureまたはmock clientを使用します。

### 参考サンプル

- [`examples/layer1/`](examples/layer1/)：入力とFact Graph
- [`examples/layer2/`](examples/layer2/)：NVDキャッシュ、Operator、Connection、未解決項目
- [`examples/README.md`](examples/README.md)：サンプルのハイブリッドクラウド構成
