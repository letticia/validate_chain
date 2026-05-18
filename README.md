# TLS Certificate Chain Validator (`validate_chain.sh`)

指定した対象サーバーの TLS（SSL）証明書チェーンを動的に解析し、エンド証明書から上位の証明書（中間CA、ルート証明書）へと信頼チェーン（Chain of Trust）が正しく繋がっているかを検証するシェルスクリプトです。

## 特徴

- **動的なチェーン追跡**: サーバーから返される証明書の階層数（Depth）を動的に判定し、最上位まで途切れなく `Issuer`（発行者）と `Subject`（所有者）が一致するかを検証します。
- **直感的なエラーメッセージ**: チェーン切れ（設定漏れ）などが検知された場合、原因や解決策のヒントを日本語で分かりやすく出力します。
- **スマートな引数補完**: FQDN（ドメイン名）を1つ指定するだけで、ポート番号やサーバー名を自動で補完して検証を実行します。
- **外部依存なし**: `openssl`, `awk`, `grep` など、標準的なコマンド群のみで動作します。

## 前提条件 (Requirements)

- `bash`
- `openssl` (`s_client` コマンドを使用)
- 標準のテキスト処理ツール (`awk`, `grep`, `cut` など)

## 使い方 (Usage)

スクリプトに実行権限を付与してから使用してください。

```bash
chmod +x validate_chain.sh
```

### 1. FQDNを1つだけ指定する（おすすめ）

ドメイン名を1つ指定するだけで、自動的に `ポート443` と `ServerName (SNI)` が補完されて実行されます。

```bash
./validate_chain.sh certs.nii.ac.jp
```
*(内部的に `certs.nii.ac.jp:443` に対して `ServerName: certs.nii.ac.jp` として接続します)*

明示的にポート番号を指定したい場合は以下のように実行できます。
```bash
./validate_chain.sh example.com:8443
```

### 2. 引数なしで実行する

引数を省略した場合は、スクリプトにデフォルトで組み込まれているホスト（`certs.nii.ac.jp`）に対して検証を行います。動作確認に便利です。

```bash
./validate_chain.sh
```

### 3. ホストとサーバー名を個別に指定する

接続先のホスト（IPアドレスや別ポート）と、SNIとして送信するサーバー名を明確に分けたい場合に使用します。

```bash
./validate_chain.sh 192.168.1.100:443 example.com
```

## 出力例とトラブルシューティング

### 成功時の出力例

チェーンが正常にルート証明書または自己署名証明書まで辿れた場合は、各階層の一致状況と `[SUCCESS]` が表示されます。

```text
Connecting to certs.nii.ac.jp:443 (ServerName: certs.nii.ac.jp) ...
[OK] Depth 0 Issuer matches Depth 1 Subject.
[OK] Depth 1 Issuer matches Depth 2 Subject.
[SUCCESS] Certificate chain is perfectly linked from End-Entity to Root (Total Depth: 2).
```

### 失敗時の出力例（チェーン切れの場合）

サーバー側の設定ミス（中間証明書のインストール漏れなど）によりチェーンが途切れている場合、以下のようなどこで途切れたかの情報と共にエラーが表示されます。

```text
Connecting to www.example.com:443 (ServerName: www.example.com) ...
[ERROR] 証明書の信頼チェーン検証に失敗しました。（ルートまで辿れません）
詳細: unable to get local issuer certificate (エラーコード: 20)
原因: サーバー側に中間証明書が正しくインストールされていないか、必要なクロスルート証明書が不足しているため、チェーンが途切れています。
```

> **解決のヒント**: このエラーが出た場合、検証対象のウェブサーバー（Apache, Nginxなど）において、「サーバー証明書」単体だけでなく、「中間CA証明書」「クロスルート証明書」も含んだ正しい順序で設定・結合されているかを確認してください。
> 
> 詳しい設定手順については、以下のマニュアルをご参照ください：
> [https://nii-auth.atlassian.net/wiki/spaces/UPKIManual/pages/43877668/Apache+IIS+Nginx](https://nii-auth.atlassian.net/wiki/spaces/UPKIManual/pages/43877668/Apache+IIS+Nginx)

## ライセンス (License)

このプロジェクトは **MIT License** の下で公開されています。
詳細については、プロジェクトのルートディレクトリにある `LICENSE` ファイルをご覧ください。
