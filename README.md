# Rubicairn

超軽量・単一ユーザー向けの独立 ActivityPub（Fediverse）サーバーです。

## 名称の由来（Origin of the Name）

**Rubicairn（ルビケルン）** は、**Ruby**（紅玉）と **Cairn**（ケルン＝登山道に積まれた道標の石積み）を掛け合わせた造語です。

- **Ruby**: Ruby 4.0（標準ライブラリ中心・最小依存）で書かれています。
- **Cairn**: 汎用 SNS サーバーではなく、メンテナンスの手間をかけずに長く残る道標のような個人発信拠点です。

> **Note**: Rubicairn は Mastodon からインスパイアされて作成した、独立した ActivityPub サーバー実装です。

## 主な特徴

- **超軽量フットプリント**: Ruby 4.0 + Sinatra + Puma + SQLite3 (WAL) で定常メモリ約 60〜100 MiB。
- **パーミッシブ依存のみ**: 依存 Gem は `sinatra`, `puma`, `sqlite3`, `rackup`, `rss`, `base64`, `minitest` のみ（コピーレフト依存ゼロ、`Gemfile.lock` SHA256 チェックサム固定）。
- **単一ユーザー**: ActivityPub 経由では返信・メンション・他者の投稿を受信せず、扱うのは自分の投稿と、受信したいいねの数だけです。
- **公開ページは完全ゼロ JS（管理画面を除く）**: `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline';` を維持し、外部アセット・Cookie・トラッキングを一切使いません。公開連絡先メールも CSS で難読化しています。
- **多層防御の管理画面 (`/admin`)**:
  1. **Cloudflare Access**（`Cf-Access-Authenticated-User-Email` 照合）＋ CSRF トークン検証
  2. **純 Ruby 標準 OpenSSL による WebAuthn (Passkey) 認証**（外部 `webauthn` / `cbor` gem 不使用）
  3. **秘密鍵の暗号化ボールト**: ActivityPub 署名用 RSA 秘密鍵を `AES-256-GCM` で暗号化（`config/private.pem.enc`）し、Passkey 認証中のみメモリ上に復号
  4. **高リスク操作のステップアップ再認証**: 新規フォロー・未知アカウントのフォロー承認・Passkey 追加/削除の直前に都度 Passkey 再タッチを要求
- **月次 OSV.dev 脆弱性チェック**: `bin/check-advisories` により `Gemfile.lock` の脆弱性を確認し、該当がある間は管理画面へ週 1 回の頻度でリマインドを表示（`Gemfile.lock` 更新で自動消去）。

## デメリット・制限

Rubicairn はセキュリティと軽量さを優先して設計しているため、一般的な ActivityPub（Fediverse）サーバーにある多くの機能を意図的に実装していません。

- **タイムラインは RSS 経由のみ**: 他サーバーの投稿を ActivityPub 経由で直接受信・表示せず、フォロー先が配信する RSS フィードから取得します。これにより、少なくとも外部の投稿データを ActivityPub の `Create` として処理することはなく、その経路のパースや署名処理に起因する脆弱性・インジェクションのリスクを避けています。
- **リプライ・メンションを受信できない**: Inbox ではフォロー・いいね・取り消し等のみを受け付け、他者からの返信やメンション（`Create`）は保存せず破棄します。
- **DM 機能・画像投稿機能がない**: 画像やダイレクトメッセージを実装すると、セキュリティリスクが増えるだけでなく、メタデータ等を通じた意図しない個人情報流出にもつながります。個人での保守範囲を超えるため、実装していません。

> **推奨**: 単一ユーザーで最小構成の ActivityPub を試してみたい方向けの実装です。サーバーを維持する金銭的・時間的余裕がある場合は、他の本格的な ActivityPub（Fediverse）サーバーを利用することを強く推奨します。

## セキュリティ上の注意（公開・運用時）

- **無保証・参考実装**: 開発者（`hrtmys`）自身が利用するために作ったプログラムであり、完全に無保証です。リポジトリの公開は、設計や実装の参考にしていただく目的を主としています。
- **限界の認識**: 脆弱性リスクを下げることを目的に、Cloudflare Access による保護や Passkey による署名用秘密鍵の暗号化といった対策を重ねています。それでも、未知の不具合や抜け穴が残っている可能性は否定できません。本ソフトウェアは、学生が Google Antigravity を用いて趣味で開発したものです。興味本位で利用される場合も十分にご注意ください。
- **軽量サーバーの代替候補**: 実運用向けの軽量な Mastodon 互換サーバーを検討されている場合は、移植性の高い C 言語で書かれた [grunfink/snac2](https://codeberg.org/grunfink/snac2) などの利用を推奨します。
- **必ず認証リバースプロキシの背後で運用してください**: `compose.yml` のポート公開をそのままインターネットへ直接晒さないでください（`Cf-Access-Authenticated-User-Email` ヘッダはリバースプロキシが終端・上書きする前提です。プロキシと同一ホスト上で完結する場合は `127.0.0.1:20001:4567` のようにローカルバインドすることを推奨します）。

## セットアップ

始める前に、前節のとおり認証リバースプロキシ（Cloudflare Access）を用意し、ポートをインターネットへ直接公開しないでください。

```bash
cp config/app.yml.example config/app.yml
# config/app.yml の domain / username / admin_email / contact 等を編集

docker compose build
docker compose run --rm app bundle exec ruby bin/setup
docker compose up -d
```

1. ブラウザで `https://<your-domain>/admin` を開くと `/admin/auth` へ遷移します。
2. 初回 Passkey を登録すると `config/private.pem` が `AES-256-GCM` で暗号化され、平文の秘密鍵は削除されます。
3. 初回登録のときに **1 回のみ表示される 64 桁のリカバリーキー**を、必ず安全な場所へ保管してください。

## テスト

```bash
docker compose run --rm -e RACK_ENV=test app \
  bundle exec ruby -Ilib:test -e 'Dir["test/test_*.rb"].each { |f| require_relative f }'
```

## 運用コマンド

- 脆弱性チェック手動実行: `docker compose exec -T app bundle exec ruby bin/check-advisories`
- Passkey 状態確認 / 緊急リセット: `docker compose exec -T app bundle exec ruby bin/reset-passkey --status`

## ライセンス

[MIT License](LICENSE)
