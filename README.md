# SmartPlate Access Control Check

`smartplate-parameter-integration-spec-v1.4.pdf` の内容に沿って、以下を確認するための最小実装です。

- `hs` の復号（AES-256-CBC + SHA-256 x 3 rounds）
- `readtime` の有効期限チェック（`atp` 別ウィンドウ）
- `ut` のセッション固定（初回アクセスでCookie保存、以後不一致は拒否）

## 構成

- `index.html`: 検証用の簡易UI
- `api/verify.js`: 復号 + 標準パターン検証 API
- `api/session.js`: セッション初期化 API
- `scripts/test-vector.js`: 仕様書のテストベクタ一致確認

## ローカル確認

```bash
# 1) 仕様書テストベクタで復号実装を確認
node scripts/test-vector.js

# 2) Vercel ローカル起動（vercel CLIがある場合）
vercel dev
```

## Vercel デプロイ手順

1. このディレクトリを新規リポジトリに push
2. Vercel で Import
3. Project Settings > Environment Variables で以下を設定
   - `SP_DECRYPT_KEY`: 本番用の復号キー（仕様書のテストキーではなく、実プロジェクト用）
4. Deploy

## 動作確認シナリオ（標準パターン）

1. NFC 経由で `?hs=...` 付き URL にアクセス
2. 初回:
   - `200 ACCESS_ALLOWED`
   - `sp_ut` Cookie がセットされる
3. 同一ブラウザで別 `ut` の `hs` を使う:
   - `403 USER_MISMATCH`
4. 有効期限外の `readtime`:
   - `410 EXPIRED`

## 補足

- テストベクタの `readtime` は過去時刻のため、`/api/verify` では `EXPIRED` になります（復号自体は成功しても期限チェックで拒否）。
- セッションを切り替えたい場合は UI の「セッション初期化」を実行してください。
