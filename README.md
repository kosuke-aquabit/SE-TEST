# SmartPlate Access Control Check

`smartplate-parameter-integration-spec-v1.4.pdf` の内容に沿って、以下を確認するための最小実装です。

- `hs` の復号（AES-256-CBC + SHA-256 x 3 rounds）
- `readtime` の有効期限チェック（`atp` 別ウィンドウ）
- `atp` の判定（`NFC: atp=N` のみ許可）
- `id` のワンタイムチェック（Upstash Redis による使用済み管理）← **厳格パターン**

## 構成

- `index.html`: 自動判定して保護コンテンツを出し分けるページ
- `api/verify.js`: 復号 + 厳格パターン検証 API（idワンタイム）
- `api/session.js`: セッションクリア API
- `scripts/test-vector.js`: 仕様書のテストベクタ一致確認

## アクセス制御の仕組み（厳格パターン）

```
NFCタップ
  └─ plate.id サーバ → ?hs=... 付きURLへリダイレクト
       └─ /api/verify
            ├─ hs を復号
            ├─ atp=N（NFC）チェック
            ├─ readtime 有効期限チェック（5分以内）
            └─ id をRedisに SET NX で登録
                 ├─ 未使用 → 200 ACCESS_ALLOWED（登録完了）
                 └─ 使用済み → 409 ID_ALREADY_USED（拒否）
```

同じ `hs` URL を別端末でコピーしてアクセスしても、`id` がすでに使用済みとして Redis に記録されているため **409 エラー** で拒否されます。

## 必要な環境変数（Vercel）

| 変数名 | 説明 | 設定方法 |
|---|---|---|
| `SP_DECRYPT_KEY` | hs 復号キー（プロジェクト固有） | 手動設定 |
| `KV_REST_API_URL` | Upstash Redis REST API URL | Upstash連携で自動設定 |
| `KV_REST_API_TOKEN` | Upstash Redis 認証トークン | Upstash連携で自動設定 |

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
3. **Storage → Upstash (Redis) を作成してプロジェクトに接続**
   - `KV_REST_API_URL` / `KV_REST_API_TOKEN` が自動追加される
4. Project Settings > Environment Variables で以下を手動設定
   - `SP_DECRYPT_KEY`: 本番用の復号キー
5. Deploy

## 動作確認シナリオ（厳格パターン）

1. NFC 経由で `?hs=...` 付き URL にアクセス
2. 初回:
   - `200 ACCESS_ALLOWED`
   - 画面に「セキュアなアクセスです。」と保護コンテンツが表示される
   - Redis に `sp:used_id:{id}` が記録される（TTL: 7日）
3. **同じ URL を別端末・別ブラウザでアクセス**:
   - `409 ID_ALREADY_USED`
   - 画面に「不正なアクセスです。」が表示される ← **URL共有防止**
4. 有効期限外の `readtime`:
   - `410 EXPIRED`
5. `atp=Q` または `atp=L` のアクセス:
   - `403 NON_NFC_ACCESS`

## 補足

- テストベクタの `readtime` は過去時刻のため、`/api/verify` では `EXPIRED` になります（復号自体は成功しても期限チェックで拒否）。
- 使用済み `id` の TTL は 7日間です。期間経過後は同じ `id` が再利用可能になりますが、`readtime` の有効期限（5分）により実質的に再利用は不可能です。
- Redis の `SET NX`（存在しない場合のみセット）によりアトミックに使用済み登録を行うため、同時アクセスによる競合も防止されます。
