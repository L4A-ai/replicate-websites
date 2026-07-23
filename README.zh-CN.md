[English](README.md) | [简体中文](README.zh-CN.md)

[![skills.sh](https://skills.sh/b/l4a-ai/replicate-websites)](https://skills.sh/l4a-ai/replicate-websites/pixel-by-pixel)

# Pixel by Pixel

**Pixel by Pixel**（`pixel-by-pixel`）是一个可移植的 Agent Skill，用于重建已获授权的
网页，并通过确定性的 Playwright 截图、语义契约、无障碍检查、交互测试和逐像素比较来
验证前端保真度。

仓库只维护一个规范技能：
[`skills/pixel-by-pixel`](skills/pixel-by-pixel)。它适用于 Claude Code、Codex
以及其他支持开放 Agent Skills 目录结构的智能体，不会为不同智能体复制多份技能说明。

> 本技能原名为 `replicate-websites`：请使用 `--skill pixel-by-pixel` 重新安装，然后删除
> 旧的技能安装目录，避免智能体同时发现两个副本。

## 功能

- 在沙箱中以只读 GET 方式检查已获授权的源页面
- 在四个响应式视口下进行全页面严格及容差逐像素比较
- 采集 DOM、排版、资源、控件、表单标签、链接和无障碍契约
- 提供安全的静态页面引导工具和零依赖的本地候选页面服务
- 候选页面完整性检查和合成的求职申请流程测试
- 同源模拟提交后端：默认不保留数据、默认关闭邮件
- 支持防回归的保真度循环、差异诊断和洁净环境评测

## 环境要求

- Node.js 20 或更高版本
- npm
- macOS、Linux 或 Windows

技能安装器负责放置说明和工具。安装后还需执行一次独立的初始化命令，以安装锁定版本的
npm 运行时和 Chromium。

## 使用跨智能体安装器

推荐使用与其他可移植 Agent Skill 仓库相同的
[`skills`](https://github.com/vercel-labs/skills) 安装方式：

```bash
npx skills add L4A-ai/replicate-websites \
  --skill pixel-by-pixel \
  --copy
```

安装器会检测受支持的智能体并打印安装目录。将 `SKILL_DIR` 指向该目录，然后安装并验证
运行时：

```bash
SKILL_DIR=/absolute/path/to/pixel-by-pixel
npm --prefix "$SKILL_DIR" run setup
npm --prefix "$SKILL_DIR" run doctor
```

`setup` 会安装 `playwright`、`pixelmatch` 和 `pngjs`，随后下载 Chromium；它不会安装后台
服务。`doctor` 为只读检查，用于报告 Node、依赖包和可用 Chromium 是否齐全。

### Codex

项目级安装：

```bash
npx skills add L4A-ai/replicate-websites \
  --skill pixel-by-pixel \
  --agent codex \
  --copy \
  -y

npm --prefix .agents/skills/pixel-by-pixel run setup
```

用户级安装：

```bash
npx skills add L4A-ai/replicate-websites \
  --skill pixel-by-pixel \
  --agent codex \
  --global \
  --copy \
  -y

npm --prefix ~/.agents/skills/pixel-by-pixel run setup
```

Codex 会从项目的 `.agents/skills` 和用户目录的 `~/.agents/skills` 中发现技能。

### Claude Code

项目级安装：

```bash
npx skills add L4A-ai/replicate-websites \
  --skill pixel-by-pixel \
  --agent claude-code \
  --copy \
  -y

npm --prefix .claude/skills/pixel-by-pixel run setup
```

用户级安装：

```bash
npx skills add L4A-ai/replicate-websites \
  --skill pixel-by-pixel \
  --agent claude-code \
  --global \
  --copy \
  -y

npm --prefix ~/.claude/skills/pixel-by-pixel run setup
```

### 多个或其他智能体

重复使用 `--agent`，即可为多个智能体安装同一个规范技能：

```bash
npx skills add L4A-ai/replicate-websites \
  --skill pixel-by-pixel \
  --agent codex \
  --agent claude-code \
  --copy \
  -y
```

对于其他受支持的智能体，可以省略 `--agent` 后交互选择，也可以传入安装器支持的智能体
标识。对于能读取自定义技能目录的智能体，将 `skills/pixel-by-pixel`
复制到其技能目录，再在副本中运行 `npm run setup`。

## 使用技能

要求智能体使用 `pixel-by-pixel`，并提供已获授权的目标 URL、输出目录和部署模式。
对于支持显式技能调用的智能体，可以使用如下提示词：

```text
Use $pixel-by-pixel to recreate this authorized webpage in an empty local workspace.
Keep the source GET-only, compare all four default viewports, and run the integrity gates.
```

完整的采集、实现、比较、诊断、交互和发布流程请参阅
[`SKILL.md`](skills/pixel-by-pixel/SKILL.md)。

也可以直接运行核心脚本：

```bash
SKILL_DIR=/absolute/path/to/pixel-by-pixel

node "$SKILL_DIR/scripts/compare-pages.mjs" \
  --baseline https://example.com/authorized-page \
  --candidate http://127.0.0.1:4173/ \
  --out /tmp/replica-comparison
```

默认视口为：桌面端 `1440x1000`、平板 `768x1024`、手机 `390x844` 和紧凑视口
`360x800`。

## 安全边界

- 对第三方在线目标只做只读检查；绝不提交其表单或发送分析写入请求。
- 只有在拥有所有权或获得许可时，才可复制内容和资源。
- `authorized-local` 输出必须保持私有，并仅绑定回环地址。
- 公开的第三方模拟页面必须持续显示清晰且无歧义的声明。
- 不得使用 iframe、反向代理、源站脚本、不透明隐藏值或整页截图伪造保真度。
- 申请人字段和上传文件只能短暂存在；除非另行实现并明确启用，否则邮件功能保持关闭。

完整说明请参阅
[`safety-and-provenance.md`](skills/pixel-by-pixel/references/safety-and-provenance.md)。

## 开发与验证

```bash
git clone https://github.com/L4A-ai/replicate-websites.git
cd replicate-websites
npm ci --ignore-scripts
npx playwright install chromium
npm run validate
npm run check:install
node evals/scripts/hash-skill.mjs
```

仓库结构：

| 路径 | 用途 |
|---|---|
| `skills/pixel-by-pixel/` | 唯一可分发的 Agent Skill |
| `test/skill/` | 仓库自有的运行时和浏览器测试 |
| `evals/` | 洁净环境评测器、策略、模式和贡献者文档 |
| `.github/workflows/skill-ci.yml` | 验证、发现、打包和哈希检查 |

CI 会验证仓库只暴露一个可发现技能，并确保 npm 压缩包只包含预期的技能运行时文件。

## 许可证

本仓库中的可复用代码和文档采用 MIT 许可证。捕获的第三方内容和资源不在授权范围内，
也不会随仓库分发。
