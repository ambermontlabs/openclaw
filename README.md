# 🦞 OpenClaw — Personal AI Assistant

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/openclaw/openclaw/main/docs/assets/openclaw-logo-text-dark.svg">
    <img src="https://raw.githubusercontent.com/openclaw/openclaw/main/docs/assets/openclaw-logo-text.svg" alt="OpenClaw" width="500">
  </picture>
</p>

<p align="center">
  <strong>EXFOLIATE! EXFOLIATE!</strong>
</p>

<p align="center">
  <a href="https://github.com/openclaw/openclaw/actions/workflows/ci.yml?branch=main"><img src="https://img.shields.io/github/actions/workflow/status/openclaw/openclaw/ci.yml?branch=main&style=for-the-badge" alt="CI status"></a>
  <a href="https://github.com/openclaw/openclaw/releases"><img src="https://img.shields.io/github/v/release/openclaw/openclaw?include_prereleases&style=for-the-badge" alt="GitHub release"></a>
  <a href="https://discord.gg/clawd"><img src="https://img.shields.io/discord/1456350064065904867?label=Discord&logo=discord&logoColor=white&color=5865F2&style=for-the-badge" alt="Discord"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge" alt="MIT License"></a>
</p>

**OpenClaw** is a _personal AI assistant_ you run on your own devices.
It answers you on the channels you already use (WhatsApp, Telegram, Slack, Discord, Google Chat, Signal, iMessage, BlueBubbles, IRC, Microsoft Teams, Matrix, Feishu, LINE, Mattermost, Nextcloud Talk, Nostr, Synology Chat, Tlon, Twitch, Zalo, Zalo Personal, WeChat, WebChat). It can speak and listen on macOS/iOS/Android, and can render a live Canvas you control. The Gateway is just the control plane — the product is the assistant.

If you want a personal, single-user assistant that feels local, fast, and always-on, this is it.

---

## 🚀 Quick Start

### Recommended Setup (5 minutes)

**Runtime:** Node 24 (recommended) or Node 22.16+

```bash
# Install OpenClaw globally
npm install -g openclaw@latest
# or: pnpm add -g openclaw@latest

# Run the onboarding wizard (recommended)
openclaw onboard --install-daemon
```

OpenClaw Onboard guides you step by step through setting up the gateway, workspace, channels, and skills.

### TL;DR - Get Running in 60 Seconds

```bash
# Install and onboard
openclaw onboard --install-daemon

# Start the gateway (in one terminal)
openclaw gateway --port 18789 --verbose

# Send a message (in another terminal)
openclaw message send --to +1234567890 --message "Hello from OpenClaw"

# Talk to the assistant
openclaw agent --message "Ship checklist" --thinking high
```

---

## 📚 Documentation

| Topic | Link |
|-------|------|
| **Getting Started** | [docs.openclaw.ai/start/getting-started](https://docs.openclaw.ai/start/getting-started) |
| **Onboarding Wizard** | [docs.openclaw.ai/start/wizard](https://docs.openclaw.ai/start/wizard) |
| **Installation** | [docs.openclaw.ai/install](https://docs.openclaw.ai/install) |
| **Configuration** | [docs.openclaw.ai/gateway/configuration](https://docs.openclaw.ai/gateway/configuration) |
| **Channels** | [docs.openclaw.ai/channels](https://docs.openclaw.ai/channels) |
| **Tools & Skills** | [docs.openclaw.ai/tools](https://docs.openclaw.ai/tools) |
| **Security** | [docs.openclaw.ai/gateway/security](https://docs.openclaw.ai/gateway/security) |
| **Troubleshooting** | [docs.openclaw.ai/channels/troubleshooting](https://docs.openclaw.ai/channels/troubleshooting) |
| **FAQ** | [docs.openclaw.ai/help/faq](https://docs.openclaw.ai/help/faq) |

---

## 🌟 Features

### 📱 Multi-Channel Support
Connect with your assistant on the platforms you already use:
- WhatsApp, Telegram, Slack, Discord
- Google Chat, Signal, iMessage (BlueBubbles recommended)
- Microsoft Teams, Matrix, Feishu, LINE
- Mattermost, Nextcloud Talk, Nostr, Synology Chat
- Tlon, Twitch, Zalo, WeChat, WebChat

### 🎯 Smart Routing
- Multi-agent routing with isolated workspaces
- Group message handling with mention gating
- Channel-specific rules and permissions

### 🎤 Voice & Audio
- **Voice Wake** on macOS/iOS (wake words)
- **Talk Mode** continuous voice on Android
- ElevenLabs + system TTS fallback

### 🖼️ Visual Workspace
- **Live Canvas** with agent-driven visual interface
- [A2UI](https://docs.openclaw.ai/platforms/mac/canvas#canvas-a2ui) for rich UI components
- Browser control with snapshots and actions

### 🛠️ Powerful Tools
- **Browser automation** (dedicated Chrome/Chromium)
- **Canvas** with eval, snapshot, and push/reset
- **Nodes** for camera, screen recording, location, notifications
- **Cron jobs** and webhooks for automation

### 📱 Companion Apps
- **macOS app** - menu bar control, voice wake, PTT overlay
- **iOS node** - Canvas, voice trigger, camera, screen recording
- **Android node** - Connect tab, chat sessions, voice tab

---

## 🔧 Installation Options

### npm / pnpm (Recommended)
```bash
npm install -g openclaw@latest
# or
pnpm add -g openclaw@latest

openclaw onboard --install-daemon
```

### Docker
```bash
docker run -it \
  -v openclaw-data:/root/.openclaw \
  -p 18789:18789 \
  openclaw/openclaw
```

### Nix
```bash
nix run github:openclaw/nix-openclaw
```

### From Source (Development)
```bash
git clone https://github.com/openclaw/openclaw.git
cd openclaw

pnpm install
pnpm ui:build  # auto-installs UI deps on first run
pnpm build

pnpm openclaw onboard --install-daemon

# Dev loop (auto-reload on source/config changes)
pnpm gateway:watch
```

---

## 🎮 Chat Commands

Send these in any connected channel:

| Command | Description |
|---------|-------------|
| `/status` | Compact session status (model + tokens, cost) |
| `/new` / `/reset` | Reset the current session |
| `/compact` | Compact session context (summary) |
| `/think <level>` | Set thinking level: off|minimal|low|medium|high|xhigh |
| `/verbose on\|off` | Toggle verbose output |
| `/usage off\|tokens\|full` | Set usage footer display |
| `/restart` | Restart the gateway (owner-only in groups) |
| `/activation mention\|always` | Group activation toggle |

---

## 🔐 Security

OpenClaw connects to real messaging surfaces. Treat inbound DMs as **untrusted input**.

### Default Security Model
- Tools run on the host for the **main** session (full access when it's just you)
- Group/channel safety: set `agents.defaults.sandbox.mode: "non-main"` to run non-main sessions inside per-session Docker sandboxes

### DM Policy
- **pairing** (default): Unknown senders receive a pairing code; bot doesn't process their message
- **open**: Public inbound DMs require explicit opt-in

Run `openclaw doctor` to check for risky/misconfigured DM policies.

Full security guide: [docs.openclaw.ai/gateway/security](https://docs.openclaw.ai/gateway/security)

---

## 📦 Supported Models

OpenClaw supports multiple AI providers:

- **OpenAI** (ChatGPT/Codex) - OAuth or API keys
- **Anthropic** (Claude)
- **Google** (Gemini)
- **OpenRouter**
- And more...

### Recommended Setup
For the best experience and lower prompt-injection risk, use the strongest latest-generation model available to you.

- [Models configuration](https://docs.openclaw.ai/concepts/models)
- [Model failover](https://docs.openclaw.ai/concepts/model-failover)

---

## 🌐 Web Access

OpenClaw serves a **Control UI** and **WebChat** directly from the Gateway:

- Control Panel: `http://localhost:18789`
- WebChat: `http://localhost:18789/chat`

### Remote Access Options
- **Tailscale Serve/Funnel** - Expose Gateway dashboard securely
- **SSH tunnels** - Connect from anywhere

Details: [Tailscale guide](https://docs.openclaw.ai/gateway/tailscale) · [Remote access](https://docs.openclaw.ai/gateway/remote)

---

## 📖 Advanced Topics

| Topic | Documentation |
|-------|---------------|
| Architecture | [docs.openclaw.ai/concepts/architecture](https://docs.openclaw.ai/concepts/architecture) |
| Gateway Protocol | [docs.openclaw.ai/reference/rpc](https://docs.openclaw.ai/reference/rpc) |
| Session Management | [docs.openclaw.ai/concepts/session](https://docs.openclaw.ai/concepts/session) |
| Agent Loop | [docs.openclaw.ai/concepts/agent-loop](https://docs.openclaw.ai/concepts/agent-loop) |
| TypeBox Schemas | [docs.openclaw.ai/concepts/typebox](https://docs.openclaw.ai/concepts/typebox) |
| Queue System | [docs.openclaw.ai/concepts/queue](https://docs.openclaw.ai/concepts/queue) |

---

## 🤝 Community

- **Discord**: [discord.gg/clawd](https://discord.gg/clawd)
- **GitHub Issues**: [github.com/openclaw/openclaw/issues](https://github.com/openclaw/openclaw/issues)
- **ClawHub** (Skills Registry): [clawhub.com](https://clawhub.com)

---

## 🏆 Sponsors

| OpenAI | Vercel | Blacksmith | Convex |
|--------|--------|------------|--------|
| [![OpenAI](docs/assets/sponsors/openai.svg)](https://openai.com/) | [![Vercel](docs/assets/sponsors/vercel.svg)](https://vercel.com/) | [![Blacksmith](docs/assets/sponsors/blacksmith.svg)](https://blacksmith.sh/) | [![Convex](docs/assets/sponsors/convex.svg)](https://www.convex.dev/) |

---

## 📈 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=openclaw/openclaw&type=date&legend=top-left)](https://www.star-history.com/#openclaw/openclaw&type=date&legend=top-left)

---

## 🧩 What's Built

### Core Platform
- [Gateway WS control plane](https://docs.openclaw.ai/gateway) with sessions, presence, config, cron, webhooks
- [CLI surface](https://docs.openclaw.ai/tools/agent-send): gateway, agent, send, onboarding, doctor
- [Pi agent runtime](https://docs.openclaw.ai/concepts/agent) in RPC mode with tool streaming
- [Session model](https://docs.openclaw.ai/concepts/session): main, group isolation, activation modes

### Channels
- [WhatsApp](https://docs.openclaw.ai/channels/whatsapp), [Telegram](https://docs.openclaw.ai/channels/telegram), [Slack](https://docs.openclaw.ai/channels/slack)
- [Discord](https://docs.openclaw.ai/channels/discord), [Google Chat](https://docs.openclaw.ai/channels/googlechat)
- [Signal](https://docs.openclaw.ai/channels/signal), [BlueBubbles](https://docs.openclaw.ai/channels/bluebubbles) (iMessage)
- [Microsoft Teams](https://docs.openclaw.ai/channels/msteams), [Matrix](https://docs.openclaw.ai/channels/matrix)
- And 15+ more channels...

### Apps & Nodes
- [macOS app](https://docs.openclaw.ai/platforms/macos): menu bar, voice wake, PTT, WebChat
- [iOS node](https://docs.openclaw.ai/platforms/ios): Canvas, voice trigger, camera
- [Android node](https://docs.openclaw.ai/platforms/android): Connect tab, chat sessions, voice

### Tools & Automation
- [Browser control](https://docs.openclaw.ai/tools/browser)
- [Canvas + A2UI](https://docs.openclaw.ai/platforms/mac/canvas)
- [Nodes](https://docs.openclaw.ai/nodes): camera, screen record, location
- [Cron + webhooks](https://docs.openclaw.ai/automation)
- [Skills platform](https://docs.openclaw.ai/tools/skills)

---

## 📝 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 👥 Authors

OpenClaw was built for **Molty**, a space lobster AI assistant. 🦞

by Peter Steinberger and the community.

- [openclaw.ai](https://openclaw.ai)
- [soul.md](https://soul.md)
- [@openclaw](https://x.com/openclaw)

---

## 🙏 Contributors

Thanks to all clawtributors! ❤️

<a href="https://github.com/openclaw/openclaw/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=openclaw/openclaw" />
</a>

---

*Built with ❤️ by the OpenClaw community*