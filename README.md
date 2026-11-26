# 月啼山水通讯 · Yueti ShanShui TongXun

水墨山水风格的端到端加密通讯软件（Windows / Android / 网页 + 自托管服务器）。
An ink-landscape styled end-to-end encrypted messenger (Windows / Android / Web + self-hosted server).

**1.5.4** · [Windows、Android 与 Linux 服务器下载 / Downloads](https://github.com/misaki-mei-yue/Yueti-ShanShui-TongXun/releases/tag/v1.5.4) · [升级说明 / Upgrade guide (中文)](docs/UPGRADE-zh.txt)

同一联系人的私聊和归档现在可以在一个窗口阅读。可以在输入框旁召唤山岚，也可以在会话详情查看授权和暂停调用。本版还修复了安卓打开长归档时多条消息显示解密错误的问题。

## 目录 / Layout

| 路径 Path | 内容 Contents |
|---|---|
| `server/` | 服务器源码（Node.js，`node server/main.js`）/ server source |
| `public/` | 网页客户端源码（Windows/Android 客户端共用界面）/ web client source |
| `deploy/deploy-shanshui-opt.sh` | Linux 安装和升级脚本 / install & upgrade script |
| `docs/` | 发布说明、升级说明 / release & upgrade notes |
| [handoff.md](handoff.md) | 当前进度、构建与部署、已知问题 / maintainer handoff |
| `legacy/1.1.x/` | 早期 1.1.x Electron 客户端源码 / early 1.1.x Electron client |

运行 / Run: Node.js ≥ 24，`npm start`（数据目录、端口等见 `deploy/` 脚本与 `docs/`）。

## 许可证 / License

**AGPL-3.0 + 商业授权双协议 / Dual-licensed: AGPL-3.0 + Commercial.**

- 默认按 [AGPL-3.0](LICENSE) 开源：修改后分发或通过网络提供服务，必须公开完整源码。
  Open source under [AGPL-3.0](LICENSE): if you distribute it or provide it as a network service, you must publish the complete source including modifications.
- **闭源商用必须先取得版权持有人 misaki-mei-yue 的书面商业授权**，详见 [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md)。
  **Closed-source commercial use requires a written commercial license from misaki-mei-yue.** See [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).
- 申请商业授权请提 [Issue](https://github.com/misaki-mei-yue/Yueti-ShanShui-TongXun/issues) 或通过 GitHub 主页 [@misaki-mei-yue](https://github.com/misaki-mei-yue) 联系。

Copyright © 2026 misaki-mei-yue. 第三方组件许可见 / Third-party notices: [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt).
