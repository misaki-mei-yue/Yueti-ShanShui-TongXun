# 月啼山水通讯 · Yueti ShanShui TongXun

水墨山水风格的端到端加密通讯软件（Windows / Android / 网页 + 自托管服务器）。
An ink-landscape styled end-to-end encrypted messenger (Windows / Android / Web + self-hosted server).

当前版本 / Current version: **1.4.1** — 安装包见 / binaries: [Releases](https://github.com/misaki-mei-yue/Yueti-ShanShui-TongXun/releases/tag/v1.4.1)

## 目录 / Layout

| 路径 Path | 内容 Contents |
|---|---|
| `server/` | 1.4.1 服务器源码（Node.js，`node server/main.js`）/ server source |
| `public/` | 1.4.1 网页客户端源码（Windows/Android 客户端共用界面）/ web client source |
| `deploy/deploy-shanshui-opt.sh` | Linux 安装和升级脚本 / install & upgrade script |
| `docs/` | 1.4.1 发布说明、升级说明 / release & upgrade notes |
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
