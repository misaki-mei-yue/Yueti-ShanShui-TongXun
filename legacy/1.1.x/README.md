# 月啼山水通讯（墨境）

东方水墨美学通讯桌面应用。纯前端本地运行：启动闪屏 → 注册/登录 → 七大功能区（消息、联系人、动态、文件、艺术聊天室、智慧协作、社交游戏厅）。

## 功能概览

- **账号**：本地 `localStorage` 注册 / 登录 / 会话恢复
- **好友**：侧栏搜索账号添加；联系人含「电子宠物小月啼」本地助手
- **界面**：大版本水墨 UI + Three.js 粒子背景 + 主题切换
- **离线**：外链图片已替换为 SVG 占位，无后端亦可浏览

## 直接打开 HTML

1. 用浏览器打开 `index.html`（推荐 Chrome / Edge）
2. 等待启动画面 → 注册账号并登录
3. 刷新后若已登录会自动进入主界面

> 需联网加载 Tailwind / Font Awesome / Three.js / GSAP CDN；其余逻辑在本地。

## Electron 开发运行

```bash
cd mojing
npm install
npm start
```

## Windows 一键包

已构建的便携版（若存在）：

- `dist/Mojing-1.0.0-portable.exe` — 双击即可运行，无需安装

自行打包（在本机或本仓库）：

```bash
npm run dist
```

需要 Wine 才能在 Linux 上交叉编译 Windows 目标。若失败可试：

```bash
npm run dist:dir    # 生成未打包的 win-unpacked
npm run dist:linux  # Linux AppImage 备选
```

## 使用提示

1. 注册两个账号可互相搜索加好友
2. 联系人 →「电子宠物小月啼」可本地对话
3. 演示联系人「王羲之」可体验墨境聊天气泡
4. 侧栏退出图标可注销当前会话

## 目录

- `index.html` — 合并后的完整应用
- `main.js` — Electron 主进程
- `package.json` — 依赖与 electron-builder 配置
- `build/icon.png` — 应用图标
