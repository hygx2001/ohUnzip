# OhUnzip

基于 **Rust + GPUI Kit (`gpui-kit 0.11`)** 构建的轻量级智能解压小工具，调用系统自带 **7-Zip**，专门解决日常与网盘资源场景中的**正常压缩包、改后缀伪装、隐写图种/视频种、多层嵌套套娃与密码本自动匹配**。

## 核心特性

- **全格式常规解压**：支持 `ZIP / 7Z / RAR / TAR / GZ / BZ2 / XZ / ZSTD / CAB / ISO / WIM` 等 7-Zip 支持的常见格式与标准分卷（`.001`、`.part1.rar`、`.z01`+`.zip`）。
- **改后缀 / 无后缀识别**：基于文件头魔数与 CRC 校验识别伪装成 `.mp4 / .jpg / .txt` 或删除后缀的压缩包，并自动还原**改后缀分卷**（如 `xxx.7z.001.mp4`、`xxx.part01.rar删`，通过同目录硬链接零额外空间还原）。
- **隐写 / 图种 / 视频种扫描**：支持 O(1) 尾部 ZIP EOCD 校验以及分块扫描 JPEG / PNG / GIF / WEBP / MP4 / MKV / PDF 等载体中嵌入的 ZIP / 7Z / RAR，自动剥离载荷解压而不破坏原载体文件。
- **智能套娃递归 & 软件组件保护**：
  - 自动递归解开多层嵌套压缩包，支持清理中间层压缩包与防压缩炸弹保护；
  - 自动保护 `.jar / .whl / .lib / .a / .apk / .vsix / .nupkg / Office 文档` 等正常组件，且对已解出的多文件软件/项目目录自动停止递归，避免拆坏程序包。
- **明文密码本管理**：
  - 独立页面明文展示，支持回车添加与输入即筛选、上下调序、按命中次数排序、一键复制与带确认清空；
  - **多格式导入（文本处理弹窗 + 实时预览）**：支持 TXT / JSON / CSV / TSV / 网盘文案自动解析，支持自定义分隔符与重复项预览；
  - **多格式导出**：支持导出 TXT / JSON / CSV 或一键复制全部；
  - 解压时自动从**文件名、压缩包注释（Comment）及同目录密码文本**提取候选密码优先尝试，失败时支持卡片内回车补输密码并自动保存。
- **简洁交互与系统集成**：
  - 紧凑窗口 + 固定拖拽区 + 可收缩抽屉式日志面板（记住上次展开/收起状态，窗口高度自适应）；
  - 实时解压进度条、并发队列控制（最多 3 个并行）、随时取消任务、ZIP 乱码一键按 GBK / Shift-JIS 重解（自动回收旧乱码目录）；
  - 顶栏窗口置顶（图钉）、8 套浅色/深色主题色下拉切换、`Esc` 快速返回主页；
  - 一键注册 Windows 资源管理器右键级联菜单（`OhUnzip → 解压到当前目录 / 解压到指定目录`），内置单实例 IPC 合并右键多选任务；
  - 可选解压完成后移入回收站、完成系统通知、以及绿色便携模式（在程序同目录放置 `config.json` 即可启用）。

## 环境要求

- **Rust**：1.90+（Edition 2024）
- **7-Zip**：系统安装 [7-Zip](https://www.7-zip.org/) 或 NanaZip（启动时自动从 Windows 注册表、`PATH` 和常见安装目录检测，也可在设置页手动指定 `7z.exe` 位置）

## 构建与运行

```powershell
# 开发模式运行
cargo run

# 运行单元测试
cargo test

# 构建精简发布版（已启用 thin LTO 与 strip，无控制台窗口）
cargo build --release
```

发布版可执行文件位于 `target\release\oh-unzip.exe`。

## 配置文件与便携模式

- **默认位置**：`%APPDATA%\OhUnzip\config.json`
- **便携模式**：在 `oh-unzip.exe` 同级目录新建一个空的 `config.json`（内容为 `{}`），程序会自动优先读写该文件并在设置页底部显示「便携模式」。

## 目录结构

```text
assets/
  icon.svg / icon.png / icon.ico   # 程序图标（由 build.rs 嵌入 Windows 资源）
build.rs                           # 纯 Rust .ico -> .res 编译与链接脚本
src/
  main.rs                          # 入口、CLI 参数解析、单实例选举与窗口初始化
  config.rs                        # 配置持久化、便携模式、密码多格式导入导出解析
  context_menu.rs                  # Windows HKCU 右键级联菜单注册与卸载
  detector.rs                      # 魔数识别、改后缀分卷、图种隐写扫描、组件保护与密码提示提取
  extractor.rs                     # 7z 流式解压（进度/取消/编码重解）、硬链接分卷还原、智能套娃递归
  notify.rs                        # Windows Toast 系统通知与 AUMID/图标注册
  seven_zip.rs                     # 7-Zip 自动检测与版本探测
  single_instance.rs               # 本地 TCP 单实例选举与右键多选消息转发
  theme.rs                         # 8 套浅色/深色主题配色预设
  trash.rs                         # Win32 SHFileOperationW 安全移入回收站
  ui/
    mod.rs                         # OhUnzipApp 状态、并发队列、顶栏与主题下拉菜单
    main_page.rs                   # 主页：固定拖拽区 + 可收缩日志抽屉 + 任务卡片
    passwords_page.rs              # 密码管理页与导出弹窗
    import_dialog.rs               # 密码导入文本处理弹窗（自定义分隔符 + 实时预览）
    settings_page.rs               # 设置页
```

## 开源协议

本项目基于 [MIT License](LICENSE) 开源。
