# PixPin 本地解锁工具

[English README](README.en.md)

当前版本：**v1.0.0**（首个公开版本）

这是一个独立的 Windows C++ 工具，用于安装、检查和还原本地 `PixAuth.dll` 补丁。不依赖 Python、Qt 或额外的 C++ 运行库。

## 快速使用

1. 将 `unlock.exe` 放到 PixPin 根目录，与 `PixPin.exe`、`PixAuth.dll` 放在一起。
2. 关闭 PixPin。
3. 双击运行 `unlock.exe`。
4. 选择语言。
5. 选择安装补丁并输入 `y` 确认。
6. 按提示启动 PixPin，或稍后手动启动。

程序启动时会显示 PE 段分析、目标 RVA/文件偏移、备份校验、写入过程和 SHA-256 校验。

## 菜单

| 选项 | 功能 |
| --- | --- |
| 1 | 安装或更新本地补丁 |
| 2 | 还原原始 `PixAuth.dll` |
| 3 | 查看详细状态和哈希 |
| 4 | 启动 PixPin |
| 5 | 退出 |

安装或还原前必须关闭 PixPin。原始文件保存在 `PixAuth.dll.unlock-original.bak`，状态记录保存在 `PixAuth.dll.unlock-state.json`。

## 路径定位

无参数运行时，程序只检查 `unlock.exe` 所在目录，并要求同目录同时存在 `PixPin.exe` 和 `PixAuth.dll`。

找不到时不会猜测其他磁盘或固定路径。程序会提示将 `unlock.exe` 移动到 PixPin 根目录。自定义安装位置可以使用：

```powershell
.\unlock.exe --exe "E:\Apps\PixPin\PixPin.exe"
```

## 命令行模式

默认启动是交互菜单，也保留命令行参数：

```powershell
.\unlock.exe --status
.\unlock.exe --install --launch
.\unlock.exe --restore
.\unlock.exe --help
```

## 编译

```bat
call D:\VSBuildTools\VC\Auxiliary\Build\vcvars64.bat
cl /nologo /utf-8 /std:c++17 /O2 /EHsc /MT unlock_pixpin.cpp bcrypt.lib shell32.lib /link /SUBSYSTEM:CONSOLE /OUT:unlock.exe
```

`/MT` 会静态链接 C++ 运行库；生成文件只依赖系统组件 `bcrypt.dll` 和 `KERNEL32.dll`。

## 范围与来源说明

补丁针对当前分析版本的本地 `VipInfo::isVip()` 门禁，支持备份、校验和还原。厂商更新 `PixAuth.dll` 后，可能需要重新分析并安装。

本仓库只包含工具源码和编译产物，不包含或重新分发 PixPin、`PixAuth.dll` 或其他原厂文件。PixPin 相关名称、软件和资源归其各自所有者所有，本项目与 PixPin 开发者没有关联。
