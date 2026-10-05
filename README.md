# PixPin Unlock Tool

`unlock.exe` is a standalone Windows C++ utility for applying and removing the local `PixAuth.dll` patch used by this project. It does not require Python, Qt, or a separate runtime installation. The interactive menu supports Simplified Chinese and English.

## Quick Start

1. Place `unlock.exe` in the PixPin installation directory, next to `PixPin.exe` and `PixAuth.dll`.
2. Close PixPin.
3. Double-click `unlock.exe`.
4. Select `1. 简体中文` or `2. English`.
5. Select the install action and confirm with `y`.
6. Launch PixPin when prompted, or launch it normally later.

The tool displays its current status when it starts. It also prints the PE sections it inspected, the target RVA/file offset, backup verification, write operation, and SHA-256 verification.

## Menu Actions

| Choice | Action |
| --- | --- |
| 1 | Install or update the persistent local patch |
| 2 | Restore the original `PixAuth.dll` |
| 3 | Show detailed status and hashes |
| 4 | Launch PixPin |
| 5 | Exit |

PixPin must be closed before installing or restoring the DLL. The original file is kept at `PixAuth.dll.unlock-original.bak`. Installation metadata is stored in `PixAuth.dll.unlock-state.json`.

## Path Detection

When started without arguments, the program resolves its own executable path with Windows `GetModuleFileNameW` and checks that directory first. If both `PixPin.exe` and `PixAuth.dll` are beside `unlock.exe`, that installation is selected.

If the files are not found there, the program does not guess another machine-specific path. The menu reports that automatic detection failed and tells the user to place the tool beside PixPin or provide an explicit path.

For a non-default installation, use:

```powershell
.\unlock.exe --exe "E:\Apps\PixPin\PixPin.exe"
```

## Command-Line Mode

The interactive menu is the default. The original command-line operations remain available:

```powershell
.\unlock.exe --status
.\unlock.exe --install --launch
.\unlock.exe --restore
.\unlock.exe --help
```

## Build

Open an x64 Native Tools command prompt for Visual Studio 2022, or use the installed Build Tools environment:

```bat
call D:\VSBuildTools\VC\Auxiliary\Build\vcvars64.bat
cl /nologo /utf-8 /std:c++17 /O2 /EHsc /MT unlock_pixpin.cpp bcrypt.lib shell32.lib /link /SUBSYSTEM:CONSOLE /OUT:unlock.exe
```

The `/MT` build embeds the C++ runtime. The resulting executable only imports system components (`bcrypt.dll` and `KERNEL32.dll`).

## Scope

The patch changes the local `VipInfo::isVip()` gate in the currently analyzed PixPin build. It is reversible and guarded by PE format, x64, executable-section, signature, backup, and post-write hash checks. A vendor update that replaces `PixAuth.dll` may require running the installer again after reviewing the new build.

The account page and cloud subscription data are server-backed presentation/data. This utility operates on the local DLL and does not modify an online account.

## Provenance

This repository contains the original utility source and its compiled executable. It does not include or redistribute PixPin or `PixAuth.dll`. PixPin and related names, software, and assets remain the property of their respective owners; this project is not affiliated with the PixPin developers.
