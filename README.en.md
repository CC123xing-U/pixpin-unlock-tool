# PixPin Unlock Tool

[简体中文 README](README.md)

`unlock.exe` is a standalone Windows C++ utility for installing, checking, and restoring the local `PixAuth.dll` patch. It does not require Python, Qt, or a separate C++ runtime installation.

## Quick Start

1. Place `unlock.exe` beside `PixPin.exe` and `PixAuth.dll` in the PixPin installation directory.
2. Close PixPin.
3. Double-click `unlock.exe`.
4. Select Language.
5. Select the install action and confirm with `y`.
6. Launch PixPin when prompted, or launch it later.

The tool prints PE section analysis, target RVA/file offset, backup verification, write progress, and SHA-256 verification.

## Menu

| Choice | Action |
| --- | --- |
| 1 | Install or update the local patch |
| 2 | Restore the original `PixAuth.dll` |
| 3 | Show detailed status and hashes |
| 4 | Launch PixPin |
| 5 | Exit |

PixPin must be closed before installation or restoration. The original file is kept at `PixAuth.dll.unlock-original.bak`; state metadata is stored in `PixAuth.dll.unlock-state.json`.

## Path Detection

When started without arguments, the program checks only the directory containing `unlock.exe`. Both `PixPin.exe` and `PixAuth.dll` must be present there.

The tool does not guess another drive or machine-specific path. If detection fails, it tells the user to move `unlock.exe` into the PixPin directory. For a custom installation, use:

```powershell
.\unlock.exe --exe "E:\Apps\PixPin\PixPin.exe"
```

## Command-Line Mode

The interactive menu is the default, and command-line operations remain available:

```powershell
.\unlock.exe --status
.\unlock.exe --install --launch
.\unlock.exe --restore
.\unlock.exe --help
```

## Build

```bat
call D:\VSBuildTools\VC\Auxiliary\Build\vcvars64.bat
cl /nologo /utf-8 /std:c++17 /O2 /EHsc /MT unlock_pixpin.cpp bcrypt.lib shell32.lib /link /SUBSYSTEM:CONSOLE /OUT:unlock.exe
```

The `/MT` build embeds the C++ runtime. The resulting executable only imports system components (`bcrypt.dll` and `KERNEL32.dll`).

## Scope and Provenance

The patch targets the local `VipInfo::isVip()` gate in the currently analyzed build and includes backup, validation, and restore checks. A vendor update replacing `PixAuth.dll` may require a new analysis.

This repository contains only the utility source and compiled executable. It does not include or redistribute PixPin, `PixAuth.dll`, or other vendor files. PixPin and related names, software, and assets remain the property of their respective owners; this project is not affiliated with the PixPin developers.
