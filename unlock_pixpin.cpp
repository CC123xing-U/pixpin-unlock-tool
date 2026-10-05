// Persistent local PixPin entitlement patcher.
// Build (x64 Native Tools or the bundled Build Tools command prompt):
//   cl /nologo /std:c++17 /O2 /EHsc /MT unlock_pixpin.cpp bcrypt.lib /link /SUBSYSTEM:CONSOLE /OUT:unlock.exe

#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <shellapi.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")

namespace fs = std::filesystem;

constexpr uint32_t kTargetRva = 0xEE950;
constexpr size_t kPatchSize = 3;
constexpr char kBackupSuffix[] = ".unlock-original.bak";
constexpr char kStateSuffix[] = ".unlock-state.json";
const std::array<uint8_t, kPatchSize> kPatch = {0xB0, 0x01, 0xC3};

const std::vector<uint8_t> kSignature = {
    0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x39, 0x03, 0x7F, 0x2E, 0x8B, 0x43, 0x20, 0x85, 0xC0, 0x74, 0x13, 0x83, 0xF8, 0x06,
    0x74, 0x0E, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x32, 0xC0, 0x48, 0x83, 0xC4, 0x20, 0x5B,
    0xC3, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x48, 0x39, 0x43, 0x38, 0x7F, 0x08, 0x32, 0xC0,
    0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3, 0xB0, 0x01, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3
};

struct UnlockError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct Section {
    std::string name;
    uint32_t virtualAddress = 0;
    uint32_t virtualSize = 0;
    uint32_t rawPointer = 0;
    uint32_t rawSize = 0;
    uint32_t characteristics = 0;

    bool executable() const { return (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0; }
};

struct PeImage {
    const std::vector<uint8_t>& data;
    std::vector<Section> sections;

    static PeImage parse(const std::vector<uint8_t>& bytes) {
        if (bytes.size() < sizeof(IMAGE_DOS_HEADER) ||
            reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data())->e_magic != IMAGE_DOS_SIGNATURE) {
            throw UnlockError("PixAuth.dll is not a valid PE image (missing MZ header)");
        }
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
        if (dos->e_lfanew < 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > bytes.size()) {
            throw UnlockError("PixAuth.dll has an invalid PE header offset");
        }
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(bytes.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) throw UnlockError("PixAuth.dll has an invalid PE signature");
        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) throw UnlockError("PixAuth.dll is not x64");
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) throw UnlockError("PixAuth.dll is not PE32+");
        const size_t table = static_cast<size_t>(dos->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader;
        const size_t tableBytes = static_cast<size_t>(nt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
        if (table > bytes.size() || tableBytes > bytes.size() - table) throw UnlockError("truncated PE section table");

        PeImage image{bytes, {}};
        const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(bytes.data() + table);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            const auto& s = sections[i];
            char name[9] = {};
            std::copy_n(reinterpret_cast<const char*>(s.Name), 8, name);
            image.sections.push_back({name, s.VirtualAddress, s.Misc.VirtualSize, s.PointerToRawData, s.SizeOfRawData, s.Characteristics});
        }
        return image;
    }

    size_t rvaToFileOffset(uint32_t rva, size_t size) const {
        for (const auto& s : sections) {
            const uint64_t span = std::max<uint32_t>(s.virtualSize, s.rawSize);
            if (rva >= s.virtualAddress && static_cast<uint64_t>(rva) + size <= static_cast<uint64_t>(s.virtualAddress) + span) {
                const uint64_t offset = static_cast<uint64_t>(s.rawPointer) + (rva - s.virtualAddress);
                if (offset + size <= data.size()) return static_cast<size_t>(offset);
            }
        }
        throw UnlockError("target RVA is outside file-backed PE sections");
    }

    const Section& sectionForRva(uint32_t rva) const {
        for (const auto& s : sections) {
            const uint64_t span = std::max<uint32_t>(s.virtualSize, s.rawSize);
            if (rva >= s.virtualAddress && static_cast<uint64_t>(rva) < static_cast<uint64_t>(s.virtualAddress) + span) return s;
        }
        throw UnlockError("target RVA has no PE section");
    }
};

std::string narrow(const fs::path& p) {
    std::string out;
    for (wchar_t c : p.native()) out.push_back(c < 128 ? static_cast<char>(c) : '?');
    return out;
}

std::string narrow(const std::wstring& value) {
    std::string out;
    for (wchar_t c : value) out.push_back(c < 128 ? static_cast<char>(c) : '?');
    return out;
}

bool installationFilesPresent(const fs::path& exe) {
    if (exe.empty()) return false;
    std::error_code ec;
    const bool hasExe = fs::is_regular_file(exe, ec);
    ec.clear();
    const bool hasDll = fs::is_regular_file(exe.parent_path() / L"PixAuth.dll", ec);
    return hasExe && hasDll;
}

void requireInstallation(const fs::path& exe) {
    if (!installationFilesPresent(exe)) {
        throw UnlockError("PixPin was not found beside this unlock.exe. Put unlock.exe in the PixPin directory, or pass --exe PATH");
    }
}

std::wstring winError(DWORD error = GetLastError()) {
    wchar_t* buffer = nullptr;
    const DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                   nullptr, error, 0, reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
    std::wstring result = n ? std::wstring(buffer, n) : L"unknown Windows error";
    if (buffer) LocalFree(buffer);
    while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n')) result.pop_back();
    return result;
}

void check(bool condition, const char* message) {
    if (!condition) throw UnlockError(std::string(message) + ": " + narrow(winError()));
}

std::vector<uint8_t> readFile(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw UnlockError("cannot open " + narrow(path));
    in.seekg(0, std::ios::end);
    const auto end = in.tellg();
    if (end < 0) throw UnlockError("cannot determine size of " + narrow(path));
    std::vector<uint8_t> bytes(static_cast<size_t>(end));
    in.seekg(0, std::ios::beg);
    if (!bytes.empty()) in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!in && !bytes.empty()) throw UnlockError("read failed for " + narrow(path));
    return bytes;
}

void writeFile(const fs::path& path, const std::vector<uint8_t>& bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) throw UnlockError("cannot create " + narrow(path));
    if (!bytes.empty()) out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!out) throw UnlockError("write failed for " + narrow(path));
    out.flush();
}

std::string sha256(const std::vector<uint8_t>& bytes) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0, resultSize = 0, hashSize = 0;
    std::vector<uint8_t> object;
    std::array<uint8_t, 32> digest{};
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) throw UnlockError("BCryptOpenAlgorithmProvider(SHA-256) failed");
    auto cleanup = [&]() { if (hash) BCryptDestroyHash(hash); if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0); };
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &resultSize, 0) != 0 ||
        BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashSize), sizeof(hashSize), &resultSize, 0) != 0 || hashSize != digest.size()) {
        cleanup(); throw UnlockError("BCrypt SHA-256 properties failed");
    }
    object.resize(objectSize);
    if (BCryptCreateHash(algorithm, &hash, object.data(), objectSize, nullptr, 0, 0) != 0 ||
        BCryptHashData(hash, const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0) != 0 ||
        BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) != 0) {
        cleanup(); throw UnlockError("BCrypt SHA-256 failed");
    }
    cleanup();
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (uint8_t byte : digest) out << std::setw(2) << static_cast<unsigned>(byte);
    return out.str();
}

bool signatureMatches(const uint8_t* actual) {
    for (size_t i = 0; i < kSignature.size(); ++i) {
        const bool wildcard = (i >= 11 && i <= 14) || (i >= 34 && i <= 37) || (i >= 48 && i <= 51);
        if (!wildcard && actual[i] != kSignature[i]) return false;
    }
    return true;
}

struct Target {
    size_t offset = 0;
    std::string mode;
};

Target locateTarget(const PeImage& image) {
    const size_t known = image.rvaToFileOffset(kTargetRva, kPatchSize);
    if (std::equal(kPatch.begin(), kPatch.end(), image.data.begin() + known)) return {known, "patched"};
    if (known + kSignature.size() <= image.data.size() && signatureMatches(image.data.data() + known)) {
        if (!image.sectionForRva(kTargetRva).executable()) throw UnlockError("target RVA is in a non-executable section");
        return {known, "original"};
    }
    std::vector<size_t> candidates;
    for (const auto& section : image.sections) {
        if (!section.executable() || section.rawPointer >= image.data.size() || section.rawSize < kSignature.size()) continue;
        const size_t end = std::min(image.data.size(), static_cast<size_t>(section.rawPointer) + section.rawSize);
        for (size_t offset = section.rawPointer; offset + kSignature.size() <= end; ++offset) {
            if (signatureMatches(image.data.data() + offset)) candidates.push_back(offset);
        }
    }
    if (candidates.size() == 1) return {candidates[0], "original-scan"};
    if (candidates.empty()) throw UnlockError("VipInfo::isVip signature was not found; refusing unknown build");
    throw UnlockError("multiple possible VipInfo::isVip signatures were found");
}

bool processRunning() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W entry{sizeof(entry)};
    bool found = false;
    if (Process32FirstW(snapshot, &entry)) {
        do { if (_wcsicmp(entry.szExeFile, L"PixPin.exe") == 0) { found = true; break; } } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}

fs::path sibling(const fs::path& dll, const char* suffix) { return fs::path(dll.wstring() + std::wstring(suffix, suffix + strlen(suffix))); }

void atomicReplace(const fs::path& source, const fs::path& destination) {
    if (!MoveFileExW(source.c_str(), destination.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) throw UnlockError("atomic replacement failed: " + narrow(winError()));
}

std::string jsonEscape(const std::string& value) {
    std::string escaped;
    for (unsigned char c : value) {
        if (c == '\\') escaped += "\\\\";
        else if (c == '\"') escaped += "\\\"";
        else if (c == '\n') escaped += "\\n";
        else if (c == '\r') escaped += "\\r";
        else if (c == '\t') escaped += "\\t";
        else if (c < 0x20) {
            std::ostringstream code;
            code << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<unsigned>(c);
            escaped += code.str();
        } else escaped.push_back(static_cast<char>(c));
    }
    return escaped;
}

void writeState(const fs::path& path, const fs::path& dll, size_t offset, const std::string& originalHash, const std::string& patchedHash, const std::string& mode) {
    std::ofstream out(path, std::ios::trunc);
    if (!out) throw UnlockError("cannot write state file " + narrow(path));
    out << "{\n"
        << "  \"dll\": \"" << jsonEscape(narrow(dll)) << "\",\n"
        << "  \"rva\": \"0x" << std::hex << std::uppercase << kTargetRva << "\",\n"
        << "  \"file_offset\": \"0x" << offset << "\",\n"
        << "  \"patch\": \"b0 01 c3\",\n"
        << "  \"original_sha256\": \"" << originalHash << "\",\n"
        << "  \"patched_sha256\": \"" << patchedHash << "\",\n"
        << "  \"locator\": \"" << mode << "\"\n"
        << "}\n";
}

fs::path defaultExe() {
    wchar_t buffer[MAX_PATH] = {};
    const DWORD length = GetModuleFileNameW(nullptr, buffer, MAX_PATH);
    if (length) {
        fs::path beside = fs::path(buffer).parent_path() / L"PixPin.exe";
        if (fs::is_regular_file(beside) && fs::is_regular_file(beside.parent_path() / L"PixAuth.dll")) return beside;
        // Do not guess a machine-specific installation path. The caller gets a
        // clear placement message and can use --exe for a custom location.
        return beside;
    }
    return {};
}

void launchPixPin(const fs::path& exe) {
    STARTUPINFOW startup{sizeof(startup)};
    PROCESS_INFORMATION process{};
    std::wstring command = L"\"" + exe.wstring() + L"\"";
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');
    if (!CreateProcessW(exe.c_str(), mutableCommand.data(), nullptr, nullptr, FALSE, 0, nullptr, exe.parent_path().c_str(), &startup, &process)) {
        throw UnlockError("could not launch PixPin: " + narrow(winError()));
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    std::cout << "[+] Started " << narrow(exe) << "\n";
}

int install(const fs::path& exe, bool launch) {
    requireInstallation(exe);
    const fs::path dll = exe.parent_path() / L"PixAuth.dll";
    const fs::path backup = sibling(dll, kBackupSuffix);
    const fs::path state = sibling(dll, kStateSuffix);
    std::cout << "[1/7] Installation root: " << narrow(exe.parent_path()) << "\n";
    std::cout << "[2/7] Checking PixPin process...\n";
    if (processRunning()) throw UnlockError("PixPin.exe is running; close it before installing");
    std::cout << "[3/7] Reading and parsing PixAuth.dll (" << fs::file_size(dll) << " bytes)...\n";
    const auto data = readFile(dll);
    const auto image = PeImage::parse(data);
    std::cout << "      x64 PE with " << image.sections.size() << " sections\n";
    for (const auto& section : image.sections) {
        std::cout << "      section " << section.name
                  << " RVA=0x" << std::hex << std::uppercase << section.virtualAddress
                  << " raw=0x" << section.rawPointer << "+0x" << section.rawSize
                  << (section.executable() ? " executable" : "") << std::dec << "\n";
    }
    const Target target = locateTarget(image);
    std::cout << "[4/7] Target locator: " << target.mode << ", RVA 0x" << std::hex << std::uppercase << kTargetRva << ", file offset 0x" << target.offset << std::dec << "\n";
    if (target.mode == "patched") {
        std::cout << "[+] Patch already installed.\n";
        if (launch) launchPixPin(exe);
        return 0;
    }
    const std::string originalHash = sha256(data);
    if (!fs::exists(backup)) {
        std::cout << "[5/7] Creating original backup: " << narrow(backup) << "\n";
        fs::copy_file(dll, backup);
    } else {
        std::cout << "[5/7] Existing backup found; verifying hash...\n";
        if (sha256(readFile(backup)) != originalHash) throw UnlockError("existing backup does not match the current unpatched DLL");
    }
    std::vector<uint8_t> patched = data;
    std::copy(kPatch.begin(), kPatch.end(), patched.begin() + target.offset);
    const std::string patchedHash = sha256(patched);
    const fs::path temp = dll.parent_path() / (dll.filename().wstring() + L".unlock.tmp");
    std::cout << "[6/7] Writing B0 01 C3 (mov al,1; ret) atomically...\n";
    writeFile(temp, patched);
    atomicReplace(temp, dll);
    if (sha256(readFile(dll)) != patchedHash) throw UnlockError("post-write SHA-256 verification failed");
    writeState(state, dll, target.offset, originalHash, patchedHash, target.mode);
    std::cout << "[7/7] Persistent patch installed.\n"
              << "      SHA-256: " << patchedHash << "\n"
              << "      State: " << narrow(state) << "\n";
    if (launch) launchPixPin(exe);
    return 0;
}

int showStatus(const fs::path& exe) {
    requireInstallation(exe);
    const fs::path dll = exe.parent_path() / L"PixAuth.dll";
    const fs::path backup = sibling(dll, kBackupSuffix);
    const fs::path state = sibling(dll, kStateSuffix);
    if (!fs::is_regular_file(dll)) throw UnlockError("missing " + narrow(dll));
    const auto data = readFile(dll);
    const auto image = PeImage::parse(data);
    const Target target = locateTarget(image);
    std::cout << "DLL: " << narrow(dll) << "\n"
              << "SHA-256: " << sha256(data) << "\n"
              << "Target: RVA 0x" << std::hex << std::uppercase << kTargetRva << ", file offset 0x" << target.offset << std::dec << "\n"
              << "Status: " << (target.mode == "patched" ? "INSTALLED" : "NOT INSTALLED") << "\n"
              << "Backup: " << (fs::exists(backup) ? "present" : "missing") << " (" << narrow(backup) << ")\n"
              << "State: " << (fs::exists(state) ? "present" : "missing") << " (" << narrow(state) << ")\n";
    return 0;
}

int restore(const fs::path& exe) {
    requireInstallation(exe);
    const fs::path dll = exe.parent_path() / L"PixAuth.dll";
    const fs::path backup = sibling(dll, kBackupSuffix);
    const fs::path state = sibling(dll, kStateSuffix);
    if (processRunning()) throw UnlockError("PixPin.exe is running; close it before restoring");
    if (!fs::is_regular_file(backup)) throw UnlockError("original backup was not found: " + narrow(backup));
    std::cout << "[1/4] Reading backup and calculating SHA-256...\n";
    const auto original = readFile(backup);
    const std::string originalHash = sha256(original);
    const fs::path temp = dll.parent_path() / (dll.filename().wstring() + L".restore.tmp");
    std::cout << "[2/4] Restoring PixAuth.dll atomically...\n";
    writeFile(temp, original);
    atomicReplace(temp, dll);
    std::cout << "[3/4] Verifying restored file...\n";
    if (sha256(readFile(dll)) != originalHash) throw UnlockError("restore SHA-256 verification failed");
    if (fs::exists(state)) fs::remove(state);
    std::cout << "[4/4] Restored original PixAuth.dll.\n      SHA-256: " << originalHash << "\n      Backup retained: " << narrow(backup) << "\n";
    return 0;
}

void usage() {
    std::cout << "unlock.exe - persistent local PixPin patcher\n\n"
              << "Usage:\n"
              << "  unlock.exe [--install] [--launch] [--exe PATH]\n"
              << "  unlock.exe --status [--exe PATH]\n"
              << "  unlock.exe --restore [--exe PATH]\n";
}

void waitForEnter() {
    std::cout << "\nPress Enter to continue...";
    std::string line;
    std::getline(std::cin, line);
}

bool askYesNo(const std::string& prompt) {
    for (;;) {
        std::cout << prompt << " [y/N]: ";
        std::string answer;
        if (!std::getline(std::cin, answer)) return false;
        for (char& c : answer) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (answer == "y" || answer == "yes") return true;
        if (answer.empty() || answer == "n" || answer == "no") return false;
        std::cout << "Please enter y or n.\n";
    }
}

int interactive(const fs::path& exe) {
    SetConsoleTitleW(L"PixPin Unlock Tool");
    for (;;) {
        std::cout << "\n============================================================\n"
                  << " PixPin Unlock Tool (local persistent patch)\n"
                  << "============================================================\n"
                  << "Expected PixPin: " << (exe.empty() ? "(unknown)" : narrow(exe)) << "\n\n"
                  << "Current status:\n";
        if (!installationFilesPresent(exe)) {
            std::cout << "  [!] PixPin was not found beside this unlock.exe.\n"
                      << "      Put unlock.exe in the PixPin directory, then run it again.\n"
                      << "      For a custom location, use: unlock.exe --exe PATH\n";
        } else {
            try {
                showStatus(exe);
            } catch (const std::exception& error) {
                std::cout << "  Status unavailable: " << error.what() << "\n";
            }
        }
        std::cout << "\nChoose an action:\n"
                  << "  1. Install / update local unlock patch\n"
                  << "  2. Restore the original PixAuth.dll\n"
                  << "  3. Show detailed status\n"
                  << "  4. Launch PixPin\n"
                  << "  5. Exit\n"
                  << "\nSelection: ";
        std::string choice;
        if (!std::getline(std::cin, choice)) return 0;
        if (choice == "5" || choice == "q" || choice == "Q") return 0;

        try {
            if (choice == "1") {
                if (askYesNo("Install the local patch now?")) {
                    install(exe, false);
                    if (askYesNo("Launch PixPin now?")) launchPixPin(exe);
                } else {
                    std::cout << "No changes were made.\n";
                }
                waitForEnter();
            } else if (choice == "2") {
                if (askYesNo("Restore the original DLL?")) restore(exe);
                else std::cout << "No changes were made.\n";
                waitForEnter();
            } else if (choice == "3") {
                showStatus(exe);
                waitForEnter();
            } else if (choice == "4") {
                requireInstallation(exe);
                if (processRunning()) std::cout << "PixPin is already running.\n";
                else launchPixPin(exe);
                waitForEnter();
            } else {
                std::cout << "Unknown selection. Choose 1, 2, 3, 4, or 5.\n";
                waitForEnter();
            }
        } catch (const std::exception& error) {
            std::cout << "[!] " << error.what() << "\n";
            waitForEnter();
        }
    }
}

int wmain(int argc, wchar_t** argv) {
    try {
        fs::path exe = defaultExe();
        enum class Action { Install, Status, Restore } action = Action::Install;
        bool launch = false;
        for (int i = 1; i < argc; ++i) {
            const std::wstring arg = argv[i];
            if (arg == L"--install") action = Action::Install;
            else if (arg == L"--status") action = Action::Status;
            else if (arg == L"--restore") action = Action::Restore;
            else if (arg == L"--launch") launch = true;
            else if (arg == L"--exe" && i + 1 < argc) exe = argv[++i];
            else if (arg == L"--help" || arg == L"-h") { usage(); return 0; }
            else throw UnlockError("unknown argument: " + narrow(arg));
        }
        if (argc == 1) return interactive(exe);
        std::cout << "PixPin unlock tool (local persistent patch)\n"
                  << "Executable: " << (exe.empty() ? "(not detected)" : narrow(exe)) << "\n";
        if (action == Action::Status) return showStatus(exe);
        if (action == Action::Restore) return restore(exe);
        return install(exe, launch);
    } catch (const UnlockError& error) {
        std::cerr << "[!] " << error.what() << "\n";
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "[!] " << error.what() << "\n";
        return 3;
    }
}
