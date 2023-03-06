#include "tools.h"
namespace tools {
auto check_mask(const char *base, const char *pattern, const char *mask)
    -> bool {
    for (; *mask; ++base, ++pattern, ++mask) {
        if ('x' == *mask && *base != *pattern) {
            return false;
        }
    }

    return true;
}
auto find_pattern(void *base, int length, const char *pattern, const char *mask)
    -> void * {
    length -= static_cast<int>(strlen(mask));
    for (auto i = 0; i <= length; ++i) {
        const auto *data = static_cast<char *>(base);
        const auto *address = &data[i];
        if (check_mask(address, pattern, mask)) return PVOID(address);
    }

    return nullptr;
}
auto find_pattern_image(void *base, const char *pattern, const char *mask)
    -> void * {
    void *match = nullptr;

    auto *headers = reinterpret_cast<PIMAGE_NT_HEADERS>(
        static_cast<char *>(base) +
        static_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew);
    auto *sections = IMAGE_FIRST_SECTION(headers);

    for (auto i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
        auto *section = &sections[i];
        if ('EGAP' == *reinterpret_cast<int *>(section->Name) ||
            memcmp(section->Name, ".text", 5) == 0) {
            match = find_pattern(
                static_cast<char *>(base) + section->VirtualAddress,
                section->Misc.VirtualSize, pattern, mask);
            if (match) break;
        }
    }
    return match;
}
auto get_simple_system_version() -> _simple_system_version {
    static _simple_system_version systemVer = _simple_system_version::kUnk;
    if (systemVer == _simple_system_version::kUnk) {
        RTL_OSVERSIONINFOEXW verInfo = {0};
        verInfo.dwOSVersionInfoSize = sizeof(verInfo);
        const auto ntStatus = RtlGetVersion((PRTL_OSVERSIONINFOW)&verInfo);
        NT_ASSERT(NT_SUCCESS(ntStatus));
        ULONG verShort = (verInfo.dwMajorVersion << 8) |
                         (verInfo.dwMinorVersion << 4) |
                         verInfo.wServicePackMajor;
        switch (verShort) {
            case _winver::WINVER_7:
            case _winver::WINVER_7_SP1:
                systemVer = _simple_system_version::kWin7;
                break;
            case _winver::WINVER_8:
                systemVer = _simple_system_version::kWin8;
                break;
            case _winver::WINVER_81:
                systemVer = _simple_system_version::kWin8_1;
                break;
            case _winver::WINVER_10: {
                switch (verInfo.dwBuildNumber) {
                    case 10240:
                        systemVer = _simple_system_version::kWin10_1507;
                        break;
                    case 10586:
                        systemVer = _simple_system_version::kWin10_1511;
                        break;
                    case 14393:
                        systemVer = _simple_system_version::kWin10_1607;
                        break;
                    case 15063:
                        systemVer = _simple_system_version::kWin10_1703;
                        break;
                    case 16299:
                        systemVer = _simple_system_version::kWin10_1709;
                        break;
                    case 17134:
                        systemVer = _simple_system_version::kWin10_1803;
                        break;
                    case 17763:
                        systemVer = _simple_system_version::kWin10_1809;
                        break;
                    case 18362:
                        systemVer = _simple_system_version::kWin10_1903;
                        break;
                    case 18363:
                        systemVer = _simple_system_version::kWin10_1909;
                        break;
                    case 19041:
                        systemVer = _simple_system_version::kWin10_2004;
                        break;
                    case 19042:
                        systemVer = _simple_system_version::kWin10_20H2;
                        break;
                    case 19043:
                        systemVer = _simple_system_version::kWin10_21H1;
                        break;
                    case 20348:
                        systemVer = _simple_system_version::kWin10_Server_2022;
                        break;
                    case 22000:
                        systemVer = _simple_system_version::kWin11_21H2;
                        break;
                    case 19044:
                        systemVer = _simple_system_version::kWin10_21H2;
                        break;
                    case 22621:
                        systemVer = _simple_system_version::kWin11_22H2;
                        break;
                    case 19045:
                        systemVer = _simple_system_version::kWin10_22H2;
                        break;
                    default:
                        break;
                }
            } break;
            default: {
                NT_ASSERT(false);
                break;
            }
        }
    }
    NT_ASSERT(systemVer != _simple_system_version::kUnk);
    return systemVer;
}
auto get_driver_info_by_name(char *driver_name) -> _driver_info * {
    size_t bytes = 0;
    uintptr_t found_base = 0;
    auto ntStatus = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes,
                                             (PULONG)&bytes);
    _driver_info *driver_info = nullptr;
    if (ntStatus == STATUS_INFO_LENGTH_MISMATCH) {
        const auto sysModules = static_cast<PRTL_PROCESS_MODULES>(
            ExAllocatePoolWithTag(NonPagedPoolNx, bytes, huoji_tag));
        if (sysModules) {
            memset(sysModules, 0, bytes);
            ntStatus = ZwQuerySystemInformation(
                SystemModuleInformation, sysModules, bytes, (PULONG)&bytes);
            if (NT_SUCCESS(ntStatus)) {
                auto iter = sysModules->Modules;
                for (size_t i = 0; i < sysModules->NumberOfModules; i++) {
                    const auto lower_name =
                        _strlwr((char *)iter[i].FullPathName);
                    if (strstr((char *)lower_name, (char *)driver_name) !=
                        NULL) {
                        driver_info = reinterpret_cast<_driver_info *>(
                            ExAllocatePoolWithTag(NonPagedPoolNx,
                                                  sizeof(_driver_info),
                                                  huoji_tag));
                        if (driver_info) {
                            memset(driver_info, 0, sizeof(_driver_info));
                            driver_info->base =
                                reinterpret_cast<uintptr_t>(iter[i].ImageBase);
                            driver_info->size = iter[i].ImageSize;
                            memcpy(driver_info->name, iter[i].FullPathName,
                                   255);
                        }
                        break;
                    }
                }
            }
            ExFreePoolWithTag(sysModules, huoji_tag);
        }
    }
    return driver_info;
}
auto get_driver_info_by_address(uintptr_t address) -> _driver_info * {
    size_t bytes = 0;
    uintptr_t found_base = 0;
    auto ntStatus = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes,
                                             (PULONG)&bytes);
    _driver_info *driver_info = nullptr;
    if (ntStatus == STATUS_INFO_LENGTH_MISMATCH) {
        const auto sysModules = static_cast<PRTL_PROCESS_MODULES>(
            ExAllocatePoolWithTag(NonPagedPoolNx, bytes, huoji_tag));
        if (sysModules) {
            memset(sysModules, 0, bytes);
            ntStatus = ZwQuerySystemInformation(
                SystemModuleInformation, sysModules, bytes, (PULONG)&bytes);
            if (NT_SUCCESS(ntStatus)) {
                auto iter = sysModules->Modules;
                for (size_t i = 0; i < sysModules->NumberOfModules; i++) {
                    if (address >=
                            reinterpret_cast<uintptr_t>(iter[i].ImageBase) &&
                        address <=
                            reinterpret_cast<uintptr_t>(iter[i].ImageBase) +
                                iter[i].ImageSize) {
                        driver_info = reinterpret_cast<_driver_info *>(
                            ExAllocatePoolWithTag(NonPagedPoolNx,
                                                  sizeof(_driver_info),
                                                  huoji_tag));
                        if (driver_info) {
                            memset(driver_info, 0, sizeof(_driver_info));
                            driver_info->base =
                                reinterpret_cast<uintptr_t>(iter[i].ImageBase);
                            driver_info->size = iter[i].ImageSize;
                            memcpy(driver_info->name, iter[i].FullPathName,
                                   255);
                        }
                        break;
                    }
                }
            }
            ExFreePoolWithTag(sysModules, huoji_tag);
        }
    }
    return driver_info;
};
auto get_driver_base_by_name(char *driver_name) -> uintptr_t {
    size_t bytes = 0;
    uintptr_t found_base = 0;
    auto ntStatus = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes,
                                             (PULONG)&bytes);
    if (ntStatus == STATUS_INFO_LENGTH_MISMATCH) {
        const auto sysModules = static_cast<PRTL_PROCESS_MODULES>(
            ExAllocatePoolWithTag(NonPagedPoolNx, bytes, huoji_tag));
        if (sysModules) {
            memset(sysModules, 0, bytes);
            ntStatus = ZwQuerySystemInformation(
                SystemModuleInformation, sysModules, bytes, (PULONG)&bytes);
            if (NT_SUCCESS(ntStatus)) {
                auto iter = sysModules->Modules;
                for (size_t i = 0; i < sysModules->NumberOfModules; i++) {
                    const auto lower_name =
                        _strlwr((char *)iter[i].FullPathName);
                    if (strstr((char *)lower_name, (char *)driver_name) !=
                        NULL) {
                        found_base = (uintptr_t)iter[i].ImageBase;
                        break;
                    }
                }
            }
            ExFreePoolWithTag(sysModules, huoji_tag);
        }
    }
    return found_base;
}
}  // namespace tools
