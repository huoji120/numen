#pragma once
#include "head.h"
typedef enum _winver {
    WINVER_7 = 0x0610,
    WINVER_7_SP1 = 0x0611,
    WINVER_8 = 0x0620,
    WINVER_81 = 0x0630,
    WINVER_10 = 0x0A00
};
enum class _simple_system_version {
    kUnk,
    kWin7,
    kWin8,
    kWin8_1,
    kWin10_1507,
    kWin10_1511,
    kWin10_1607,
    kWin10_1703,
    kWin10_1709,
    kWin10_1803,
    kWin10_1809,
    kWin10_1903,
    kWin10_1909,
    kWin10_2004,
    kWin10_20H2,
    kWin10_21H1,
    kWin10_Server_2022,
    kWin11_21H2,
    kWin10_21H2,
    kWin11_22H2,
    kWin10_22H2,
};
struct _driver_info {
    uintptr_t base;
    size_t size;
    char name[256];
};
extern "C" POBJECT_TYPE *IoDriverObjectType;
extern "C" {

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
                         OUT PVOID SystemInformation,
                         IN ULONG SystemInformationLength,
                         OUT PULONG ReturnLength OPTIONAL);
NTSTATUS ObReferenceObjectByName(PUNICODE_STRING objectName, ULONG attributes,
                                 PACCESS_STATE accessState,
                                 ACCESS_MASK desiredAccess,
                                 POBJECT_TYPE objectType,
                                 KPROCESSOR_MODE accessMode, PVOID parseContext,
                                 PVOID *object);
}
namespace tools {
auto find_pattern_image(void *base, const char *pattern, const char *mask)
    -> void *;
auto get_driver_base_by_name(char *driver_name) -> uintptr_t;
auto get_simple_system_version() -> _simple_system_version;
auto get_driver_info_by_address(uintptr_t address) -> _driver_info *;
auto get_driver_info_by_name(char *driver_name) -> _driver_info *;
}  // namespace tools
