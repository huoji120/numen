#include "head.h"
auto Init() -> bool {
    const auto system_version = tools::get_simple_system_version();
    switch (system_version) {
        case _simple_system_version::kWin7:
            /* code */
            break;

        default:
            break;
    }
    const auto flt_mgr_base = tools::get_driver_base_by_name("fltMgr.sys");
    do {
        if (flt_mgr_base == 0) {
            DebugPrint("fltMgr.sys not found");
            break;
        }
    } while (false);
    return true;
}
auto DriverUnload(PDRIVER_OBJECT DriverObject) -> NTSTATUS {
    DebugPrint("Driver Unload");
    return STATUS_SUCCESS;
}
extern "C" auto DriverEntry(PDRIVER_OBJECT DriverObject,
                            PUNICODE_STRING RegistryPath) -> NTSTATUS {
    DriverObject->DriverUnload = (PDRIVER_UNLOAD)DriverUnload;
    DebugPrint("numen kernel rootkit pathcer by huoji 2023.3.6 \n");
    return STATUS_SUCCESS;
}
