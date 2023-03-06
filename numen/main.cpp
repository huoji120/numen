#include "head.h"
auto get_attach_device(PDRIVER_OBJECT driver_object) -> PDRIVER_OBJECT {
    const auto system_device = driver_object->DeviceObject;

    if (MmIsAddressValid(system_device) == false) {
        return NULL;
    }

    if (system_device->AttachedDevice) {
        return MmIsAddressValid(system_device->AttachedDevice) == false
                   ? NULL
                   : system_device->AttachedDevice->DriverObject;
    } else {
        return driver_object;
    }
}
auto unhook_ntfs_dispatch_fn(uintptr_t fltmgr_fltpcreate_addr,
                             _driver_info* flt_mgr_info) -> bool {
    PDRIVER_OBJECT ntfs_object = nullptr;
    static UNICODE_STRING ntfs_driver_name =
        RTL_CONSTANT_STRING(L"\\FileSystem\\Ntfs");
    const auto nt_status = ObReferenceObjectByName(
        &ntfs_driver_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, 0,
        *IoDriverObjectType, KernelMode, NULL, (PVOID*)&ntfs_object);
    bool status = false;
    if (NT_SUCCESS(nt_status) == false || ntfs_object == nullptr) {
        return status;
    }
    do {
        const auto attach_device = get_attach_device(ntfs_object);

        if (attach_device == nullptr) {
            break;
        }
        const auto ntfs_dispatch_fn = reinterpret_cast<uintptr_t>(
            attach_device->MajorFunction[IRP_MJ_CREATE]);
        if (ntfs_dispatch_fn == 0) {
            break;
        }
        bool is_attach_by_fltmgr =
            (ntfs_dispatch_fn >= flt_mgr_info->base &&
             ntfs_dispatch_fn < flt_mgr_info->size + flt_mgr_info->base);

        if (is_attach_by_fltmgr) {
            DebugPrint("[%s] non-detect Ntfs dispatch function hook\n",
                       __FUNCTION__);
            break;
        }
        const auto driver_info =
            tools::get_driver_info_by_address(ntfs_dispatch_fn);

        DebugPrint("[%s] detect Ntfs hook: 0x%p fltmgr_fltpcreate_addr: %p \n",
                   __FUNCTION__, ntfs_dispatch_fn, fltmgr_fltpcreate_addr);
        if (driver_info == nullptr) {
            DebugPrint("[%s][!!!] hook from manual map driver! \n",
                       __FUNCTION__);
        } else {
            DebugPrint("[%s] hook from %s \n", __FUNCTION__, driver_info->name);
        }
        attach_device->MajorFunction[IRP_MJ_CREATE] =
            reinterpret_cast<PDRIVER_DISPATCH>(fltmgr_fltpcreate_addr);
        DebugPrint("[%s] unhook Ntfs success \n", __FUNCTION__);
        if (driver_info != nullptr) {
            ExFreePoolWithTag(driver_info, huoji_tag);
        }
        status = true;
    } while (false);
    if (ntfs_object != 0) {
        ObfDereferenceObject(ntfs_object);
    }
    return status;
}
auto init() -> bool {
    bool status = false;
    _driver_info* flt_mgr_info = nullptr;
    do {
        flt_mgr_info = tools::get_driver_info_by_name("fltmgr.sys");
        if (flt_mgr_info == nullptr) {
            DebugPrint("[%s] get fltmgr.sys info failed \n", __FUNCTION__);
            break;
        }
        char* pattern = nullptr;
        char* mask = nullptr;
        const auto system_version = tools::get_simple_system_version();
        switch (system_version) {
            case _simple_system_version::kWin7:
                pattern =
                    "\xFF\xF3\x55\x57\x48\xCC\xCC\xCC\xCC\xCC\xCC\x4C\x8B\xC2"
                    "\x48\x8B\xF9\x48\xCC\xCC\xCC\xCC\xCC\xCC\x0F\xCC\xCC\xCC"
                    "\xCC\xCC\x48\xCC\xCC\xCC\xCC\xCC\xCC\x0F\xCC\xCC\xCC\xCC"
                    "\xCC\x48\x8B\xCC\xCC\x48\x85\xC0\x74\xCC\xB9\xCC\xCC\xCC"
                    "\xCC\x66\x39\x08\x0F\xCC\xCC\xCC\xCC\xCC";
                mask =
                    "xxxxx??????xxxxxxx??????x?????x??????x?????xx??xxxx?x????"
                    "xxxx?????";
                break;
            case _simple_system_version::kWin10_1703:
            case _simple_system_version::kWin10_1709:
            case _simple_system_version::kWin10_1803:
            case _simple_system_version::kWin10_1809:
                pattern =
                    "\x40\x55\x56\x57\x41\x56\x41\x57\x48\x8B\xEC\x48\xCC\xCC"
                    "\xCC\xCC\xCC\xCC\x33\xC0\x45\x32\xFF\x48";
                mask = "xxxxxxxxxxxx??????xxxxxx";
                break;
            case _simple_system_version::kWin10_1903:
            case _simple_system_version::kWin10_1909:
            case _simple_system_version::kWin10_2004:
            case _simple_system_version::kWin10_20H2:
            case _simple_system_version::kWin10_21H1:
            case _simple_system_version::kWin10_21H2:
                pattern =
                    "\x40\x55\x56\x57\x41\x56\x48\x8D\xCC\xCC\xCC\x48\xCC\xCC"
                    "\xCC\xCC\xCC\xCC\x40\x32\xF6\x4C\x8B\xF2\x33\xD2\x40\x88"
                    "\xCC\xCC\x48\xCC\xCC\xCC\xCC\xCC\xCC\x48\x8B\xF9\x48\x89"
                    "\xCC\xCC\x89\x55\xCC\x0F\xCC\xCC\xCC\xCC\xCC\x48\xCC\xCC"
                    "\xCC\xCC\xCC\xCC";
                mask =
                    "xxxxxxxx???x??????xxxxxxxxxx??x??????xxxxx??xx?x?????x????"
                    "??";
                break;
            case _simple_system_version::kWin11_21H2:
            case _simple_system_version::kWin11_22H2:
                pattern =
                    "\x40\x55\x56\x57\x41\x56\x48\x8D\xCC\xCC\xCC\x48\xCC\xCC"
                    "\xCC\xCC\xCC\xCC\x45\x32\xF6\x48\x8B\xF2\x33\xD2\x44\x88"
                    "\xCC\xCC\x48\xCC\xCC\xCC\xCC\xCC\xCC";
                mask = "xxxxxxxx???x??????xxxxxxxxxx??x??????";
                break;
            default:
                DebugPrint("[%s]non-support system \n", __FUNCTION__);
                break;
        }
        if (pattern == nullptr) {
            DebugPrint("[%s]non-support system \n", __FUNCTION__);
            break;
        }
        const auto fltmgr_fltpcreate_addr =
            reinterpret_cast<uintptr_t>(tools::find_pattern_image(
                reinterpret_cast<char*>(flt_mgr_info->base), pattern, mask));
        if (fltmgr_fltpcreate_addr == 0) {
            DebugPrint("[%s]fltmgr_fltpcreate_addr is zero \n", __FUNCTION__);
            break;
        }
        DebugPrint("[%s] fltmgr_fltpcreate_addr: 0x%llx \n", __FUNCTION__,
                   fltmgr_fltpcreate_addr);

        status = unhook_ntfs_dispatch_fn(fltmgr_fltpcreate_addr, flt_mgr_info);

    } while (false);
    if (flt_mgr_info != nullptr) {
        ExFreePoolWithTag(flt_mgr_info, huoji_tag);
    }
    return status;
}
auto DriverUnload(PDRIVER_OBJECT DriverObject) -> NTSTATUS {
    DebugPrint("Driver Unload \n");
    return STATUS_SUCCESS;
}
extern "C" auto DriverEntry(PDRIVER_OBJECT DriverObject,
                            PUNICODE_STRING RegistryPath) -> NTSTATUS {
    DriverObject->DriverUnload = (PDRIVER_UNLOAD)DriverUnload;
    DebugPrint("numen kernel rootkit patcher by huoji 2023.3.6 \n");

    return init() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
