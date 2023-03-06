#pragma once
#include <intrin.h>
#include <ntifs.h>
#include <ntddk.h>
#include <stdlib.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <ifdef.h>
#define huoji_tag 'huoJ'
// #define _llvm 0
#ifdef DEBUG
#define DebugPrint(...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)
#else
#define DebugPrint(...)
#endif  // DEBUG

#include "windows.h"
#include "tools.h"
