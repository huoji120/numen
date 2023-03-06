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
#define DebugPrint(...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)

#include "windows.h"
#include "tools.h"
