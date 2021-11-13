#ifndef __MMLOADER_H_INCLUDED_
#define __MMLOADER_H_INCLUDED_
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MMEC_OK 0
#define MMEC_BAD_PE_FORMAT 1
#define MMEC_ALLOCATED_MEMORY_FAILED 2
#define MMEC_INVALID_RELOCATION_BASE 3
#define MMEC_IMPORT_MODULE_FAILED 4
#define MMEC_PROTECT_SECTION_FAILED 5
#define MMEC_INVALID_ENTRY_POINT 6
#define MMEC_INVALID_WIN32_ENV 0xff

typedef enum _MMHELPER_METHOD {
  MHM_BOOL_LOAD,         
  MHM_VOID_FREE,         
  MHM_FARPROC_GETPROC,   
} MMHELPER_METHOD;

typedef void **HMEMMODULE;
typedef LPVOID(__stdcall *Type_MemModuleHelper)(MMHELPER_METHOD, LPVOID, LPVOID, LPVOID);
LPVOID MemModuleHelper(_In_ MMHELPER_METHOD method, _In_ LPVOID lpArg1, _In_ LPVOID lpArg2, _In_ LPVOID lpArg3);
HMEMMODULE LoadMemModule(_In_ LPVOID lpPeModuleBuffer, _In_ BOOL bCallEntry, _Inout_ DWORD *pdwError);
FARPROC GetMemModuleProc(_In_ HMEMMODULE MemModuleHandle, _In_ LPCSTR lpName);
VOID FreeMemModule(_In_ HMEMMODULE MemModuleHandle);
#ifdef __cplusplus
}
#endif

#endif  
