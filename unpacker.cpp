// Dev : Hamid.Memar

// WinAPI Functions
#include <Windows.h>
#include <winnt.h>
EXTERN_C IMAGE_DOS_HEADER __ImageBase;

// Resolvers Functions
EXTERN_C void crt_init();
EXTERN_C void k32_init();

// Encryption Library
extern "C"
{
	#include "aes.h"
}

// Compression Library
#include "lzma2\fast-lzma2.h"

// PE Loader Library
#include "mmLoader.h"

// Merge Data With Code
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/merge:.data=.text")

// Cross Section Value
EXTERN_C static volatile uintptr_t		moduleImageBase = 0xBCEAEFBA;
EXTERN_C static volatile FARPROC		functionForwardingPtr = (FARPROC)0xCAFEBABE;

// External Functions
EXTERN_C BOOL CallModuleEntry(void* pMemModule_d, DWORD dwReason);

// Multi-Accessing Values
HMEMMODULE pe_module = 0;

#pragma section(".text")
__declspec(allocate(".text")) volatile const unsigned char key[32] = {
	0xE4, 0xC9, 0x9D, 0x5C, 0x64, 0x45, 0x76, 0x20, 0x35, 0x2D, 0x33,
	0xA8, 0x31, 0xE3, 0xC3, 0x02, 0xDB, 0x32, 0xE8, 0xF8, 0x2A, 0x8B,
	0x90, 0x2B, 0xBB, 0xE8, 0x6B, 0x56, 0x2A, 0xB0, 0xDA, 0x7A
};

#pragma section(".text")
__declspec(allocate(".text")) volatile const unsigned char iv[16] = {
	0xC7, 0x07, 0x32, 0x6C, 0x0C, 0x7A, 0x57, 0xF4, 0x96, 0x86, 0x69,
	0xEC, 0x2B, 0x31, 0x26, 0x1D
};

// Entrypoint (EXE/DLL)
BOOL func_unpack(void*, int reason, void*)
{
	// Releasing DLL PE Module
	if (reason == DLL_PROCESS_DETACH)
	{
		CallModuleEntry(pe_module, DLL_PROCESS_DETACH); FreeMemModule(pe_module); return TRUE;
	};

	// Handling DLL Thread Events
	if (reason == DLL_THREAD_ATTACH) return CallModuleEntry(pe_module, DLL_THREAD_ATTACH);
	if (reason == DLL_THREAD_DETACH) return CallModuleEntry(pe_module, DLL_THREAD_DETACH);

	// Internal Data [ Signatures ]
	volatile PVOID data_ptr = (void*)0xAABBCCDD;
	volatile DWORD data_size = 0xEEFFAADD;
	volatile DWORD actual_data_size = 0xA0B0C0D0;
	volatile DWORD header_size = 0xF0E0D0A0;

	// Initializing Resolvers
	k32_init(); crt_init();

	// Getting BaseAddress of Module
	intptr_t imageBase = (intptr_t)&__ImageBase;
	data_ptr = (void*)((intptr_t)data_ptr + imageBase);

	// Initializing Cryptor
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, (const uint8_t*)key, (const uint8_t*)iv);

	// Casting PVOID to BYTE
	uint8_t* data_ptr_byte = (uint8_t*)data_ptr;

	// Decrypting Buffer
	AES_CBC_decrypt_buffer(&ctx, data_ptr_byte, data_size);

	// Allocating Code Buffer
	uint8_t* code_buffer = (uint8_t*)malloc(actual_data_size);

	// Decompressing Buffer
	FL2_decompress(code_buffer, actual_data_size, &data_ptr_byte[16], data_size - 32);
	memset(data_ptr, 0, data_size);

	// Loading PE Module
	DWORD pe_loader_result = 0;
	pe_module = LoadMemModule(code_buffer, false, &pe_loader_result);

	// Set Image Base
	moduleImageBase = (uintptr_t)*pe_module;
	functionForwardingPtr = 0;

	// Call Entrypoint
	return CallModuleEntry(pe_module, DLL_PROCESS_ATTACH);
}