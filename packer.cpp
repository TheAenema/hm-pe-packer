// Dev : Hamid.Memar

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>

using namespace std;

// Macros
#define BOOL_STR(b) b ? "true" : "false"
#define CONSOLE_COLOR_DEFAULT 	SetConsoleTextAttribute(hConsole, 0x09);
#define CONSOLE_COLOR_ERROR		SetConsoleTextAttribute(hConsole, 0x0C);
#define CONSOLE_COLOR_SUCCSESS	SetConsoleTextAttribute(hConsole, 0x0A);
#define CONSOLE_COLOR_WHITE 	SetConsoleTextAttribute(hConsole, 0x07);

// Encryption Library
extern "C"
{
	#include "aes.h"
}

// Compression Library
#include "lzma2/fast-lzma2.h"
#pragma comment(lib, "lzma2\\fast-lzma2.lib")

// PE Info Ediotr
void  HMResKit_LoadPEFile(const char* peFile);
void  HMResKit_SetFileInfo(const char* key, const char* value);
void  HMResKit_SetPEVersion(const char* peFile);
void  HMResKit_ChangeIcon(const char* iconPath);
void  HMResKit_CommitChanges(const char* sectionName);

// Unpacker Stub
#include "unpacker_stub.h"

// Configs
#define file_alignment_size			512
#define memory_alignment_size		4096

// Helpers
inline DWORD _align(DWORD size, DWORD align, DWORD addr = 0) 
{
	if (!(size % align)) return addr + size;
	return addr + (size / align + 1) * align;
}
inline DWORD _find(uint8_t* data, size_t data_size, DWORD& value)
{
	for (size_t i = 0; i < data_size; i++)
		if (memcmp(&data[i], &value, sizeof DWORD) == 0) return i;
	return -1;
}

// Machine Code
unsigned char func_forwarding_code[32] =
{
	0x51, 0x50,											// PUSH RCX, PUSH RAX
	0x48, 0x8B, 0x05,	0x00, 0x00, 0x00, 0x00,	 		// MOV RAX,QWORD PTR DS:[OFFSET]
	0xB9,				0x00, 0x00, 0x00, 0x00,			// MOV ECX,VALUE
	0x48, 0x03, 0xC1,									// ADD RAX,RCX
	0x48, 0x89, 0x05,	0x00, 0x00, 0x00, 0x00,			// MOV QWORD PTR DS:[OFFSET],RAX
	0x58, 0x59,											// POP RAX, POP RCX
	0xFF, 0x25,			0x00, 0x00, 0x00, 0x00,			// JMP QWORD PTR DS:[OFFSET]
};

// App Entrypoint
int main(int argc, char* argv[])
{
	// Setup Console 
	HANDLE  hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTitle("Custom x64 PE Packer by H.M v1.0");
	FlushConsoleInputBuffer(hConsole);
	CONSOLE_COLOR_DEFAULT;

	// Validate Arguments Count
	if (argc != 3) return EXIT_FAILURE;

	// User Inputs
	char* input_pe_file		= argv[1];
	char* output_pe_file	= argv[2];

	// Reading Input PE File
	ifstream input_pe_file_reader(argv[1], ios::binary);
	vector<uint8_t> input_pe_file_buffer(istreambuf_iterator<char>(input_pe_file_reader), {});
	
	// Parsing Input PE File
	PIMAGE_DOS_HEADER in_pe_dos_header = (PIMAGE_DOS_HEADER)input_pe_file_buffer.data();
	PIMAGE_NT_HEADERS in_pe_nt_header =  (PIMAGE_NT_HEADERS)(input_pe_file_buffer.data() + in_pe_dos_header->e_lfanew);
	
	// Validte PE Infromation
	bool isPE  = in_pe_dos_header->e_magic == IMAGE_DOS_SIGNATURE;
	bool is64  = in_pe_nt_header->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
				 in_pe_nt_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	bool isDLL = in_pe_nt_header->FileHeader.Characteristics & IMAGE_FILE_DLL;
	bool isNET = in_pe_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size != 0;

	// Log Validation Data
	printf("[Validation] Is PE File : %s\n", BOOL_STR(isPE));
	printf("[Validation] Is 64bit : %s\n", BOOL_STR(is64));
	printf("[Validation] Is DLL : %s\n", BOOL_STR(isDLL));
	printf("[Validation] Is COM or .Net : %s\n", BOOL_STR(isNET));
	
	// Validate and Apply Action
	if (!isPE)
	{
		CONSOLE_COLOR_ERROR;
		printf("[Error] Input PE file is invalid. (Signature Mismatch)\n");
		return EXIT_FAILURE;
	}
	if (!is64)
	{
		CONSOLE_COLOR_ERROR;
		printf("[Error] This packer only supports x64 PE files.\n");
		return EXIT_FAILURE;
	}
	if (isNET) 
	{
		CONSOLE_COLOR_ERROR;
		printf("[Error] This packer currently doesn't support .NET/COM assemblies.\n");
		return EXIT_FAILURE;
	}

	// <----- Packing Data ( Main Implementation ) ----->
	printf("[Information] Initializing AES Cryptor...\n");
	struct AES_ctx ctx;
	const unsigned char key[32] = {
	0xD6, 0x23, 0xB8, 0xEF, 0x62, 0x26, 0xCE, 0xC3, 0xE2, 0x4C, 0x55, 0x12,
	0x7D, 0xE8, 0x73, 0xE7, 0x83, 0x9C, 0x77, 0x6B, 0xB1, 0xA9, 0x3B, 0x57,
	0xB2, 0x5F, 0xDB, 0xEA, 0x0D, 0xB6, 0x8E, 0xA2
	};
	const unsigned char iv[16] = {
	0x18, 0x42, 0x31, 0x2D, 0xFC, 0xEF, 0xDA, 0xB6, 0xB9, 0x49, 0xF1, 0x0D,
	0x03, 0x7E, 0x7E, 0xBD
	};
	AES_init_ctx_iv(&ctx, key, iv);

	printf("[Information] Initializing Compressor...\n");
	FL2_CCtx* cctx = FL2_createCCtxMt(8);
	FL2_CCtx_setParameter(cctx, FL2_p_compressionLevel, 9);
	FL2_CCtx_setParameter(cctx, FL2_p_dictionarySize, 1024);

	vector<uint8_t> data_buffer;
	data_buffer.resize(input_pe_file_buffer.size());

	printf("[Information] Compressing Buffer...\n");
	size_t original_size = input_pe_file_buffer.size();
	size_t compressed_size = FL2_compressCCtx(cctx, data_buffer.data(), data_buffer.size(),
		   input_pe_file_buffer.data(), original_size, 9);
	data_buffer.resize(compressed_size);

	// Add Padding Before Encryption
	for (size_t i = 0; i < 16; i++) data_buffer.insert(data_buffer.begin(), 0x0);
	for (size_t i = 0; i < 16; i++) data_buffer.push_back(0x0);

	printf("[Information] Encrypting Buffer...\n");
	AES_CBC_encrypt_buffer(&ctx, data_buffer.data(), data_buffer.size());

	// Log Compression Information
	printf("[Information] Original PE Size :  %ld bytes\n", input_pe_file_buffer.size());
	printf("[Information] Packed PE Size   :  %ld bytes\n", data_buffer.size());

	// Calculate Compression Ratio
	float ratio =
		(1.0f - ((float)data_buffer.size() / (float)input_pe_file_buffer.size())) * 100.f;
	printf("[Information] Compression Ratio : %.2f%%\n", (roundf(ratio * 100.0f) * 0.01f));

	// Generating PE File, Initializing DOS + NT Headeres
	#pragma region | PE Generation |
	printf("[Information] Generating PE...\n");
	IMAGE_DOS_HEADER	dos_h;
	memset(&dos_h, NULL, sizeof IMAGE_DOS_HEADER);
	dos_h.e_magic		= IMAGE_DOS_SIGNATURE;
	dos_h.e_cblp		= 0x0090;
	dos_h.e_cp			= 0x0003;
	dos_h.e_crlc		= 0x0000;
	dos_h.e_cparhdr		= 0x0004;
	dos_h.e_minalloc	= 0x0000;
	dos_h.e_maxalloc    = 0xFFFF;
	dos_h.e_ss			= 0x0000;
	dos_h.e_sp			= 0x00B8;
	dos_h.e_csum		= 0x0000;
	dos_h.e_ip			= 0x0000;
	dos_h.e_cs			= 0x0000;
	dos_h.e_lfarlc		= 0x0040;
	dos_h.e_ovno		= 0x0000;
	dos_h.e_oemid		= 0x0000;
	dos_h.e_oeminfo		= 0x0000;
	dos_h.e_lfanew		= 0x0040;

	IMAGE_NT_HEADERS	nt_h;
	memset(&nt_h, NULL, sizeof IMAGE_NT_HEADERS);
	nt_h.Signature											= IMAGE_NT_SIGNATURE;
	nt_h.FileHeader.Machine									= IMAGE_FILE_MACHINE_AMD64;
	nt_h.FileHeader.NumberOfSections						= 2;
	nt_h.FileHeader.TimeDateStamp							= 0x00000000;
	nt_h.FileHeader.PointerToSymbolTable					= 0x0;
	nt_h.FileHeader.NumberOfSymbols							= 0x0;
	nt_h.FileHeader.SizeOfOptionalHeader					= 0x00F0;
	nt_h.FileHeader.Characteristics							= 0x0022;
	nt_h.OptionalHeader.Magic								= IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	nt_h.OptionalHeader.MajorLinkerVersion					= 1;
	nt_h.OptionalHeader.MinorLinkerVersion					= 0;
	nt_h.OptionalHeader.SizeOfCode							= 0x00000200;
	nt_h.OptionalHeader.SizeOfInitializedData				= 0x00000200;
	nt_h.OptionalHeader.SizeOfUninitializedData				= 0x0;
	nt_h.OptionalHeader.AddressOfEntryPoint					= 0x00001000;
	nt_h.OptionalHeader.BaseOfCode							= 0x00001000;
	nt_h.OptionalHeader.ImageBase							= 0x0000000140000000;
	nt_h.OptionalHeader.SectionAlignment					= memory_alignment_size;
	nt_h.OptionalHeader.FileAlignment						= file_alignment_size;
	nt_h.OptionalHeader.MajorOperatingSystemVersion			= 0x0;
	nt_h.OptionalHeader.MinorOperatingSystemVersion			= 0x0;
	nt_h.OptionalHeader.MajorImageVersion					= 0x0006;
	nt_h.OptionalHeader.MinorImageVersion					= 0x0000;
	nt_h.OptionalHeader.MajorSubsystemVersion				= 0x0006;
	nt_h.OptionalHeader.MinorSubsystemVersion				= 0x0000;
	nt_h.OptionalHeader.Win32VersionValue					= 0x0;
	nt_h.OptionalHeader.SizeOfImage							= 0x00003000;
	nt_h.OptionalHeader.SizeOfHeaders						= 0x00000200;
	nt_h.OptionalHeader.CheckSum							= 0x0000F3A6;
	nt_h.OptionalHeader.Subsystem							= IMAGE_SUBSYSTEM_WINDOWS_CUI;
	nt_h.OptionalHeader.DllCharacteristics					= 0x0120;
	nt_h.OptionalHeader.SizeOfStackReserve					= 0x0000000000100000;
	nt_h.OptionalHeader.SizeOfStackCommit					= 0x0000000000001000;
	nt_h.OptionalHeader.SizeOfHeapReserve					= 0x0000000000100000;
	nt_h.OptionalHeader.SizeOfHeapCommit					= 0x0000000000001000;
	nt_h.OptionalHeader.LoaderFlags							= 0x00000000;
	nt_h.OptionalHeader.NumberOfRvaAndSizes					= 0x00000010;

	// Initializing Section [ Code ]
	IMAGE_SECTION_HEADER	c_sec;
	memset(&c_sec, NULL, sizeof IMAGE_SECTION_HEADER);
	c_sec.Name[0] = '[';
	c_sec.Name[1] = ' ';
	c_sec.Name[2] = 'H';
	c_sec.Name[3] = '.';
	c_sec.Name[4] = 'M';
	c_sec.Name[5] = ' ';
	c_sec.Name[6] = ']';
	c_sec.Name[7] = 0x0;
	c_sec.Misc.VirtualSize									= _align(sizeof unpacker_stub, memory_alignment_size);
	c_sec.VirtualAddress									= memory_alignment_size;
	c_sec.SizeOfRawData										= sizeof unpacker_stub;
	c_sec.PointerToRawData									= file_alignment_size;
	c_sec.Characteristics									= IMAGE_SCN_MEM_EXECUTE	  |	
											  				  IMAGE_SCN_MEM_READ	  |
											  				  IMAGE_SCN_MEM_WRITE	  |
											  				  IMAGE_SCN_CNT_CODE	  ;

	// Initializing Section [ Data ]
	IMAGE_SECTION_HEADER	d_sec;
	memset(&d_sec, NULL, sizeof IMAGE_SECTION_HEADER);
	d_sec.Name[0] = '[';
	d_sec.Name[1] = ' ';
	d_sec.Name[2] = 'H';
	d_sec.Name[3] = '.';
	d_sec.Name[4] = 'M';
	d_sec.Name[5] = ' ';
	d_sec.Name[6] = ']';
	d_sec.Name[7] = 0x0;
	d_sec.Misc.VirtualSize									= _align(data_buffer.size(), memory_alignment_size);
	d_sec.VirtualAddress									= c_sec.VirtualAddress + c_sec.Misc.VirtualSize;
	d_sec.SizeOfRawData										= _align(data_buffer.size(), file_alignment_size);
	d_sec.PointerToRawData									= c_sec.PointerToRawData + c_sec.SizeOfRawData;
	d_sec.Characteristics									= IMAGE_SCN_CNT_INITIALIZED_DATA	|
        									  				  IMAGE_SCN_MEM_READ				|
												  			  IMAGE_SCN_MEM_WRITE				;

	// Update PE Image Size
	printf("[Information] Updating PE Information...\n");
	nt_h.OptionalHeader.SizeOfImage = 
		_align(d_sec.VirtualAddress + d_sec.Misc.VirtualSize, memory_alignment_size);

	// Update PE Informations
	nt_h.FileHeader.Characteristics = in_pe_nt_header->FileHeader.Characteristics;
	nt_h.FileHeader.TimeDateStamp = in_pe_nt_header->FileHeader.TimeDateStamp;
	nt_h.OptionalHeader.CheckSum = 0x0000F3A6;
	nt_h.OptionalHeader.SizeOfCode = c_sec.SizeOfRawData;
	nt_h.OptionalHeader.SizeOfInitializedData = d_sec.SizeOfRawData;
	nt_h.OptionalHeader.Subsystem = in_pe_nt_header->OptionalHeader.Subsystem;

	// Update PE Entrypoint ( Taken from .map file )
	nt_h.OptionalHeader.AddressOfEntryPoint = 0x00005F10;

	// Get Const Values Offset In Unpacker
	DWORD imagebase_value_sig = 0xBCEAEFBA;
	DWORD imageBaseValueOffset = _find(unpacker_stub, sizeof unpacker_stub, imagebase_value_sig);
	memset(&unpacker_stub[imageBaseValueOffset], NULL, sizeof uintptr_t);
	if (imageBaseValueOffset != -1)
		printf("[Information] ImageBase Value Signature Found at :  %X\n", imageBaseValueOffset);
	DWORD forwarding_value_sig = 0xCAFEBABE;
	DWORD forwarding_value_offset = _find(unpacker_stub, sizeof unpacker_stub, forwarding_value_sig);
	memset(&unpacker_stub[forwarding_value_offset], NULL, sizeof FARPROC);
	if (imageBaseValueOffset != -1)
		printf("[Information] Function Forwading Value Signature Found at :  %X\n", forwarding_value_offset);

	// Create Export Table ( Section [ Export ] )
	IMAGE_SECTION_HEADER et_sec;
	memset(&et_sec, NULL, sizeof IMAGE_SECTION_HEADER);
	bool hasExports = false; vector<uint8_t> et_buffer;

	// Macros
	#define GET_SECTION(h,s) (uintptr_t)IMAGE_FIRST_SECTION(h) + ((s) * sizeof IMAGE_SECTION_HEADER)
	#define RVA_TO_FILE_OFFSET(rva,membase,filebase) ((rva - membase) + filebase)
	#define RVA2OFS_EXP(rva) (input_pe_file_buffer.data() +  \
		(RVA_TO_FILE_OFFSET(rva, in_pe_exp_sec->VirtualAddress, in_pe_exp_sec->PointerToRawData)))
	#define REBASE_RVA(rva) ((rva - in_pe_exp_sec->VirtualAddress + et_sec_virtual_address) - \
								(e_dir_rva - in_pe_exp_sec->VirtualAddress))

	if (isDLL)
	{
		uint8_t export_section_index = 0;
		int export_section_raw_addr = -1;

		// Get Export Table Information
		IMAGE_DATA_DIRECTORY ex_table =
			in_pe_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (ex_table.VirtualAddress != 0) hasExports = true;

		printf("[Information] Has Exports : %s\n", BOOL_STR(hasExports));

		if (hasExports)
		{
			printf("[Information] Creating Export Table...\n");

			// Export Directory RVA
			DWORD e_dir_rva = ex_table.VirtualAddress;
			DWORD et_sec_virtual_address = d_sec.VirtualAddress + d_sec.Misc.VirtualSize;

			printf("[Information] Input PE File Section Count : %d\n", in_pe_nt_header->FileHeader.NumberOfSections);

			// Find Export Section in Input PE File
			for (size_t i = 0; i < in_pe_nt_header->FileHeader.NumberOfSections; i++)
			{
				IMAGE_SECTION_HEADER* get_sec = (PIMAGE_SECTION_HEADER)(GET_SECTION(in_pe_nt_header, i));
				IMAGE_SECTION_HEADER* get_next_sec = (PIMAGE_SECTION_HEADER)(GET_SECTION(in_pe_nt_header, i + 1));

				if (e_dir_rva > get_sec->VirtualAddress &&
					e_dir_rva < get_next_sec->VirtualAddress &&
					(i + 1) <= in_pe_nt_header->FileHeader.NumberOfSections)
				{
					export_section_index = i; break;
				};
			}

			printf("[Information] Export Section Found At %dth Section\n", export_section_index + 1);

			if (export_section_index != -1)
			{
				printf("[Information] Parsing Input PE Export Section...\n");

				// Get Export Directory
				PIMAGE_SECTION_HEADER in_pe_exp_sec = (PIMAGE_SECTION_HEADER)(GET_SECTION(in_pe_nt_header, export_section_index));
				PIMAGE_EXPORT_DIRECTORY e_dir = (PIMAGE_EXPORT_DIRECTORY)RVA2OFS_EXP(e_dir_rva);
				DWORD e_dir_size = in_pe_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

				printf("[Information] Export Section Name : %s\n", in_pe_exp_sec->Name);

				// Extracting Input Binary Export Table
				PULONG  in_et_fn_tab = (PULONG)RVA2OFS_EXP(e_dir->AddressOfFunctions);
				PULONG  in_et_name_tab = (PULONG)RVA2OFS_EXP(e_dir->AddressOfNames);
				PUSHORT in_et_ordianl_tab = (PUSHORT)RVA2OFS_EXP(e_dir->AddressOfNameOrdinals);
				uintptr_t in_et_data_start = (uintptr_t)in_et_fn_tab;
				DWORD in_et_last_fn_name_size = strlen((char*)RVA2OFS_EXP(in_et_name_tab[e_dir->NumberOfNames - 1])) + 1;
				uintptr_t in_et_data_end = (uintptr_t)(RVA2OFS_EXP(in_et_name_tab[e_dir->NumberOfNames - 1]) + in_et_last_fn_name_size);

				// Rebase Export Table Addresses
				printf("[Information] Rebasing Expor Table Addresses...\n");
				e_dir->AddressOfFunctions = REBASE_RVA(e_dir->AddressOfFunctions);
				e_dir->AddressOfNames = REBASE_RVA(e_dir->AddressOfNames);
				e_dir->AddressOfNameOrdinals = REBASE_RVA(e_dir->AddressOfNameOrdinals);
				for (size_t i = 0; i < e_dir->NumberOfNames; i++) in_et_name_tab[i] = REBASE_RVA(in_et_name_tab[i]);

				// Generate Export Table Direcotry Data
				et_buffer.resize(e_dir_size);
				memcpy(et_buffer.data(), e_dir, sizeof IMAGE_EXPORT_DIRECTORY);

				// Generate Export Table Codes
				printf("[Information] Generating Function Forwarding Code...\n");
				DWORD ff_code_buffer_size = sizeof func_forwarding_code * e_dir->NumberOfFunctions;
				uint8_t* ff_code_buffer = (uint8_t*)malloc(ff_code_buffer_size);
				DWORD image_base_rva = c_sec.VirtualAddress + imageBaseValueOffset;
				DWORD ff_value_rva = c_sec.VirtualAddress + forwarding_value_offset;
				for (size_t i = 0; i < e_dir->NumberOfFunctions; i++)
				{
					DWORD func_offset = in_et_fn_tab[in_et_ordianl_tab[i]];
					DWORD machine_code_offset = i * sizeof func_forwarding_code;
					DWORD machine_code_rva = et_buffer.size() + machine_code_offset + et_sec_virtual_address;

					// Machine Code Data
					int32_t* offset_to_image_base = (int32_t*)&func_forwarding_code[5];
					int32_t* function_offset_value = (int32_t*)&func_forwarding_code[10];
					int32_t* offset_to_func_addr = (int32_t*)&func_forwarding_code[20];
					int32_t* offset_to_func_addr2 = (int32_t*)&func_forwarding_code[28];

					offset_to_image_base[0] = (image_base_rva - machine_code_rva) - (5 + sizeof int32_t);
					function_offset_value[0] = func_offset;
					offset_to_func_addr[0] = (ff_value_rva - machine_code_rva) - (20 + sizeof int32_t);
					offset_to_func_addr2[0] = (ff_value_rva - machine_code_rva) - (28 + sizeof int32_t);
					memcpy(&ff_code_buffer[machine_code_offset], func_forwarding_code, sizeof func_forwarding_code);

					// Update Function Address
					in_et_fn_tab[i] = et_sec_virtual_address + et_buffer.size() + (i * sizeof func_forwarding_code);
				}

				// Copy Updated Export Table Data
				DWORD et_data_size = in_et_data_end - in_et_data_start;
				memcpy(&et_buffer.data()[sizeof IMAGE_EXPORT_DIRECTORY], (void*)in_et_data_start, et_data_size);

				// Merge Export Table and Export Data Buffers
				DWORD size_of_export_table = et_buffer.size();
				et_buffer.resize(size_of_export_table + ff_code_buffer_size);
				memcpy(&et_buffer.data()[size_of_export_table], (void*)ff_code_buffer, ff_code_buffer_size);
				free(ff_code_buffer);

				// Generate Export Table Section
				et_sec.Name[0] = '[';
				et_sec.Name[1] = ' ';
				et_sec.Name[2] = 'H';
				et_sec.Name[3] = '.';
				et_sec.Name[4] = 'M';
				et_sec.Name[5] = ' ';
				et_sec.Name[6] = ']';
				et_sec.Name[7] = 0x0;
				et_sec.Misc.VirtualSize = _align(et_buffer.size(), memory_alignment_size);
				et_sec.VirtualAddress = et_sec_virtual_address;
				et_sec.SizeOfRawData = _align(et_buffer.size(), file_alignment_size);
				et_sec.PointerToRawData = d_sec.PointerToRawData + d_sec.SizeOfRawData;
				et_sec.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;

				// Update Export Table Directory
				nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = et_sec.VirtualAddress;
				nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = e_dir_size;

				// Update PE Headers
				nt_h.FileHeader.NumberOfSections = 3;

				// Update PE Image Size
				nt_h.OptionalHeader.SizeOfImage =
					_align(et_sec.VirtualAddress + et_sec.Misc.VirtualSize, memory_alignment_size);
			}
		}
	}

	// Create/Open PE File
	printf("[Information] Writing Generated PE to Disk...\n");
	fstream pe_writter;
	size_t current_pos;
	pe_writter.open(output_pe_file, ios::binary | ios::out);

	// Write DOS Header
	pe_writter.write((char*)&dos_h, sizeof dos_h);

	// Write NT Header
	pe_writter.write((char*)&nt_h, sizeof nt_h);

	// Write Headers of Sections
	pe_writter.write((char*)&c_sec, sizeof c_sec);
	pe_writter.write((char*)&d_sec, sizeof d_sec);
	if (nt_h.FileHeader.NumberOfSections == 3) pe_writter.write((char*)&et_sec, sizeof et_sec);

	// Add Padding
	while (pe_writter.tellp() != c_sec.PointerToRawData) pe_writter.put(0x0);

	// Find Singuatures in Unpacker Stub
	DWORD data_ptr_sig = 0xAABBCCDD;
	DWORD data_size_sig = 0xEEFFAADD;
	DWORD actual_data_size_sig = 0xA0B0C0D0;
	DWORD header_size_sig = 0xF0E0D0A0;
	DWORD data_ptr_offset = _find(unpacker_stub, sizeof unpacker_stub, data_ptr_sig);
	DWORD data_size_offset = _find(unpacker_stub, sizeof unpacker_stub, data_size_sig);
	DWORD actual_data_size_offset = _find(unpacker_stub, sizeof unpacker_stub, actual_data_size_sig);
	DWORD header_size_offset = _find(unpacker_stub, sizeof unpacker_stub, header_size_sig);

	// Update Code Section
	printf("[Information] Updating Offset Data...\n");
	memcpy(&unpacker_stub[data_ptr_offset], &d_sec.VirtualAddress, sizeof DWORD);
	memcpy(&unpacker_stub[data_size_offset], &d_sec.SizeOfRawData, sizeof DWORD);
	DWORD pe_file_actual_size = (DWORD)input_pe_file_buffer.size();
	memcpy(&unpacker_stub[actual_data_size_offset], &pe_file_actual_size, sizeof DWORD);
	memcpy(&unpacker_stub[header_size_offset], &nt_h.OptionalHeader.BaseOfCode, sizeof DWORD);

	// Write Code Section
	printf("[Information] Writing Code Data...\n");
	current_pos = pe_writter.tellp();
	pe_writter.write((char*)&unpacker_stub, sizeof unpacker_stub);
	while (pe_writter.tellp() != current_pos + c_sec.SizeOfRawData) pe_writter.put(0x0);

	// Write Data Section
	printf("[Information] Writing Packed Data...\n");
	current_pos = pe_writter.tellp();
	pe_writter.write((char*)data_buffer.data(), data_buffer.size());
	while (pe_writter.tellp() != current_pos + d_sec.SizeOfRawData) pe_writter.put(0x0);

	// Write Export Section
	if (et_buffer.size() != 0 && hasExports)
	{
		printf("[Information] Writing Export Table Data...\n");
		current_pos = pe_writter.tellp();
		pe_writter.write((char*)et_buffer.data(), et_buffer.size());
		while (pe_writter.tellp() != current_pos + et_sec.SizeOfRawData) pe_writter.put(0x0);
	}

	// Close PE File
	pe_writter.close();

	#pragma endregion

	// Post-Process [ Add Information & Icon ]
	printf("[Information] Adding File Information and Icon...\n");
	HMResKit_LoadPEFile(output_pe_file);
	HMResKit_SetFileInfo("ProductName", "Custom PE Packer");
	HMResKit_SetFileInfo("CompanyName", "MemarDesign™ LLC.");
	HMResKit_SetFileInfo("LegalTrademarks", "MemarDesign™ LLC.");
	HMResKit_SetFileInfo("Comments", "Developed by Hamid.Memar");
	HMResKit_SetFileInfo("FileDescription", "A PE File Packed by HMPacker");
	HMResKit_SetFileInfo("ProductVersion", "1.0.0.1");
	HMResKit_SetFileInfo("FileVersion", "1.0.0.1");
	HMResKit_SetFileInfo("InternalName", "packed-pe-file");
	HMResKit_SetFileInfo("OriginalFilename", "packed-pe-file");
	HMResKit_SetFileInfo("LegalCopyright", "Copyright MemarDesign™ LLC. © 2021-2022");
	HMResKit_SetFileInfo("PrivateBuild", "Packed PE");
	HMResKit_SetFileInfo("SpecialBuild", "Packed PE");
	HMResKit_SetPEVersion("1.0.0.1");
	if (!isDLL) HMResKit_ChangeIcon("app.ico");
	HMResKit_CommitChanges("[ H.M ]");

	// Releasing And Finalizing
	vector<uint8_t>().swap(input_pe_file_buffer);
	vector<uint8_t>().swap(data_buffer);
	CONSOLE_COLOR_SUCCSESS;
	printf("[Information] PE File Packed Successfully.");
	CONSOLE_COLOR_WHITE;
	return EXIT_SUCCESS;
}