#include <stdio.h>
#include <Windows.h>
#include <winnt.h>
#include <stdlib.h>
#include <crtdbg.h>

#define _CRTDBG_MAP_ALLOC
#define DOS_SIGNATURE 0x5A4D
#define PE_SIGNATURE 0x4550

#define LOG_INVALID_PARAM(paramType) printf("Invalid %s parameter in %s.\n", paramType, __FUNCTION__)

typedef unsigned long long QWORD, *PQWORD;

typedef struct _FILE_INFO {
	HANDLE fileHandle;
	HANDLE mappingHandle;
	BYTE* fileData;
	DWORD fileSize;
} FILE_INFO, *PFILE_INFO;

typedef struct _NT_FILE_INFO {
	PIMAGE_NT_HEADERS32 ntHeaders;
	PIMAGE_SECTION_HEADER sectionHeaders;
	DWORD rva;
	DWORD fileOffset;
} NT_FILE_INFO, *PNT_FILE_INFO;

typedef enum _PE_ARCHITECTURE {
    PE_UNDEF,
    PE_X86,
    PE_X64
} PE_ARCHITECTURE;

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;

typedef unsigned char UBYTE;

typedef union _UNWIND_CODE {
    struct {
        UBYTE CodeOffset;
        UBYTE UnwindOp : 4;
        UBYTE OpInfo   : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

// Definitions taken from https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170

typedef struct _UNWIND_INFO {
    UBYTE Version       : 3;
    UBYTE Flags         : 5;
    UBYTE SizeOfProlog;
    UBYTE CountOfCodes;
    UBYTE FrameRegister : 4;
    UBYTE FrameOffset   : 4;
    UNWIND_CODE UnwindCode[1];
/*  UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1];
*   union {
*       OPTIONAL ULONG ExceptionHandler;
*       OPTIONAL ULONG FunctionEntry;
*   };
*   OPTIONAL ULONG ExceptionData[]; */
} UNWIND_INFO, *PUNWIND_INFO;

#define GetUnwindCodeEntry(info, index) \
    ((info)->UnwindCode[index])

#define GetLanguageSpecificDataPtr(info) \
    ((PVOID)&GetUnwindCodeEntry((info),((info)->CountOfCodes + 1) & ~1))

#define GetExceptionHandler(base, info) \
    ((PEXCEPTION_HANDLER)((base) + *(PULONG)GetLanguageSpecificDataPtr(info)))

#define GetChainedFunctionEntry(base, info) \
    ((PRUNTIME_FUNCTION)((base) + *(PULONG)GetLanguageSpecificDataPtr(info)))

#define GetExceptionDataPtr(info) \
    ((PVOID)((PULONG)GetLanguageSpecificData(info) + 1))

// End of imported definitions

int rvaToFileOffset(
    WORD numberOfSections, 
    DWORD sectionAlignment, 
    PIMAGE_SECTION_HEADER sectionHeaders, 
    DWORD rva, 
    DWORD* fileOffset
);

int parseExportDirectory(
    PIMAGE_DATA_DIRECTORY dExportInfo, 
    PFILE_INFO fileInfo, 
    PIMAGE_SECTION_HEADER sectionHeader,
    WORD numberOfSections,
    DWORD sectionAlignment,
    PE_ARCHITECTURE peArch
);

int parseImportDescriptor(
    PIMAGE_DATA_DIRECTORY dImportInfo, 
    PFILE_INFO fileInfo, 
    PIMAGE_SECTION_HEADER sectionHeader,
    WORD numberOfSections,
    DWORD sectionAlignment,
    PE_ARCHITECTURE peArch
);

int parseResourceDirectory(
    PIMAGE_DATA_DIRECTORY dRsrcInfo, 
    PFILE_INFO fileInfo, 
    PIMAGE_SECTION_HEADER sectionHeader,
    WORD numberOfSections,
    DWORD sectionAlignment,
    PE_ARCHITECTURE peArch
);

int parseExceptionDirectory(
    PIMAGE_DATA_DIRECTORY dExceptionInfo, 
    PFILE_INFO fileInfo, 
    PIMAGE_SECTION_HEADER sectionHeader,
    WORD numberOfSections,
    DWORD sectionAlignment,
    PE_ARCHITECTURE peArch
);



int (*directoryParserFunctions[])(
    PIMAGE_DATA_DIRECTORY, 
    PFILE_INFO,
    PIMAGE_SECTION_HEADER,
    WORD,
    DWORD,
    PE_ARCHITECTURE
) = {
    parseExportDirectory,
    parseImportDescriptor,
    parseResourceDirectory,
    parseExceptionDirectory
};

char *directoryNames[] = {
    "export",
    "import",
    "resource",
    "exception"
};