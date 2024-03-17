#include <stdio.h>
#include <Windows.h>
#include <winnt.h>
#include <stdlib.h>
#include <crtdbg.h>

#define _CRTDBG_MAP_ALLOC
#define DOS_SIGNATURE 0x5A4D
#define PE_SIGNATURE 0x4550
//#define DEBUGRVA

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

int rvaToFileOffset(WORD numberOfSections, 
                    DWORD sectionAlignment, 
                    PIMAGE_SECTION_HEADER sectionHeaders, 
                    DWORD rva, 
                    DWORD* fileOffset
);

int unMapFile(PFILE_INFO fileInfo)
{
	int retVal = 0;

	if (fileInfo == NULL) {
        LOG_INVALID_PARAM("PFILE_INFO");
		return -1;
	}

	if (NULL != fileInfo->fileData) {
		if (!UnmapViewOfFile(fileInfo->fileData)) {
			printf("The file data failed to unmap(0x%08x).\n", GetLastError());
			retVal = -1;
		}
	}

	if (NULL != fileInfo->mappingHandle) {
		if (!CloseHandle(fileInfo->mappingHandle)) {
			printf("The mapping handle failed to close(0x%08x).\n", GetLastError());
			retVal = -1;
		}
	}

	if (INVALID_HANDLE_VALUE != fileInfo->fileHandle) {
		if (!CloseHandle(fileInfo->fileHandle)) {
			printf("The file handle failed to close(0x%08x).\n", GetLastError());
			retVal = -1;
		}
	}

	return retVal;
}

int mapFile(char* path, PFILE_INFO fileInfo)
{
	if (fileInfo == NULL) {
        LOG_INVALID_PARAM("PFILE_INFO");
		return -1;
	}

	int retVal = 0;
	fileInfo->fileHandle = INVALID_HANDLE_VALUE;
	fileInfo->mappingHandle = NULL;
	fileInfo->fileData = NULL;
	do {
		fileInfo->fileHandle = CreateFileA(
			path,
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);
		if (INVALID_HANDLE_VALUE == fileInfo->fileHandle) {
			printf("Failed to open file(0x%08x).\n", GetLastError());
			retVal = -1;
			break;
		}

		fileInfo->fileSize = GetFileSize(fileInfo->fileHandle, NULL);

		if (fileInfo->fileSize == 0) {
			printf("Given file has a length of 0 and cannot be mapped.\n");
			retVal = -1;
			break;
		}
		fileInfo->mappingHandle = CreateFileMappingA(
			fileInfo->fileHandle,
			NULL,
			PAGE_READONLY,
			0,
			0,
			NULL
		);
		if (NULL == fileInfo->mappingHandle) {
			printf("Failed to map file(0x%08x).\n", GetLastError());
			retVal = -1;
			break;
		}

		fileInfo->fileData = (BYTE*)MapViewOfFile(
			fileInfo->mappingHandle,
			FILE_MAP_READ,
			0,
			0,
			0
		);
		if (NULL == fileInfo->fileData) {
			printf("Failed MapViewOfFile(0x%08x).\n", GetLastError());
			retVal = -1;
			break;
		}
	} while (0);

	if (0 != retVal) {
		unMapFile(fileInfo);
	}

	return retVal;
}

int parseExportDirectory(
    PIMAGE_DATA_DIRECTORY dExportInfo, 
    PFILE_INFO fileInfo, 
    PIMAGE_SECTION_HEADER sectionHeader,
    WORD numberOfSections,
    DWORD sectionAlignment,
    PE_ARCHITECTURE peArch
) {
	int retVal = 0;
	PIMAGE_EXPORT_DIRECTORY exportDir = NULL;
	DWORD exportOffset;
	DWORD namesOffset, functionsOffset, nameOrdinalsOffset;
	DWORD namesArrayOffset;
	PDWORD namesArray = NULL;
	DWORD functionsArrayOffset;
	PDWORD functionsArray = NULL;
	DWORD nameOrdinalsArrayOffset;
	PWORD nameOrdinalsArray = NULL;

	if (dExportInfo == NULL) {
        LOG_INVALID_PARAM("PIMAGE_DATA_DIRECTORY");
		return -1;
	}

	if (fileInfo == NULL) {
        LOG_INVALID_PARAM("PFILE_INFO");
		return -1;
	}

    if (sectionHeader == NULL) {
        LOG_INVALID_PARAM("PIMAGE_SECTION_HEADER");
        return -1;
    }

    if (!numberOfSections) {
        LOG_INVALID_PARAM("WORD");
        return -1;
    }

    if (!sectionAlignment) {
        LOG_INVALID_PARAM("DWORD");
        return -1;
    }

	do {
		if (dExportInfo->Size == 0) {
			printf("The file has no export directory.\n");
			retVal = -2;
			break;
		}
		printf("\nParsing the export directory...\n\n");


		if ((retVal = rvaToFileOffset(numberOfSections, sectionAlignment, sectionHeader, 
                                        dExportInfo->VirtualAddress, &exportOffset)) != 0) {
			printf("An error ocurred while transforming the exports RVA to file offset.\n");
			break;
		}
		exportDir = (PIMAGE_EXPORT_DIRECTORY) (fileInfo->fileData + exportOffset);

		if ((retVal = rvaToFileOffset(numberOfSections, sectionAlignment, sectionHeader, 
                                        exportDir->AddressOfFunctions, &functionsOffset)) != 0) {
			printf("An error ocurred while transforming the functions RVA to file offset.\n");
			break;
		}
		functionsArray = (PDWORD)(fileInfo->fileData + functionsOffset);
		
		if ((retVal = rvaToFileOffset(numberOfSections, sectionAlignment, sectionHeader, 
                                        exportDir->AddressOfNames, &namesOffset)) != 0) {
			printf("An error ocurred while transforming the names RVA to file offset.\n");
			break;
		}
		namesArray = (PDWORD)(fileInfo->fileData + namesOffset);
		
		if ((retVal = rvaToFileOffset(numberOfSections, sectionAlignment, sectionHeader, 
                                        exportDir->AddressOfNameOrdinals, &nameOrdinalsOffset)) != 0) {
			printf("An error ocurred while transforming the name ordinals RVA to file offset.\n");
			break;
		}
		nameOrdinalsArray = (PWORD)(fileInfo->fileData + nameOrdinalsOffset);


		for (DWORD i = 0; i < exportDir->NumberOfFunctions; ++i) {

			if (rvaToFileOffset(numberOfSections, sectionAlignment, sectionHeader, functionsArray[i], 
                                &functionsArrayOffset) != 0) {
				printf("There was an error transforming the function RVA to PA for function %u (0x%08X).\n", i + exportDir->Base, functionsArray[i]);
				continue;
			}

			printf("Function with ordinal %u: RVA - 0x%08X PA - 0x%08X ", i + exportDir->Base, functionsArray[i], functionsArrayOffset);

			if (dExportInfo->VirtualAddress <= functionsArray[i] && functionsArray[i] < dExportInfo->VirtualAddress + dExportInfo->Size) {
				printf("- %s", fileInfo->fileData + functionsArrayOffset);
			}
			else {
				for (DWORD j = 0; j < exportDir->NumberOfNames; ++j) {
					if (nameOrdinalsArray[j] == i) {
						if ((retVal = rvaToFileOffset(numberOfSections, sectionAlignment, sectionHeader, namesArray[j], 
                                                        &namesArrayOffset)) != 0) {
							printf("There was an error transforming the name array RVA to file offset for name %u.\n", j);
							continue;
						}
						printf("- %s", fileInfo->fileData + namesArrayOffset);
					}
				}
			}

			printf("\n");
		}

	} while (0);

	return retVal;
}

int parseImportDescriptor(
    PIMAGE_DATA_DIRECTORY dImportInfo, 
    PFILE_INFO fileInfo, 
    PIMAGE_SECTION_HEADER sectionHeader,
    WORD numberOfSections,
    DWORD sectionAlignment,
    PE_ARCHITECTURE peArch
) {
	int retVal = 0;
	DWORD importDescOffset;
	PIMAGE_IMPORT_DESCRIPTOR importDesc = NULL;
	DWORD descriptorIdx = 0;
	DWORD dllNameOffset;
	DWORD importLookupOffset;
	DWORD lookupIdx;
	DWORD nameOffset;
	PIMAGE_IMPORT_BY_NAME fHintName = NULL;


	if (dImportInfo == NULL) {
        LOG_INVALID_PARAM("PIMAGE_DATA_DIRECTORY");
		return -1;
	}

	if (fileInfo == NULL) {
        LOG_INVALID_PARAM("PFILE_INFO");
		return -1;
	}

	if (sectionHeader == NULL) {
        LOG_INVALID_PARAM("PIMAGE_SECTION_HEADER");
		return -1;
	}

    if (!numberOfSections) {
        LOG_INVALID_PARAM("WORD");
        return -1;
    }

    if (!sectionAlignment) {
        LOG_INVALID_PARAM("DWORD");
        return -1;
    }

	// sectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeader + sizeof(IMAGE_NT_HEADERS32));

	do {
		if (dImportInfo->Size == 0) {
			printf("The file does not have an import descriptor.\n");
			retVal = -2;
			break;
		}

		printf("\nParsing the import descriptors...\n\n");

		if ((retVal = rvaToFileOffset(numberOfSections, sectionAlignment, sectionHeader, dImportInfo->VirtualAddress, 
                                        &importDescOffset)) != 0) {
			printf("There was an error transforming the import descriptor RVA to file offset.\n");
			retVal = -3;
			break;
		}
		importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(fileInfo->fileData + importDescOffset);


		while (importDesc[descriptorIdx].Characteristics != 0) {

			if (rvaToFileOffset(numberOfSections, sectionAlignment, sectionHeader, importDesc[descriptorIdx].Name, 
                                &dllNameOffset) != 0) {
				printf("There was an error transforming the dll name RVA to file offset with index %u.\n", descriptorIdx);
				continue;
			}

			printf("Importing from %s\n", fileInfo->fileData + dllNameOffset);


			if (rvaToFileOffset(numberOfSections, sectionAlignment, sectionHeader, 
                                importDesc[descriptorIdx].Characteristics, &importLookupOffset) != 0) {
				printf("There was an error transforming the import lookup table RVA to file offset.\n");
				continue;
			}

			lookupIdx = 0;

            if (peArch == PE_X86) {
                PDWORD importLookupTable = (PDWORD)(fileInfo->fileData + importLookupOffset);

                while (importLookupTable[lookupIdx]) {
                    printf("Function %u is imported by ", lookupIdx);
                    if (importLookupTable[lookupIdx] & 0x80000000) {
                        printf("ordinal: 0x%08X", importLookupTable[lookupIdx] & 0x0000FFFF);
                    }
                    else {
                        if (rvaToFileOffset(numberOfSections, sectionAlignment, sectionHeader, 
                                            importLookupTable[lookupIdx] & 0x7FFFFFFF, &nameOffset) != 0) {
                            printf("There was an error transforming the hint/name RVA to file offset with index %u\n", lookupIdx);
                            continue;
                        }
                        fHintName = (PIMAGE_IMPORT_BY_NAME)(fileInfo->fileData + nameOffset);
                        printf("ordinal and name: 0x%08X - %s", fHintName->Hint, fHintName->Name);
                    }

                    ++lookupIdx;
                    printf("\n");
                }
            }
            else if (peArch == PE_X64) {
                PQWORD importLookupTable = (PQWORD)(fileInfo->fileData + importLookupOffset);

                while (importLookupTable[lookupIdx]) {
                    printf("Function %u is imported by ", lookupIdx);
                    if (importLookupTable[lookupIdx] & 0x8000000000000000) {
                        printf("ordinal: 0x%016I64X", importLookupTable[lookupIdx] & 0x0000FFFF);
                    }
                    else {
                        if (rvaToFileOffset(numberOfSections, sectionAlignment, sectionHeader, 
                                            importLookupTable[lookupIdx] & 0x7FFFFFFF, &nameOffset) != 0) {
                            printf("There was an error transforming the hint/name RVA to file offset with index %u\n", lookupIdx);
                            continue;
                        }
                        fHintName = (PIMAGE_IMPORT_BY_NAME)(fileInfo->fileData + nameOffset);
                        printf("ordinal and name: 0x%08X - %s", fHintName->Hint, fHintName->Name);
                    }

                    ++lookupIdx;
                    printf("\n");
                }
            }

			++descriptorIdx;
			printf("\n");
		}

	} while (0);

	return retVal;
}

int parseResourceDirectory(
    PIMAGE_DATA_DIRECTORY dRsrcInfo, 
    PFILE_INFO fileInfo, 
    PIMAGE_SECTION_HEADER sectionHeader,
    WORD numberOfSections,
    DWORD sectionAlignment,
    PE_ARCHITECTURE peArch
) {
    printf("Resource parsing is not currently supported.\n");
    return 0;
}

int parseExceptionDirectory(
    PIMAGE_DATA_DIRECTORY dExceptionInfo, 
    PFILE_INFO fileInfo, 
    PIMAGE_SECTION_HEADER sectionHeader,
    WORD numberOfSections,
    DWORD sectionAlignment,
    PE_ARCHITECTURE peArch
) {
    int retVal = 0;
    DWORD exceptionDirOffset = 0;
    PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY runtimeFunction = NULL;
    
    if (dExceptionInfo == NULL) {
        LOG_INVALID_PARAM("PIMAGE_DATA_DIRECTORY");
		return -1;
	}

	if (fileInfo == NULL) {
        LOG_INVALID_PARAM("PFILE_INFO");
		return -1;
	}

    if (sectionHeader == NULL) {
        LOG_INVALID_PARAM("PIMAGE_SECTION_HEADER");
        return -1;
    }

    if (!numberOfSections) {
        LOG_INVALID_PARAM("WORD");
        return -1;
    }

    if (!sectionAlignment) {
        LOG_INVALID_PARAM("DWORD");
        return -1;
    }

	do {
		if (dExceptionInfo->Size == 0) {
			printf("The file has no exception directory.\n");
			retVal = -2;
			break;
		}

		printf("\nParsing the exception directory...\n\n");

        if ((retVal = rvaToFileOffset(numberOfSections, sectionAlignment, sectionHeader, dExceptionInfo->VirtualAddress, 
                                        &exceptionDirOffset)) != 0) {
			printf("There was an error transforming the import descriptor RVA to file offset.\n");
			retVal = -3;
			break;
		}
        runtimeFunction = (PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY) (fileInfo->fileData + exceptionDirOffset);

        for (int i = 0; i < dExceptionInfo->Size / sizeof(IMAGE_IA64_RUNTIME_FUNCTION_ENTRY); ++i) {
            printf("Identified exception-related function at 0x08%X-0x08%X.\n", 
                runtimeFunction->BeginAddress, runtimeFunction->EndAddress);
            printf("Found unwind info at 0x%08X.\n", runtimeFunction->UnwindInfoAddress);

            ++runtimeFunction;
        }

    } while (0);

    return retVal;
}

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

int _ParseExe32(PFILE_INFO fileInfo, PNT_FILE_INFO ntFileInfo, 
                PIMAGE_DOS_HEADER dosHeader, PIMAGE_NT_HEADERS32 ntHeader) {
    int retVal = 0;

    if (fileInfo == NULL) {
        LOG_INVALID_PARAM("PFILE_INFO");
        return -1;
    }

    if (ntFileInfo == NULL) {
        LOG_INVALID_PARAM("PNT_FILE_INFO");
        return -1;
    }

    if (dosHeader == NULL) {
        LOG_INVALID_PARAM("PIMAGE_DOS_HEADER");
        return -1;
    }

    if (ntHeader == NULL) {
        LOG_INVALID_PARAM("PIMAGE_NT_HEADERS32");
        return -1;
    }

    do {
        if (dosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
			ntHeader->FileHeader.SizeOfOptionalHeader > fileInfo->fileSize) {
			printf("File is too small for IMAGE_OPTIONAL_HEADER.\n");
			retVal = -7;
			break;
		}

		if (dosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
			ntHeader->FileHeader.SizeOfOptionalHeader + 
			ntHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > fileInfo->fileSize) {
			printf("File is too small for section headers.\n");
			retVal = -8;
			break;
		}

		if (ntHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) {
			printf("Parsing a DLL file...\n");
		}

        for (int i = 0; i < min(ntHeader->OptionalHeader.NumberOfRvaAndSizes, 4); ++i) {
            if (directoryParserFunctions[i](
                &(ntHeader->OptionalHeader.DataDirectory)[i],
                fileInfo,
                (PIMAGE_SECTION_HEADER) ((PBYTE)ntHeader + sizeof(IMAGE_NT_HEADERS32)),
                ntHeader->FileHeader.NumberOfSections,
                ntHeader->OptionalHeader.SectionAlignment, PE_X86) != 0) {

                printf("There was an error parsing the %s directory.\n", directoryNames[i]);
            }
        }

#ifdef DEBUGRVA
		ntFileInfo->ntHeaders = ntHeader;
		ntFileInfo->rva = ntHeader->OptionalHeader.AddressOfEntryPoint;
		ntFileInfo->sectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeader + sizeof(IMAGE_NT_HEADERS32));
		printf("Alignment is set to 0x%08X for sections.\n", ntHeader->OptionalHeader.SectionAlignment);
		printf("Alignment is set to 0x%08X for file.\n", ntHeader->OptionalHeader.FileAlignment);

		printf("The file header was parsed successfully.\n");
		printf("\n*/-------------------------------------\\*\n");
		printf("*\\-------------------------------------/*\n\n");
#endif

    } while (0);

    return retVal;
}

int _ParseExe64(PFILE_INFO fileInfo, PNT_FILE_INFO ntFileInfo, 
                PIMAGE_DOS_HEADER dosHeader, PIMAGE_NT_HEADERS64 ntHeader) {
    int retVal = 0;

    if (fileInfo == NULL) {
        LOG_INVALID_PARAM("PFILE_INFO");
        return -1;
    }

    if (ntFileInfo == NULL) {
        LOG_INVALID_PARAM("PNT_FILE_INFO");
        return -1;
    }

    if (dosHeader == NULL) {
        LOG_INVALID_PARAM("PIMAGE_DOS_HEADER");
        return -1;
    }

    if (ntHeader == NULL) {
        LOG_INVALID_PARAM("PIMAGE_NT_HEADERS64");
        return -1;
    }
    
    do {
        if (dosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
			ntHeader->FileHeader.SizeOfOptionalHeader > fileInfo->fileSize) {
			printf("File is too small for IMAGE_OPTIONAL_HEADER.\n");
			retVal = -7;
			break;
		}

		if (dosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
			ntHeader->FileHeader.SizeOfOptionalHeader + 
			ntHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > fileInfo->fileSize) {
			printf("File is too small for section headers.\n");
			retVal = -8;
			break;
		}

		if (ntHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) {
			printf("Parsing a DLL file...\n");
		}

        for (int i = 0; i < min(ntHeader->OptionalHeader.NumberOfRvaAndSizes, 4); ++i) {
            if (directoryParserFunctions[i](
                &(ntHeader->OptionalHeader.DataDirectory)[i],
                fileInfo,
                (PIMAGE_SECTION_HEADER) ((PBYTE)ntHeader + sizeof(IMAGE_NT_HEADERS64)),
                ntHeader->FileHeader.NumberOfSections,
                ntHeader->OptionalHeader.SectionAlignment, PE_X64) != 0) {

                printf("There was an error parsing the %s directory.\n", directoryNames[i]);
            }
        }

#ifdef DEBUGRVA
		ntFileInfo->ntHeaders = ntHeader;
		ntFileInfo->rva = ntHeader->OptionalHeader.AddressOfEntryPoint;
		ntFileInfo->sectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeader + sizeof(IMAGE_NT_HEADERS32));
		printf("Alignment is set to 0x%08X for sections.\n", ntHeader->OptionalHeader.SectionAlignment);
		printf("Alignment is set to 0x%08X for file.\n", ntHeader->OptionalHeader.FileAlignment);

		printf("The file header was parsed successfully.\n");
		printf("\n*/-------------------------------------\\*\n");
		printf("*\\-------------------------------------/*\n\n");
#endif

    } while (0);

    return retVal;
}

int parseExe(PFILE_INFO fileInfo, PNT_FILE_INFO ntFileInfo) {
	int retVal = 0;
	PIMAGE_DOS_HEADER dosHeader = NULL;
	PIMAGE_NT_HEADERS32 ntHeader = NULL;

	if (fileInfo == NULL) {
        LOG_INVALID_PARAM("PFILE_INFO");
		return -1;
	}

	if (ntFileInfo == NULL) {
        LOG_INVALID_PARAM("PNT_FILE_INFO");
		return -1;
	}

	do {
		if (sizeof(IMAGE_DOS_HEADER) > fileInfo->fileSize) {
			printf("File is too small to be a DOS executable.\n");
			retVal = -2;
			break;
		}
		dosHeader = (PIMAGE_DOS_HEADER)fileInfo->fileData;

		if (dosHeader->e_magic != DOS_SIGNATURE) {
			printf("File does not have DOS executable signature.\n");
			retVal = -3;
			break;
		}

		if (dosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > fileInfo->fileSize) {
			printf("File is too small to be a PE.\n");
			retVal = -4;
			break;
		}
		ntHeader = (PIMAGE_NT_HEADERS32)(fileInfo->fileData + dosHeader->e_lfanew);

		if (ntHeader->Signature != PE_SIGNATURE) {
			printf("File does not have PE signature.\n");
			retVal = -5;
			break;
		}

		if (ntHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
            retVal = _ParseExe32(fileInfo, ntFileInfo, dosHeader, ntHeader);
		} else if (ntHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            retVal = _ParseExe64(fileInfo, ntFileInfo, dosHeader, (PIMAGE_NT_HEADERS64) ntHeader);

        } else {
            printf("The parser does not support the given machine: 0x%X.\n", ntHeader->FileHeader.Machine);
            retVal = -1;
            break;
        }

        // if (ntHeader->OptionalHeader.NumberOfRvaAndSizes >= 3 &&
		// 	parseResourceDirectory(&(ntHeader->OptionalHeader.DataDirectory)[2], fileInfo, ntHeader) != 0) {
		// 	printf("There was an error parsing the resource directory.\n");
		// }

        // if (ntHeader->OptionalHeader.NumberOfRvaAndSizes >= 4 &&
		// 	parseExceptionDirectory(&(ntHeader->OptionalHeader.DataDirectory)[3], fileInfo, ntHeader) != 0) {
		// 	printf("There was an error parsing the exception descriptor.\n");
		// }

	} while (0);

	return retVal;
}

int rvaToFileOffset(WORD numberOfSections, DWORD sectionAlignment, PIMAGE_SECTION_HEADER sectionHeaders, DWORD rva, DWORD* fileOffset) {
	int retVal = -3;

	if (!numberOfSections) {
        LOG_INVALID_PARAM("WORD");
        printf("No sections for RVA to file conversion.\n");
		return -1;
	}

    if (!sectionAlignment) {
        LOG_INVALID_PARAM("WORD");
        printf("No section alignment for RVA to file conversion.\n");
		return -1;
    }

	if (sectionHeaders == NULL) {
        LOG_INVALID_PARAM("PIMAGE_SECTION_HEADER");
		return -1;
	}

	if (fileOffset == NULL) {
        LOG_INVALID_PARAM("DWORD");
		return -1;
	}

	do {
#ifdef DEBUGRVA
		printf("Total number of sections: %hu\n", numberOfSections);
		printf("Address of Entry Point(RVA): 0x%08X\n", rva);
#endif
		for (WORD i = 0; i < numberOfSections; ++i) {
#ifdef DEBUGRVA
			printf("\nSize of sector with index %d: 0x%08X\n", i, sectionHeaders[i].SizeOfRawData);
			printf("Address of sector with index %d(PA): 0x%08X\n", i, sectionHeaders[i].PointerToRawData);
			printf("Address of sector with index %d(RVA): 0x%08X\n", i, sectionHeaders[i].VirtualAddress);
#endif

			// Calculez pana unde merge pagina sectorului curent
			DWORD endOfSector = (sectionHeaders[i].VirtualAddress + sectionHeaders[i].Misc.VirtualSize + 
				sectionAlignment - 1);
			endOfSector /= sectionAlignment;
			endOfSector *= sectionAlignment;

#ifdef DEBUGRVA
			printf("End of sector is at: 0x%08X\n", endOfSector);
#endif

			if (sectionHeaders[i].VirtualAddress <= rva) {
				if (rva <= sectionHeaders[i].VirtualAddress + sectionHeaders[i].Misc.VirtualSize) {
					*fileOffset = sectionHeaders[i].PointerToRawData + rva - sectionHeaders[i].VirtualAddress;
					retVal = 0;
					break;
				}
				else if (rva < endOfSector) {
					printf("Entry point is not in a sector.\n");
					retVal = -2;
					break;
				}
			}
		}

	} while (0);

	return retVal;
}

int main(int argc, char** argv)
{
	FILE_INFO fileInfo;
	NT_FILE_INFO ntFileInfo;
	int retVal;

	if (2 != argc) {
		printf("usage: %s <file_path>\n", argv[0]);
		return 1;
	}

	if ((retVal = mapFile(argv[1], &fileInfo)) != 0) {
		printf("map fail: %d\n", retVal);
		return retVal;
	}

	printf("Mapped %s successfully\n", argv[1]);

	if ((retVal = parseExe(&fileInfo, &ntFileInfo)) != 0) {
	 	printf("There was a problem parsing the executable file.\n");
		unMapFile(&fileInfo);
		return retVal;
	}

	//if ((retVal = rvaToFileOffset(ntFileInfo.ntHeaders, ntFileInfo.sectionHeaders, ntFileInfo.rva, &ntFileInfo.fileOffset)) != 0) {
		//printf("There was a problem converting the RVA into a file offset.\n");
		//unMapFile(&fileInfo);
		//return retVal;
	//}

	//printf("\nAddress of Entry Point(PA): 0x%08X\n", ntFileInfo.fileOffset);

	unMapFile(&fileInfo);

	_CrtDumpMemoryLeaks();
	return 0;
}