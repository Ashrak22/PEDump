#ifndef __STRUCTS__
#define __STRUCTS__
#include <cstdlib>
#include <cstdint>
#include "defines.h"

typedef struct _IMAGE_DOS_HEADER
{
     uint16_t e_magic;
     uint16_t e_cblp;
     uint16_t e_cp;
     uint16_t e_crlc;
     uint16_t e_cparhdr;
     uint16_t e_minalloc;
     uint16_t e_maxalloc;
     uint16_t e_ss;
     uint16_t e_sp;
     uint16_t e_csum;
     uint16_t e_ip;
     uint16_t e_cs;
     uint16_t e_lfarlc;
     uint16_t e_ovno;
     uint16_t e_res[4];
     uint16_t e_oemid;
     uint16_t e_oeminfo;
     uint16_t e_res2[10];
     uint16_t e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
  uint16_t  Machine;
  uint16_t  NumberOfSections;
  uint32_t  TimeDateStamp;
  uint32_t  PointerToSymbolTable;
  uint32_t  NumberOfSymbols;
  uint16_t  SizeOfOptionalHeader;
  uint16_t  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
  uint32_t VirtualAddress;
  uint32_t Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
 WORD        Magic;
 BYTE        MajorLinkerVersion;
 BYTE        MinorLinkerVersion;
 DWORD       SizeOfCode;
 DWORD       SizeOfInitializedData;
 DWORD       SizeOfUninitializedData;
 DWORD       AddressOfEntryPoint;
 DWORD       BaseOfCode;
 ULONGLONG   ImageBase;
 DWORD       SectionAlignment;
 DWORD       FileAlignment;
 WORD        MajorOperatingSystemVersion;
 WORD        MinorOperatingSystemVersion;
 WORD        MajorImageVersion;
 WORD        MinorImageVersion;
 WORD        MajorSubsystemVersion;
 WORD        MinorSubsystemVersion;
 DWORD       Win32VersionValue;
 DWORD       SizeOfImage;
 DWORD       SizeOfHeaders;
 DWORD       CheckSum;
 WORD        Subsystem;
 WORD        DllCharacteristics;
 ULONGLONG   SizeOfStackReserve;
 ULONGLONG   SizeOfStackCommit;
 ULONGLONG   SizeOfHeapReserve;
 ULONGLONG   SizeOfHeapCommit;
 DWORD       LoaderFlags;
 DWORD       NumberOfRvaAndSizes;
 IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD		Magic;
  BYTE      MajorLinkerVersion;
  BYTE      MinorLinkerVersion;
  DWORD     SizeOfCode;
  DWORD     SizeOfInitializedData;
  DWORD     SizeOfUninitializedData;
  DWORD     AddressOfEntryPoint;
  DWORD     BaseOfCode;
  DWORD     BaseOfData;
  DWORD     ImageBase;
  DWORD     SectionAlignment;
  DWORD		FileAlignment;
  WORD      MajorOperatingSystemVersion;
  WORD      MinorOperatingSystemVersion;
  WORD      MajorImageVersion;
  WORD      MinorImageVersion;
  WORD      MajorSubsystemVersion;
  WORD      MinorSubsystemVersion;
  DWORD     Win32VersionValue;
  DWORD     SizeOfImage;
  DWORD     SizeOfHeaders;
  DWORD     CheckSum;
  WORD      Subsystem;
  WORD      DllCharacteristics;
  DWORD     SizeOfStackReserve;
  DWORD     SizeOfStackCommit;
  DWORD     SizeOfHeapReserve;
  DWORD     SizeOfHeapCommit;
  DWORD     LoaderFlags;
  DWORD     NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS {
  DWORD              Signature;
  IMAGE_FILE_HEADER  FileHeader;
  IMAGE_OPTIONAL_HEADER * OptionalHeader;
  IMAGE_OPTIONAL_HEADER64 * OptionalHeader64;
  bool bit64;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[9];
  DWORD PhysicalAddress;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;


#endif