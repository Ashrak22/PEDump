#include "reads.h"
/* Reads can be done by simple memcopy, specification said: 
"do it for both endians"
*/
void readDOSheader(IMAGE_DOS_HEADER &dosheader, FILE * pe)
{
	dosheader.e_magic = readLB<uint16_t>(pe);
	dosheader.e_cblp = readLB<uint16_t>(pe);
    dosheader.e_cp = readLB<uint16_t>(pe);
    dosheader.e_crlc = readLB<uint16_t>(pe);
    dosheader.e_cparhdr = readLB<uint16_t>(pe);
    dosheader.e_minalloc = readLB<uint16_t>(pe);
    dosheader.e_maxalloc = readLB<uint16_t>(pe);
    dosheader.e_ss = readLB<uint16_t>(pe);
    dosheader.e_sp = readLB<uint16_t>(pe);
    dosheader.e_csum = readLB<uint16_t>(pe);
    dosheader.e_ip = readLB<uint16_t>(pe);
    dosheader.e_cs = readLB<uint16_t>(pe);
    dosheader.e_lfarlc = readLB<uint16_t>(pe);
    dosheader.e_ovno = readLB<uint16_t>(pe);
	for(int i = 0; i < 4; i++) dosheader.e_res[i] = readLB<uint16_t>(pe);
	dosheader.e_oemid = readLB<uint16_t>(pe);
    dosheader.e_oeminfo = readLB<uint16_t>(pe);
    for(int i = 0; i < 10; i++) dosheader.e_res2[i] = readLB<uint16_t>(pe);
    dosheader.e_lfanew = readLB<uint16_t>(pe);
	fseek(pe, dosheader.e_lfanew,SEEK_SET);
}
void readOptional64Header(IMAGE_OPTIONAL_HEADER64 &m_64hdr, FILE * pe)
{
	m_64hdr.Magic = readLB<uint16_t>(pe);
	m_64hdr.MajorLinkerVersion = readLB<uint8_t>(pe);
	m_64hdr.MinorLinkerVersion = readLB<uint8_t>(pe);
	m_64hdr.SizeOfCode = readLB<uint32_t>(pe);
	m_64hdr.SizeOfInitializedData = readLB<uint32_t>(pe);
	m_64hdr.SizeOfUninitializedData = readLB<uint32_t>(pe);
	m_64hdr.AddressOfEntryPoint = readLB<uint32_t>(pe);
	m_64hdr.BaseOfCode = readLB<uint32_t>(pe);
	m_64hdr.ImageBase = readLB<uint64_t>(pe);
	m_64hdr.SectionAlignment = readLB<uint32_t>(pe);
	m_64hdr.FileAlignment = readLB<uint32_t>(pe);
	m_64hdr.MajorOperatingSystemVersion = readLB<uint16_t>(pe);
	m_64hdr.MinorOperatingSystemVersion = readLB<uint16_t>(pe);
	m_64hdr.MajorImageVersion = readLB<uint16_t>(pe);
	m_64hdr.MinorImageVersion = readLB<uint16_t>(pe);
	m_64hdr.MajorSubsystemVersion = readLB<uint16_t>(pe);
	m_64hdr.MinorSubsystemVersion = readLB<uint16_t>(pe);
	m_64hdr.Win32VersionValue = readLB<uint32_t>(pe);
	m_64hdr.SizeOfImage = readLB<uint32_t>(pe);
	m_64hdr.SizeOfHeaders = readLB<uint32_t>(pe);
	m_64hdr.CheckSum = readLB<uint32_t>(pe);
	m_64hdr.Subsystem = readLB<uint16_t>(pe);
	m_64hdr.DllCharacteristics = readLB<uint16_t>(pe);
	m_64hdr.SizeOfStackReserve = readLB<uint64_t>(pe);
	m_64hdr.SizeOfStackCommit = readLB<uint64_t>(pe);
	m_64hdr.SizeOfHeapReserve = readLB<uint64_t>(pe);
	m_64hdr.SizeOfHeapCommit = readLB<uint64_t>(pe);
	m_64hdr.LoaderFlags = readLB<uint32_t>(pe);
	m_64hdr.NumberOfRvaAndSizes = readLB<uint32_t>(pe);
	readDirs<IMAGE_OPTIONAL_HEADER64>(m_64hdr, pe);
}
void readOptionalHeader(IMAGE_OPTIONAL_HEADER &m_hdr, FILE * pe)
{
	m_hdr.Magic = readLB<uint16_t>(pe);
	m_hdr.MajorLinkerVersion = readLB<uint8_t>(pe);
	m_hdr.MinorLinkerVersion = readLB<uint8_t>(pe);
	m_hdr.SizeOfCode = readLB<uint32_t>(pe);
	m_hdr.SizeOfInitializedData = readLB<uint32_t>(pe);
	m_hdr.SizeOfUninitializedData = readLB<uint32_t>(pe);
	m_hdr.AddressOfEntryPoint = readLB<uint32_t>(pe);
	m_hdr.BaseOfCode = readLB<uint32_t>(pe);
	m_hdr.BaseOfData = readLB<uint32_t>(pe);
	m_hdr.ImageBase = readLB<uint32_t>(pe);
	m_hdr.SectionAlignment = readLB<uint32_t>(pe);
	m_hdr.FileAlignment = readLB<uint32_t>(pe);
	m_hdr.MajorOperatingSystemVersion = readLB<uint16_t>(pe);
	m_hdr.MinorOperatingSystemVersion = readLB<uint16_t>(pe);
	m_hdr.MajorImageVersion = readLB<uint16_t>(pe);
	m_hdr.MinorImageVersion = readLB<uint16_t>(pe);
	m_hdr.MajorSubsystemVersion = readLB<uint16_t>(pe);
	m_hdr.MinorSubsystemVersion = readLB<uint16_t>(pe);
	m_hdr.Win32VersionValue = readLB<uint32_t>(pe);
	m_hdr.SizeOfImage = readLB<uint32_t>(pe);
	m_hdr.SizeOfHeaders = readLB<uint32_t>(pe);
	m_hdr.CheckSum = readLB<uint32_t>(pe);
	m_hdr.Subsystem = readLB<uint16_t>(pe);
	m_hdr.DllCharacteristics = readLB<uint16_t>(pe);
	m_hdr.SizeOfStackReserve = readLB<uint32_t>(pe);
	m_hdr.SizeOfStackCommit = readLB<uint32_t>(pe);
	m_hdr.SizeOfHeapReserve = readLB<uint32_t>(pe);
	m_hdr.SizeOfHeapCommit = readLB<uint32_t>(pe);
	m_hdr.LoaderFlags = readLB<uint32_t>(pe);
	m_hdr.NumberOfRvaAndSizes = readLB<uint32_t>(pe);
	readDirs<IMAGE_OPTIONAL_HEADER>(m_hdr, pe);
}
void readNTheader(IMAGE_NT_HEADERS &ntheader, FILE * pe)
{
	ntheader.Signature = readLB<uint32_t>(pe);
	ntheader.FileHeader.Machine = readLB<uint16_t>(pe);
	ntheader.FileHeader.NumberOfSections = readLB<uint16_t>(pe);
	ntheader.FileHeader.TimeDateStamp = readLB<uint32_t>(pe);
	ntheader.FileHeader.PointerToSymbolTable = readLB<uint32_t>(pe);
	ntheader.FileHeader.NumberOfSymbols = readLB<uint32_t>(pe);
	ntheader.FileHeader.SizeOfOptionalHeader = readLB<uint16_t>(pe);
	ntheader.FileHeader.Characteristics = readLB<uint16_t>(pe);
	
	if(ntheader.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 || ntheader.FileHeader.Machine == IMAGE_FILE_MACHINE_IA64)
	{
		ntheader.bit64 = true;
		ntheader.OptionalHeader64 = new IMAGE_OPTIONAL_HEADER64;
		ntheader.OptionalHeader = NULL;
		readOptional64Header(*(ntheader.OptionalHeader64), pe);
	}
	else
	{
		ntheader.bit64 = false;
		ntheader.OptionalHeader = new IMAGE_OPTIONAL_HEADER;
		ntheader.OptionalHeader64 = NULL;
		readOptionalHeader(*(ntheader.OptionalHeader), pe);
	}
}
void readSections(IMAGE_SECTION_HEADER * sections, uint8_t numberOfSections, FILE * pe)
{
	for(int i = 0; i < numberOfSections; i++)
	{
		fread(&(sections[i].Name), 1, 8, pe);
		sections[i].Name[8] = '\0';
		sections[i].PhysicalAddress = readLB<uint32_t>(pe);
		sections[i].VirtualAddress = readLB<uint32_t>(pe);
		sections[i].SizeOfRawData = readLB<uint32_t>(pe);
		sections[i].PointerToRawData = readLB<uint32_t>(pe);
		sections[i].PointerToRelocations = readLB<uint32_t>(pe);
		sections[i].PointerToLinenumbers = readLB<uint32_t>(pe);
		sections[i].NumberOfRelocations = readLB<uint16_t>(pe);
		sections[i].NumberOfLinenumbers = readLB<uint16_t>(pe);
		sections[i].Characteristics = readLB<uint32_t>(pe);
	}
}
