#ifndef __WRITES__
#define __WRITES__
void writeMachineType(IMAGE_FILE_HEADER ntheader);
void writeLinkTime(IMAGE_FILE_HEADER ntheader);
void writeFileHeader(IMAGE_FILE_HEADER ntheader);
void writeSubsystem(uint16_t sub);
void writeSections(IMAGE_SECTION_HEADER * sections, uint8_t numberOfSections);
//Is implemented here, as definition and implementation of template functions cannot be divided
template <typename HEADER>
void writeOptionalHeader(HEADER * optionalhdr)
{
	printf("==OPTIONAL FILE HEADERS==\n");
	printf("Magic:                      0x%X\n", optionalhdr->Magic);
	printf("Linker version:             %d.%d\n", optionalhdr->MajorLinkerVersion, optionalhdr->MinorLinkerVersion);
	printf("Size of Code:               %0.02f kB\n", (float)(optionalhdr->SizeOfCode)/1024);
	printf("Size of initialized data:   %0.02f kB\n", (float)(optionalhdr->SizeOfInitializedData)/1024);
	printf("Size of uninitialized data: %0.02f kB\n", (float)(optionalhdr->SizeOfUninitializedData)/1024);
	printf("Base of code:               0x%08X\n", optionalhdr->BaseOfCode);
	printf("Entry point:                0x%08X\n", optionalhdr->AddressOfEntryPoint);
	printf("Image Version:              %d.%d\n", optionalhdr->MajorImageVersion, optionalhdr->MinorImageVersion);
	printf("OS Version:                 %d.%d\n", optionalhdr->MajorOperatingSystemVersion, optionalhdr->MinorOperatingSystemVersion);
	writeSubsystem(optionalhdr->Subsystem);
	printf("Subsystem version:          %d.%d\n", optionalhdr->MajorSubsystemVersion, optionalhdr->MinorSubsystemVersion);
	printf("Image base:                 0x%X\n", optionalhdr->ImageBase);
	printf("Section alignment:          0x%X\n", optionalhdr->SectionAlignment);
	printf("File alignment:             0x%X\n", optionalhdr->FileAlignment);
	printf("Size of image:              0x%X\n", optionalhdr->SizeOfImage);
	printf("Size of headers:            0x%X\n", optionalhdr->SizeOfHeaders);
	printf("Checksum:                   0x%X\n", optionalhdr->CheckSum);
	printf("Size of stack reserve:      0x%016X\n", optionalhdr->SizeOfStackReserve);
	printf("Size of stack commit:       0x%016X\n", optionalhdr->SizeOfStackCommit);
	printf("Size of heap reserve:       0x%016X\n", optionalhdr->SizeOfHeapReserve);
	printf("Size of heap commit:        0x%016X\n", optionalhdr->SizeOfHeapCommit);
	printf("Export Directory:           %8X[%8X]\n", optionalhdr->DataDirectory[0].VirtualAddress, optionalhdr->DataDirectory[0].Size);
    printf("Import Directory:           %8X[%8X]\n", optionalhdr->DataDirectory[1].VirtualAddress, optionalhdr->DataDirectory[1].Size);
	printf("Resource Directory:         %8X[%8X]\n", optionalhdr->DataDirectory[2].VirtualAddress, optionalhdr->DataDirectory[2].Size);
	printf("Exception Directory:        %8X[%8X]\n", optionalhdr->DataDirectory[3].VirtualAddress, optionalhdr->DataDirectory[3].Size);
	printf("Security Directory:         %8X[%8X]\n", optionalhdr->DataDirectory[4].VirtualAddress, optionalhdr->DataDirectory[4].Size);
	printf("Base Relocation Directory:  %8X[%8X]\n", optionalhdr->DataDirectory[5].VirtualAddress, optionalhdr->DataDirectory[5].Size);
	printf("Debug Directory:            %8X[%8X]\n", optionalhdr->DataDirectory[6].VirtualAddress, optionalhdr->DataDirectory[6].Size);
	printf("Description Directory:      %8X[%8X]\n", optionalhdr->DataDirectory[7].VirtualAddress, optionalhdr->DataDirectory[7].Size);
	printf("Special Directory:          %8X[%8X]\n", optionalhdr->DataDirectory[8].VirtualAddress, optionalhdr->DataDirectory[8].Size);
	printf("Thread Storage Directory:   %8X[%8X]\n", optionalhdr->DataDirectory[9].VirtualAddress, optionalhdr->DataDirectory[9].Size);
	printf("Load Config Directory:      %8X[%8X]\n", optionalhdr->DataDirectory[10].VirtualAddress, optionalhdr->DataDirectory[10].Size);
	printf("Bound Import Directory:     %8X[%8X]\n", optionalhdr->DataDirectory[11].VirtualAddress, optionalhdr->DataDirectory[11].Size);
	printf("IAT Directory:	            %8X[%8X]\n", optionalhdr->DataDirectory[12].VirtualAddress, optionalhdr->DataDirectory[12].Size);
	printf("Delay Import Directory:     %8X[%8X]\n", optionalhdr->DataDirectory[13].VirtualAddress, optionalhdr->DataDirectory[13].Size);
	printf("COR20 Header Directory:     %8X[%8X]\n", optionalhdr->DataDirectory[14].VirtualAddress, optionalhdr->DataDirectory[14].Size);
	printf("Reserved Directory:         %8X[%8X]\n", optionalhdr->DataDirectory[15].VirtualAddress, optionalhdr->DataDirectory[15].Size);
}
#endif
