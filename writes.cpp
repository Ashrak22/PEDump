#include "structs.h"
#include "writes.h"

#include <cstdio>
#include <ctime>

void writeFileHeader(IMAGE_FILE_HEADER ntheader)
{
	printf("==FILE HEADER==\n");
	if(ntheader.Characteristics & 0x2000) printf("Image is DLL\n");
	else printf("Image is EXE\n");
	writeMachineType(ntheader);
	writeLinkTime(ntheader);
	printf("Number of sections:         %d\n", ntheader.NumberOfSections);
	printf("Pointer to symbol Table:    0x%X\n", ntheader.PointerToSymbolTable);
	printf("Number of symbols:          %d\n", ntheader.NumberOfSymbols );
	printf("Size of optional header:    %X\n", ntheader.SizeOfOptionalHeader);
	printf("characteristics:            %X\n\n", ntheader.Characteristics );
}

void writeSections(IMAGE_SECTION_HEADER * sections, uint8_t numberOfSections)
{
	for(int i = 0; i < numberOfSections; i++)
	{
		printf("\n== SECTION #%d ==\n", i+1);
		printf("%s\n", sections[i].Name);
		printf("Physical address: 0x%X\n", sections[i].PhysicalAddress);
		printf("Virtual address: 0x%X\n", sections[i].VirtualAddress);
		printf("Size of RAW data: %u\n", sections[i].SizeOfRawData);
		printf("Pointer to RAW data: 0x%X\n", sections[i].PointerToRawData);
		printf("Number of relocations: %u\n", sections[i].NumberOfRelocations);
		printf("Pointer to Relocations: 0x%X\n", sections[i].PointerToRelocations);
		printf("Number of line numbers: %u\n", sections[i].NumberOfLinenumbers);
		printf("Pointer to Line numbers: 0x%X\n", sections[i].PointerToLinenumbers);
		printf("Characteristics: %X\n", sections[i].Characteristics);
	}
}

/*
Following three are helper functions to make the code more readable
*/
void writeMachineType(IMAGE_FILE_HEADER ntheader)
{
	printf("Machine type:               ");
	switch(ntheader.Machine)
	{
	case IMAGE_FILE_MACHINE_I386:
		printf("x86 32-bit\n");
		break;
	case IMAGE_FILE_MACHINE_IA64:
		printf("Intel Itanium 64-bit\n");
		break;
	case IMAGE_FILE_MACHINE_AMD64:
		printf("AMD x64 64-bit\n");
		break;
	}
}

void writeLinkTime(IMAGE_FILE_HEADER ntheader)
{
	struct tm* locTime;
	char timeString[100];
	time_t linkTime = ntheader.TimeDateStamp;
	locTime = localtime(&linkTime);
	strftime (timeString,100,"%H:%M:%S %d. %B %Y.",locTime); //Entirely non trivial - %R is time 24H format, %d - Zero padded number of day in month, %B full name of Month, %G year
	printf("Linktime:                   %s\n", timeString);
}

void writeSubsystem(uint16_t sub)
{
	printf("Subsystem:                  ");
	switch(sub)
	{
	case IMAGE_SUBSYSTEM_UNKNOWN:
		printf("Unknown\n");
		break;
	case IMAGE_SUBSYSTEM_NATIVE:
		printf("Native\n");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_GUI:
		printf("Windows GUI\n");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CUI:
		printf("Windows CUI\n");
		break;
	case IMAGE_SUBSYSTEM_OS2_CUI:
		printf("OS/2\n");
		break;
	case IMAGE_SUBSYSTEM_POSIX_CUI:
		printf("POSIX\n");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		printf("Windows CE\n");
		break;
	case IMAGE_SUBSYSTEM_EFI_APPLICATION:
		printf("EFI app\n");
		break;
	case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		printf("EFI boot service driver\n");
		break;
	case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		printf("EFI Runtime driver\n");
		break;
	case IMAGE_SUBSYSTEM_EFI_ROM:
		printf("EFI ROM\n");
		break;
	case IMAGE_SUBSYSTEM_XBOX:
		printf("XBOX\n");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
		printf("Boot application\n");
		break;
	default:
		break;
	};	
}
