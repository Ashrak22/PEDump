#include <iostream>

#include "structs.h"
#include "writes.h"
#include "reads.h"
#include "defines.h"

using namespace std;
/*
Long read functions are caused by endianity independence, 
if we were to say that don't care about compatibility with 
Big Endian machines, the read functions would shrink a lot.
*/
FILE * openFile(const char * path)
{
	FILE * pe;
	pe = fopen(path, "rb");
	if(pe == NULL)
	{
		cout << "I'm sorry, file does not exist or could not be opened\n";
		system("PAUSE");
		exit(1);
	}
	return pe;
}

int main(int argc, char** argv)
{
	FILE * pe;
	IMAGE_DOS_HEADER dosheader;
	IMAGE_NT_HEADERS ntheader;
	IMAGE_SECTION_HEADER * sections;
	if(argc < 2 || argc > 3)
	{
		cout << "Correct usage: dump \"path to PE to be dumped\"\n";
		return -1;
	}
	pe = openFile(argv[1]);
	
   // NT PE have both DOS and NT headers
   readDOSheader(dosheader, pe);
	readNTheader(ntheader, pe);
   
	//Check for magic, if magic number isn't specified constant end
   if(dosheader.e_magic != 0x5A4D || ntheader.Signature != 0x00004550)
	{
		cout << "This file is not a proper PE";
		printf("\n%X %X\n", dosheader.e_magic, ntheader.Signature);
		system("PAUSE");
		if(ntheader.bit64) delete ntheader.OptionalHeader64;
		else delete ntheader.OptionalHeader;
		return 1;
	}
   
	sections = new IMAGE_SECTION_HEADER[ntheader.FileHeader.NumberOfSections];
	readSections(sections, ntheader.FileHeader.NumberOfSections, pe);
	
   // All has been read, start output
   writeFileHeader(ntheader.FileHeader);
	
   // Differentiate between 32-bit a 64-bit executables
   if(ntheader.bit64)
	{
		writeOptionalHeader<IMAGE_OPTIONAL_HEADER64>(ntheader.OptionalHeader64);
	}
	else
	{	
		writeOptionalHeader<IMAGE_OPTIONAL_HEADER>(ntheader.OptionalHeader);
	}
	
   writeSections(sections, ntheader.FileHeader.NumberOfSections);
	fclose(pe);
	system("PAUSE");
	if(ntheader.bit64) delete ntheader.OptionalHeader64;
	else delete ntheader.OptionalHeader;
	delete [] sections;
	return 0;
}