#ifndef __READS__
#define __READS__
#include <cstdint>
#include <cstdio>
#include "structs.h"
using namespace std;

/*This function should read values from file 
regardless of the endianity of the target machine.
It has to be in header file as with template functions specification and
implementation have to be together*/
template <typename LEN>
LEN readLB(FILE * pe)
{
	uint8_t * bytes;
	LEN res = 0;
	int length = sizeof(LEN);
	bytes = new uint8_t[length];
	fread(bytes, 1, length, pe);
	res = (LEN)bytes[0];
	for(int i = 1; i < length; i++) res += ((LEN)bytes[i] << (i*8));
	delete [] bytes;
	return res;
}
template <typename HDR>
void readDirs(HDR &m_hdr, FILE * pe)
{
	for(int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
	{
		m_hdr.DataDirectory[i].VirtualAddress = readLB<uint32_t>(pe);
		m_hdr.DataDirectory[i].Size = readLB<uint32_t>(pe);
	}
}

void readDOSheader(IMAGE_DOS_HEADER &dosheader, FILE * pe);
void readOptional64Header(IMAGE_OPTIONAL_HEADER64 &m_64hdr, FILE * pe);
void readOptionalHeader(IMAGE_OPTIONAL_HEADER &m_hdr, FILE * pe);
void readNTheader(IMAGE_NT_HEADERS &ntheader, FILE * pe);
void readSections(IMAGE_SECTION_HEADER * sections, uint8_t numberOfSections, FILE * pe);
#endif
