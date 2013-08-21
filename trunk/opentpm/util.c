//MITRE TPM 1.2 Driver
//Written by Corey Kallenberg (ckallenberg@mitre.org)
//Copyright 2013 The MITRE Corporation. All Rights Reserved.
//GPL v2
#include <ntddk.h>
#include "driver.h"
#include "tpm.h"
#include "tis.h"
#include "util.h"

unsigned char Read8(unsigned int offset)
{
	return READ_REGISTER_UCHAR( (PUCHAR) ((unsigned int)gTPMLinearAddress + offset));
}

unsigned short Read16(unsigned int offset)
{
	return READ_REGISTER_USHORT( (PUSHORT) ((unsigned int)gTPMLinearAddress + offset));
}

unsigned long Read32(unsigned int offset)
{
	return READ_REGISTER_ULONG( (PULONG) ((unsigned int)gTPMLinearAddress + offset));
}

void Write8(unsigned char val, unsigned int offset)
{
	WRITE_REGISTER_UCHAR( (PUCHAR) ((unsigned int)gTPMLinearAddress + offset), val);
}

void Write16(unsigned short val, unsigned int offset)
{
	WRITE_REGISTER_USHORT( (PUSHORT) ((unsigned int)gTPMLinearAddress + offset), val);
}

void Write32(unsigned long val, unsigned int offset)
{
	WRITE_REGISTER_ULONG( (PULONG) ((unsigned int)gTPMLinearAddress + offset), val);
}

unsigned long ntohl(unsigned long in) {
    unsigned char *s = (unsigned char *)&in;
    return (unsigned long)(s[0] << 24 | s[1] << 16 | s[2] << 8 | s[3]);
}
