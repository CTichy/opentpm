#ifndef _UTIL_H_
#define _UTIL_H_

unsigned char Read8(unsigned int offset);
unsigned short Read16(unsigned int offset);
unsigned long Read32(unsigned int offset);
void Write8(unsigned char val, unsigned int offset);
void Write16(unsigned short val, unsigned int offset);
void Write32(unsigned long val, unsigned int offset);
unsigned long ntohl(unsigned long in);

#endif
