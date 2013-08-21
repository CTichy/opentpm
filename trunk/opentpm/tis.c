//MITRE TPM 1.2 Driver
//Written by Corey Kallenberg (ckallenberg@mitre.org)
//Copyright 2013 The MITRE Corporation. All Rights Reserved.
//GPL v2
#include <ntddk.h>
#include "driver.h"
#include "tis.h"
#include "util.h"

//sets gLocality to the requested locality
//returns the new locality on success,
//and -1 on error
int TIS_RequestLocality(int l)
{
	Write8(ACCESS_RELINQUISH_LOCALITY, ACCESS(gLocality));
	Write8(ACCESS_REQUEST_USE, ACCESS(l));
	if (Read8(ACCESS(l) & ACCESS_ACTIVE_LOCALITY))
		return gLocality = l;
	return GENERIC_ERROR;
}

//initializes the TPM by relinquishing access to
//all localities then grabbing locality 0.
//On success sets gLocality to 0 and returns 1
//on Error returns 0
int TIS_Init()
{
	unsigned vendor;
	unsigned int i;

	for (i=0;i<5;i++)
	{
		Write8(ACCESS_RELINQUISH_LOCALITY, ACCESS(i));
	}

	if (TIS_RequestLocality(0) < 0)
	{
		KdPrint(("TIS_Init: failed to grab locality 0\n"));
		return 0;
	}

	KeStallExecutionProcessor(10);
	vendor = Read32(DID_VID(0));
	DbgPrint("TIS_Init: vendor id: 0x%x\n", vendor);

	if ((vendor & 0xFFFF) == 0xFFFF)
	{
		KdPrint(("TIS_Init: invalid vendor id\n"));
		return 0;
	}

	gLocality = 0;

	return 1;
}

//sends len bytes of buf to the TPM data buffer
//returns the number of bytes sent on success
//returns -1 on error
int TIS_Send(unsigned char *buf, int len)
{
	int status, burstcnt = 0;
	int count = 0;
	unsigned short stat;

	if (TIS_RequestLocality(gLocality) == -1)
	{
		KdPrint(("TIS_Send: couldnt gain locality: %x\n", gLocality));
		return GENERIC_ERROR;
	}

	Write8(STS_COMMAND_READY, STS(gLocality));
	TIS_WaitStatus(STS_COMMAND_READY);

	while (count < len - 1)
	{
		burstcnt = Read8(STS(gLocality) + 1);
		burstcnt += Read8(STS(gLocality) + 2) << 8;
		if (burstcnt == 0)
		{
			KeStallExecutionProcessor(10);
		} else {
			for (; burstcnt > 0 && count < len - 1; burstcnt--)
			{
				Write8(buf[count], DATA_FIFO(gLocality));
				count++;
			}

			for (status = 0; (status & STS_VALID) == 0; )
				status = Read8(STS(gLocality));

			if ((status & STS_DATA_EXPECT) == 0)
			{
				KdPrint(("TIS_Send: Overflow\n"));
				return GENERIC_ERROR;
			}
		}
	}

	Write8(buf[count], DATA_FIFO(gLocality));

	for (status = 0; (status & STS_VALID) == 0; )
		status = Read8(STS(gLocality));

	if ((status & STS_DATA_EXPECT) != 0)
	{
		KdPrint(("TIS_Send: last byte didnt stick\n"));
		return GENERIC_ERROR;
	}

	Write8(STS_GO, STS(gLocality));
	return len;
}

//Receive count bytes of data from the TPM data buffer into buf
//returns the number of bytes read
int TIS_RecvData(unsigned char *buf, int count)
{
	int size = 0, burstcnt = 0, status;
	status = Read8(STS(gLocality));
	while ( ((status & STS_DATA_AVAIL) || (status & STS_VALID)) && size < count)
	{
		if (burstcnt == 0)
		{
			burstcnt = Read8(STS(gLocality) + 1);
			burstcnt += Read8(STS(gLocality) + 2) << 8;
		}
		if (burstcnt == 0)
		{
			KeStallExecutionProcessor(10);
		} else {
			for (; burstcnt > 0 && size < count; burstcnt--)
			{
				buf[size] = Read8(DATA_FIFO(gLocality));
				size++;
			}
		}
		status = Read8(STS(gLocality));
	}
	return size;
}

//read count bytes into buf from the TPM's data buffer
//returns the number of read bytes on success
//returns <= 0 on error
int TIS_Recv(unsigned char *buf, int count)
{
	int expected, status;
	int size = 0;

	if (count < 6)
		return 0;

	TIS_WaitStatus(STS_DATA_AVAIL);
	status = Read8(STS(gLocality));
	if ((status & (STS_DATA_AVAIL | STS_VALID)) != (STS_DATA_AVAIL | STS_VALID))
		return 0;

	if ((size = TIS_RecvData(buf, 6)) < 6)
		return GENERIC_ERROR;

	expected = ntohl(*(unsigned *)(buf + 2));

	if (expected > count)
		return GENERIC_ERROR;

	if ((size += TIS_RecvData(&buf[6], expected - 6 - 1)) < expected - 1)
		return GENERIC_ERROR;

	TIS_WaitStatus(STS_DATA_AVAIL);
	status = Read8(STS(gLocality));
	if ((status & (STS_DATA_AVAIL | STS_VALID)) != (STS_DATA_AVAIL | STS_VALID))
		return GENERIC_ERROR;

	if ((size += TIS_RecvData(&buf[size], 1)) != expected)
		return GENERIC_ERROR;


	status = Read8(STS(gLocality));
	if ((status & (STS_DATA_AVAIL | STS_VALID)) == (STS_DATA_AVAIL | STS_VALID))
		return GENERIC_ERROR;

	Write8(STS_COMMAND_READY, STS(gLocality));

	return expected;
}

//Sends a command blob to the TPM and reads the response
//back into blob. Note this uses polled I/O style, so if you
//send a command to the TPM that takes a long time, you are going
//to completely stall the CPU while you wait for the response
//returns 1 on success, 0 on error
unsigned int TIS_Transmit(unsigned char *blob)
{
	int len;
	unsigned int size;

	size = ntohl(*(unsigned int *)&blob[2]);
	len = TIS_Send(blob, size);
	if (len < 0)
	{
		KdPrint(("tis_transmit: tis_send returned %d\n", len));
		return 0;
	}

	TIS_WaitStatus(STS_DATA_AVAIL);

	len = TIS_Recv(blob, TPMMAX);
	if (len < 0)
	{
		KdPrint(("tis_transmit: tis_recv returned %x\n", len));
		return 0;
	}

	return 1;
}

//waits for the TPM status buffer to meet the required condition
void TIS_WaitStatus(unsigned int condition)
{
	unsigned short status;
	status = Read16(STS(gLocality));
	while (!(status & condition))
	{
		KeStallExecutionProcessor(1);
		status = Read16(STS(gLocality));
	}
}
