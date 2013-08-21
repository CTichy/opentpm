#ifndef _TIS_H_
#define _TIS_H_

//TSS Specification Defines
#define TCG_HASH_SIZE                  20
#define TCG_DATA_OFFSET                10
#define TCG_BUFFER_SIZE                ((TCG_DATA_OFFSET+4+TCG_HASH_SIZE))
#define TPMMAX							4096

#define ACCESS(l)		(0x0000 | ((l) << 12))
#define STS(l)			(0x0018 | ((l) << 12))
#define DATA_FIFO(l)	(0x0024 | ((l) << 12))
#define DID_VID(l)		(0x0F00 | ((l) << 12))

#define ACCESS_ACTIVE_LOCALITY		0x20
#define ACCESS_RELINQUISH_LOCALITY	0x20
#define ACCESS_REQUEST_USE			0x02

#define STS_VALID			0x80
#define STS_COMMAND_READY	0x40
#define STS_DATA_AVAIL		0x10
#define STS_DATA_EXPECT		0x08
#define STS_GO				0x20

int TIS_Init(void);
int TIS_RequestLocality(int l);
int TIS_RecvData(unsigned char *buf, int count);
int TIS_Recv(unsigned char *buf, int count);
int TIS_Send(unsigned char *buf, int len);
unsigned int TIS_Transmit(unsigned char *blob);
void TIS_WaitStatus(unsigned int condition);

#endif