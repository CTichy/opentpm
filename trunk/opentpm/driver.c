//MITRE TPM 1.2 Driver
//Written by Corey Kallenberg (ckallenberg@mitre.org)
//Copyright 2013 The MITRE Corporation. All Rights Reserved.
//GPL v2
#include <ntddk.h>
#include "driver.h"
#include "tis.h"
#include "util.h"

PVOID gTPMLinearAddress;
SIZE_T gTPMRegisterSize;
int gLocality;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	PHYSICAL_ADDRESS tpmPhysicalAddress;
	NTSTATUS ntStat;
	PDEVICE_OBJECT pDeviceObject;
	UNICODE_STRING deviceName;
	UNICODE_STRING dosDeviceName;
	unsigned int i;

	tpmPhysicalAddress.QuadPart = 0xfed40000;
	gTPMRegisterSize = 0x5000;
	pDeviceObject = NULL;	

	DbgPrint("OpenTPM Driver Loading\n");
	DbgPrint("By Corey Kallenberg\n");
	DriverObject->DriverUnload = OnUnload;

	gTPMLinearAddress = 0;
	gTPMLinearAddress = MmMapIoSpace(tpmPhysicalAddress, gTPMRegisterSize,MmNonCached); 
	if (gTPMLinearAddress == 0)
	{
		KdPrint(("DriverEntry: MmMapIOSpace Failed. Exiting.\n"));
		return GENERIC_ERROR;
	}

	if (!TIS_Init())
	{
		KdPrint(("DriverEntry: TIS_Init() failed. Exiting.\n"));
		goto failure;
	}

	RtlInitUnicodeString(&deviceName, DEVICE_NAME);
	RtlInitUnicodeString(&dosDeviceName, DOS_DEVICE_NAME);
	ntStat = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN,
							FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);

	if (ntStat != STATUS_SUCCESS)
	{
		KdPrint(("DriverEntry: IoCreateDeviceFailed. Exiting\n"));
		goto failure;
	}

	pDeviceObject->Flags |= DO_DIRECT_IO;
	pDeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);

	for (i=0;i<IRP_MJ_MAXIMUM_FUNCTION;i++)
	{
		DriverObject->MajorFunction[i] = DeviceUnsupportedFunction;
	}

	DriverObject->MajorFunction[IRP_MJ_WRITE] = DeviceWrite;
	DriverObject->MajorFunction[IRP_MJ_READ] = DeviceRead;

	IoCreateSymbolicLink(&dosDeviceName, &deviceName);

	return STATUS_SUCCESS;

failure:
	KdPrint(("MITRE TPM Driver had issues loading... Exiting\n"));
	MmUnmapIoSpace((PVOID)gTPMLinearAddress, gTPMRegisterSize);
	return GENERIC_ERROR;
}

VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING dosDeviceName;

	DbgPrint("OpenTPM Driver Unloading...\n");
	RtlInitUnicodeString(&dosDeviceName, DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&dosDeviceName);
	IoDeleteDevice(DriverObject->DeviceObject);
	MmUnmapIoSpace((PVOID)gTPMLinearAddress, gTPMRegisterSize); 
}

NTSTATUS DeviceWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS ntStat;
	PIO_STACK_LOCATION pIoStackIrp;
	unsigned char  *writeBuffer;
	int tisRet;
	unsigned int size;

	pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
	
	if (pIoStackIrp)
	{
		writeBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

		if (writeBuffer)
		{
			size = ntohl(*(unsigned int *)&writeBuffer[2]);
			if (size > TPMMAX)
			{
				KdPrint(("DeviceWrite: malformed command blob, size > TPMMAX\n"));
				goto failure;
			}
			tisRet = TIS_Send(writeBuffer,size);
			if (tisRet == -1)
			{
				KdPrint(("DeviceWrite: TIS_Send returned -1, error\n"));
				goto failure;
			}
		}
	}

	Irp->IoStatus.Status = 1;
	Irp->IoStatus.Information = tisRet;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;

failure:
	Irp->IoStatus.Status = 0;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DeviceRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION pIoStackIrp;
	unsigned int dataRead;
	unsigned char *readBuffer;
	unsigned char *tpmResultBlob;
	
	pIoStackIrp = NULL;
    pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);

	tpmResultBlob = ExAllocatePool(NonPagedPool,TPMMAX);
	memset(tpmResultBlob,0x00,TPMMAX);

    TIS_WaitStatus(STS_DATA_AVAIL);
	
	dataRead = TIS_Recv(tpmResultBlob, TPMMAX);
	if (dataRead == 0)
	{
		KdPrint(("DeviceRead: TIS_Recv returned error: %d\n", dataRead));
		goto failure;
	} 
    
    if(pIoStackIrp && Irp->MdlAddress)
    {
        readBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, 
                                   NormalPagePriority);

        if (readBuffer == NULL || pIoStackIrp->Parameters.Read.Length < dataRead)
			goto failure;

		RtlCopyMemory(readBuffer, tpmResultBlob, dataRead);
    }

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = dataRead;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	ExFreePool(tpmResultBlob);
	return STATUS_SUCCESS;

failure:
	Irp->IoStatus.Status = -1;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	ExFreePool(tpmResultBlob);
	return STATUS_SUCCESS;
}

NTSTATUS DeviceUnsupportedFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	KdPrint(("DeviceUnsupportedFunction called\n"));
	return STATUS_SUCCESS;
}






