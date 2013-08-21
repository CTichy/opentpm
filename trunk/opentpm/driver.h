#ifndef _DRIVER_H_
#define _DRIVER_H_

#define DEVICE_NAME L"\\Device\\OPENTPM"
#define DOS_DEVICE_NAME L"\\DosDevices\\OPENTPM"
#define GENERIC_ERROR -1

extern PVOID gTPMLinearAddress;
extern SIZE_T gTPMRegisterSize;
extern int gLocality;

VOID OnUnload(IN PDRIVER_OBJECT DriverObject);
NTSTATUS DeviceWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DeviceRead(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DeviceUnsupportedFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp);

#endif
