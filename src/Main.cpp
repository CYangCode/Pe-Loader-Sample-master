#include "PeLdr.h"
#include "Debug.h"
#include "PEB.h"

static
INT ShowUsage()
{
	printf("-- PE Loader Sample --\n\n");
	printf("PeLdr [PE-File]\n");
	printf("\n");

	return 0;
}

int GetPathByFile(TCHAR * pExePath)
{
	FILE * fp = fopen("./path.txt", "r");

	if (!fp)
		return -1;
	
	fseek(fp, FILE_END, 0);
	int size = ftell(fp); 
	fread(pExePath, sizeof(TCHAR), size, fp);

	return 0;
}

int wmain(int argc, wchar_t *argv[])
{
	PE_LDR_PARAM peLdr;
	//TCHAR pExePath[MAX_PATH] = { 0 };

	//GetPathByFile(pExePath);

	PeLdrInit(&peLdr);
	PeLdrSetExecutablePath(&peLdr, L"1.exe");
	PeLdrStart(&peLdr);

	return 0;
}

//
//int UnmapViewOfSection(HANDLE hProcess, LPVOID dwLoaderBase)
//{
//	NTSTATUS(NTAPI *NtUnmapViewOfSection)
//		(HANDLE, LPVOID) = NULL;
//
//	static HANDLE hLib = LoadLibraryA("ntdll.dll");
//
//	NtUnmapViewOfSection =
//		(NTSTATUS(NTAPI *)(HANDLE, LPVOID))
//		GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "ZwUnmapViewOfSection");
//	if (!NtUnmapViewOfSection)
//		DMSG("Failed to resolve address of NtUnmapViewOfSection");
//	return NtUnmapViewOfSection(hProcess, dwLoaderBase);
//}
//
//int WritePEImageToTgtProcess(HANDLE hProcess, LPVOID lpTgtProcBaseAddr, PE_LDR_PARAM * pPeLdr)
//{
//	// 拷贝headers
//	WriteProcessMemory(hProcess, lpTgtProcBaseAddr, (LPVOID)pPeLdr->dwLoaderBase, pPeLdr->pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);
//
//	// 拷贝sections
//	LPVOID lpSectionBaseAddr = (LPVOID)((DWORD)pPeLdr->dwLoaderBase + pPeLdr->pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
//	PIMAGE_SECTION_HEADER pSectionHeader;
//	for (int idx = 0; idx < pPeLdr->pNtHeaders->FileHeader.NumberOfSections; ++idx) {
//		pSectionHeader = (PIMAGE_SECTION_HEADER)lpSectionBaseAddr;
//		WriteProcessMemory(hProcess,
//			(LPVOID)((DWORD)lpTgtProcBaseAddr + pSectionHeader->VirtualAddress),
//			(LPCVOID)((DWORD)lpTgtProcBaseAddr + pSectionHeader->PointerToRawData),
//			pSectionHeader->SizeOfRawData,
//			NULL);
//		lpSectionBaseAddr = (LPVOID)((DWORD)lpSectionBaseAddr + sizeof(IMAGE_SECTION_HEADER));
//	}
//
//	return 0;
//}
//
//int ProcessReplace()
//{
//	CONTEXT context;
//	_PEB tgtPEB;
//	STARTUPINFOA si;
//	PROCESS_INFORMATION pi;
//	PE_LDR_PARAM peLdr;
//	char szTgtExePath[MAX_PATH];
//	
//	do {
//		// 获得svchost的路径
//		memset(szTgtExePath, 0, MAX_PATH);
//		GetSystemDirectoryA(szTgtExePath, MAX_PATH);
//		strcat_s(szTgtExePath, "\\svchost.exe");
//		DMSG("Get svchost path: %s", szTgtExePath);
//
//		// 以挂起状态打开程序
//		memset(&si, 0, sizeof(STARTUPINFOA));
//		memset(&pi, 0, sizeof(PROCESS_INFORMATION));
//		if (CreateProcessA(".\\ResourceHacker.exe", 0, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi) == 0) {
//			EMSG("Create Proecss failed!");
//			break;
//		}
//		DMSG("Create Proecss success!");
//
//		// 获取线程上下文
//		context.ContextFlags = CONTEXT_FULL;
//		if (GetThreadContext(pi.hThread, &context) == 0) {
//			EMSG("Get thread context failed!");
//			break;
//		}
//		DMSG("Get thread context success!");
//
//		// 释放进程内存
//		ReadProcessMemory(pi.hProcess, (LPCVOID)context.Ebx, &tgtPEB, sizeof(_PEB), 0);//此时context中EBX指向PEB的指针
//		if (UnmapViewOfSection(pi.hProcess, (LPVOID)tgtPEB.lpImageBaseAddress) != 0) {
//			EMSG("Unmap target process sections failed");
//			break;
//		}
//		DMSG("Unmap target process sections success!");
//
//		// 载入PE镜像
//		PeLdrInit(&peLdr);
//		PeLdrSetExecutablePath(&peLdr, L"ConsoleApplication1.exe");
//		PeLdrLoadImage(&peLdr);
//
//		// 将pe镜像写入目标进程
//		WritePEImageToTgtProcess(pi.hProcess, (LPVOID)tgtPEB.lpImageBaseAddress, &peLdr);
//
//		// 通过context中EBX修改目标进程的PEB
//		DWORD dwImageBase = peLdr.pNtHeaders->OptionalHeader.ImageBase;
//		WriteProcessMemory(pi.hProcess, (LPVOID)(context.Ebx + 8), (LPCVOID)&dwImageBase, sizeof(PVOID), NULL);
//		
//		// 设置上下文, 并启动主线程
//		context.Eax = dwImageBase + peLdr.pNtHeaders->OptionalHeader.AddressOfEntryPoint;
//		SetThreadContext(pi.hThread, &context);
//		ResumeThread(pi.hThread);
//		break;
//
//	} while (1);
//	
//
//	system("pause");
//	return 0;
//
//}