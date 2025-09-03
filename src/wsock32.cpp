// https://github.com/TkYu/HijackMaker

#include <windows.h>
#include <intrin.h>
#include <stdint.h>

namespace hijack
{


#define NOP_FUNC { \
    __nop();\
    __nop();\
    __nop();\
    __nop();\
    __nop();\
    __nop();\
    __nop();\
    __nop();\
    __nop();\
    __nop();\
    __nop();\
    __nop();\
    return __COUNTER__;\
}
// 用 __COUNTER__ 来生成一点不一样的代码，避免被 VS 自动合并相同函数


#define EXPORT(api) int __cdecl api() NOP_FUNC


// 声明导出函数
/*
#pragma comment(linker, "/export:accept=?accept@hijack@@YAHXZ,@1")
#pragma comment(linker, "/export:bind=?bind@hijack@@YAHXZ,@2")
#pragma comment(linker, "/export:closesocket=?closesocket@hijack@@YAHXZ,@3")
#pragma comment(linker, "/export:connect=?connect@hijack@@YAHXZ,@4")
#pragma comment(linker, "/export:getpeername=?getpeername@hijack@@YAHXZ,@5")
#pragma comment(linker, "/export:getsockname=?getsockname@hijack@@YAHXZ,@6")
#pragma comment(linker, "/export:getsockopt=?getsockopt@hijack@@YAHXZ,@7")
#pragma comment(linker, "/export:htonl=?htonl@hijack@@YAHXZ,@8")
#pragma comment(linker, "/export:htons=?htons@hijack@@YAHXZ,@9")
#pragma comment(linker, "/export:inet_addr=?inet_addr@hijack@@YAHXZ,@10")
#pragma comment(linker, "/export:inet_ntoa=?inet_ntoa@hijack@@YAHXZ,@11")
#pragma comment(linker, "/export:ioctlsocket=?ioctlsocket@hijack@@YAHXZ,@12")
#pragma comment(linker, "/export:listen=?listen@hijack@@YAHXZ,@13")
#pragma comment(linker, "/export:ntohl=?ntohl@hijack@@YAHXZ,@14")
#pragma comment(linker, "/export:ntohs=?ntohs@hijack@@YAHXZ,@15")
#pragma comment(linker, "/export:recv=?recv@hijack@@YAHXZ,@16")
#pragma comment(linker, "/export:recvfrom=?recvfrom@hijack@@YAHXZ,@17")
#pragma comment(linker, "/export:select=?select@hijack@@YAHXZ,@18")
#pragma comment(linker, "/export:send=?send@hijack@@YAHXZ,@19")
#pragma comment(linker, "/export:sendto=?sendto@hijack@@YAHXZ,@20")
#pragma comment(linker, "/export:setsockopt=?setsockopt@hijack@@YAHXZ,@21")
#pragma comment(linker, "/export:shutdown=?shutdown@hijack@@YAHXZ,@22")
#pragma comment(linker, "/export:socket=?socket@hijack@@YAHXZ,@23")
#pragma comment(linker, "/export:MigrateWinsockConfiguration=?MigrateWinsockConfiguration@hijack@@YAHXZ,@24")
#pragma comment(linker, "/export:gethostbyaddr=?gethostbyaddr@hijack@@YAHXZ,@51")
#pragma comment(linker, "/export:gethostbyname=?gethostbyname@hijack@@YAHXZ,@52")
#pragma comment(linker, "/export:getprotobyname=?getprotobyname@hijack@@YAHXZ,@53")
#pragma comment(linker, "/export:getprotobynumber=?getprotobynumber@hijack@@YAHXZ,@54")
#pragma comment(linker, "/export:getservbyname=?getservbyname@hijack@@YAHXZ,@55")
#pragma comment(linker, "/export:getservbyport=?getservbyport@hijack@@YAHXZ,@56")
#pragma comment(linker, "/export:gethostname=?gethostname@hijack@@YAHXZ,@57")
#pragma comment(linker, "/export:WSAAsyncSelect=?WSAAsyncSelect@hijack@@YAHXZ,@101")
#pragma comment(linker, "/export:WSAAsyncGetHostByAddr=?WSAAsyncGetHostByAddr@hijack@@YAHXZ,@102")
#pragma comment(linker, "/export:WSAAsyncGetHostByName=?WSAAsyncGetHostByName@hijack@@YAHXZ,@103")
#pragma comment(linker, "/export:WSAAsyncGetProtoByNumber=?WSAAsyncGetProtoByNumber@hijack@@YAHXZ,@104")
#pragma comment(linker, "/export:WSAAsyncGetProtoByName=?WSAAsyncGetProtoByName@hijack@@YAHXZ,@105")
#pragma comment(linker, "/export:WSAAsyncGetServByPort=?WSAAsyncGetServByPort@hijack@@YAHXZ,@106")
#pragma comment(linker, "/export:WSAAsyncGetServByName=?WSAAsyncGetServByName@hijack@@YAHXZ,@107")
#pragma comment(linker, "/export:WSACancelAsyncRequest=?WSACancelAsyncRequest@hijack@@YAHXZ,@108")
#pragma comment(linker, "/export:WSASetBlockingHook=?WSASetBlockingHook@hijack@@YAHXZ,@109")
#pragma comment(linker, "/export:WSAUnhookBlockingHook=?WSAUnhookBlockingHook@hijack@@YAHXZ,@110")
#pragma comment(linker, "/export:WSAGetLastError=?WSAGetLastError@hijack@@YAHXZ,@111")
#pragma comment(linker, "/export:WSASetLastError=?WSASetLastError@hijack@@YAHXZ,@112")
#pragma comment(linker, "/export:WSACancelBlockingCall=?WSACancelBlockingCall@hijack@@YAHXZ,@113")
#pragma comment(linker, "/export:WSAIsBlocking=?WSAIsBlocking@hijack@@YAHXZ,@114")
#pragma comment(linker, "/export:WSAStartup=?WSAStartup@hijack@@YAHXZ,@115")
#pragma comment(linker, "/export:WSACleanup=?WSACleanup@hijack@@YAHXZ,@116")
#pragma comment(linker, "/export:__WSAFDIsSet=?__WSAFDIsSet@hijack@@YAHXZ,@151")
#pragma comment(linker, "/export:WEP=?WEP@hijack@@YAHXZ,@500")
#pragma comment(linker, "/export:WSApSetPostRoutine=?WSApSetPostRoutine@hijack@@YAHXZ,@1000")
#pragma comment(linker, "/export:inet_network=?inet_network@hijack@@YAHXZ,@1100")
#pragma comment(linker, "/export:getnetbyname=?getnetbyname@hijack@@YAHXZ,@1101")
#pragma comment(linker, "/export:rcmd=?rcmd@hijack@@YAHXZ,@1102")
#pragma comment(linker, "/export:rexec=?rexec@hijack@@YAHXZ,@1103")
#pragma comment(linker, "/export:rresvport=?rresvport@hijack@@YAHXZ,@1104")
#pragma comment(linker, "/export:sethostname=?sethostname@hijack@@YAHXZ,@1105")
#pragma comment(linker, "/export:dn_expand=?dn_expand@hijack@@YAHXZ,@1106")
#pragma comment(linker, "/export:WSARecvEx=?WSARecvEx@hijack@@YAHXZ,@1107")
#pragma comment(linker, "/export:s_perror=?s_perror@hijack@@YAHXZ,@1108")
#pragma comment(linker, "/export:GetAddressByNameA=?GetAddressByNameA@hijack@@YAHXZ,@1109")
#pragma comment(linker, "/export:GetAddressByNameW=?GetAddressByNameW@hijack@@YAHXZ,@1110")
#pragma comment(linker, "/export:EnumProtocolsA=?EnumProtocolsA@hijack@@YAHXZ,@1111")
#pragma comment(linker, "/export:EnumProtocolsW=?EnumProtocolsW@hijack@@YAHXZ,@1112")
#pragma comment(linker, "/export:GetTypeByNameA=?GetTypeByNameA@hijack@@YAHXZ,@1113")
#pragma comment(linker, "/export:GetTypeByNameW=?GetTypeByNameW@hijack@@YAHXZ,@1114")
#pragma comment(linker, "/export:GetNameByTypeA=?GetNameByTypeA@hijack@@YAHXZ,@1115")
#pragma comment(linker, "/export:GetNameByTypeW=?GetNameByTypeW@hijack@@YAHXZ,@1116")
#pragma comment(linker, "/export:SetServiceA=?SetServiceA@hijack@@YAHXZ,@1117")
#pragma comment(linker, "/export:SetServiceW=?SetServiceW@hijack@@YAHXZ,@1118")
#pragma comment(linker, "/export:GetServiceA=?GetServiceA@hijack@@YAHXZ,@1119")
#pragma comment(linker, "/export:GetServiceW=?GetServiceW@hijack@@YAHXZ,@1120")
#pragma comment(linker, "/export:NPLoadNameSpaces=?NPLoadNameSpaces@hijack@@YAHXZ,@1130")
#pragma comment(linker, "/export:TransmitFile=?TransmitFile@hijack@@YAHXZ,@1140")
#pragma comment(linker, "/export:AcceptEx=?AcceptEx@hijack@@YAHXZ,@1141")
#pragma comment(linker, "/export:GetAcceptExSockaddrs=?GetAcceptExSockaddrs@hijack@@YAHXZ,@1142")
*/
EXPORT(accept)
EXPORT(bind)
EXPORT(closesocket)
EXPORT(connect)
EXPORT(getpeername)
EXPORT(getsockname)
EXPORT(getsockopt)
EXPORT(htonl)
EXPORT(htons)
EXPORT(inet_addr)
EXPORT(inet_ntoa)
EXPORT(ioctlsocket)
EXPORT(listen)
EXPORT(ntohl)
EXPORT(ntohs)
EXPORT(recv)
EXPORT(recvfrom)
EXPORT(select)
EXPORT(send)
EXPORT(sendto)
EXPORT(setsockopt)
EXPORT(shutdown)
EXPORT(socket)
EXPORT(MigrateWinsockConfiguration)
EXPORT(gethostbyaddr)
EXPORT(gethostbyname)
EXPORT(getprotobyname)
EXPORT(getprotobynumber)
EXPORT(getservbyname)
EXPORT(getservbyport)
EXPORT(gethostname)
EXPORT(WSAAsyncSelect)
EXPORT(WSAAsyncGetHostByAddr)
EXPORT(WSAAsyncGetHostByName)
EXPORT(WSAAsyncGetProtoByNumber)
EXPORT(WSAAsyncGetProtoByName)
EXPORT(WSAAsyncGetServByPort)
EXPORT(WSAAsyncGetServByName)
EXPORT(WSACancelAsyncRequest)
EXPORT(WSASetBlockingHook)
EXPORT(WSAUnhookBlockingHook)
EXPORT(WSAGetLastError)
EXPORT(WSASetLastError)
EXPORT(WSACancelBlockingCall)
EXPORT(WSAIsBlocking)
EXPORT(WSAStartup)
EXPORT(WSACleanup)
EXPORT(__WSAFDIsSet)
EXPORT(WEP)
EXPORT(WSApSetPostRoutine)
EXPORT(inet_network)
EXPORT(getnetbyname)
EXPORT(rcmd)
EXPORT(rexec)
EXPORT(rresvport)
EXPORT(sethostname)
EXPORT(dn_expand)
EXPORT(WSARecvEx)
EXPORT(s_perror)
EXPORT(GetAddressByNameA)
EXPORT(GetAddressByNameW)
EXPORT(EnumProtocolsA)
EXPORT(EnumProtocolsW)
EXPORT(GetTypeByNameA)
EXPORT(GetTypeByNameW)
EXPORT(GetNameByTypeA)
EXPORT(GetNameByTypeW)
EXPORT(SetServiceA)
EXPORT(SetServiceW)
EXPORT(GetServiceA)
EXPORT(GetServiceW)
EXPORT(NPLoadNameSpaces)
EXPORT(TransmitFile)
EXPORT(AcceptEx)
EXPORT(GetAcceptExSockaddrs)
}

bool WriteMemory(PBYTE BaseAddress, PBYTE Buffer, DWORD nSize)
{
    DWORD ProtectFlag = 0;
    if (VirtualProtectEx(GetCurrentProcess(), BaseAddress, nSize, PAGE_EXECUTE_READWRITE, &ProtectFlag))
    {
        memcpy(BaseAddress, Buffer, nSize);
        FlushInstructionCache(GetCurrentProcess(), BaseAddress, nSize);
        VirtualProtectEx(GetCurrentProcess(), BaseAddress, nSize, ProtectFlag, &ProtectFlag);
        return true;
    }
    return false;
}

// 还原导出函数
void InstallJMP(PBYTE BaseAddress, uintptr_t Function)
{
    if (*BaseAddress == 0xE9)
    {
        BaseAddress++;
        BaseAddress = BaseAddress + *(uint32_t*)BaseAddress + 4;
    }
    if (*BaseAddress != 0x90)
    {
        return;
    }
#ifdef _WIN64
    BYTE move[] = {0x48, 0xB8};//move rax,xxL);
    BYTE jump[] = {0xFF, 0xE0};//jmp rax

    WriteMemory(BaseAddress, move, sizeof(move));
    BaseAddress += sizeof(move);

    WriteMemory(BaseAddress, (PBYTE)&Function, sizeof(uintptr_t));
    BaseAddress += sizeof(uintptr_t);

    WriteMemory(BaseAddress, jump, sizeof(jump));
#else
    BYTE jump[] = {0xE9};
    WriteMemory(BaseAddress, jump, sizeof(jump));
    BaseAddress += sizeof(jump);

    uintptr_t offset = Function - (uintptr_t)BaseAddress - 4;
    WriteMemory(BaseAddress, (PBYTE)&offset, sizeof(offset));
#endif // _WIN64
}

void LoadWsock32(HINSTANCE hModule)
{
    PBYTE pImageBase = (PBYTE)hModule;
    PIMAGE_DOS_HEADER pimDH = (PIMAGE_DOS_HEADER)pImageBase;
    if (pimDH->e_magic == IMAGE_DOS_SIGNATURE)
    {
        PIMAGE_NT_HEADERS pimNH = (PIMAGE_NT_HEADERS)(pImageBase + pimDH->e_lfanew);
        if (pimNH->Signature == IMAGE_NT_SIGNATURE)
        {
            PIMAGE_EXPORT_DIRECTORY pimExD = (PIMAGE_EXPORT_DIRECTORY)(pImageBase + pimNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
            DWORD*  pName = (DWORD*)(pImageBase + pimExD->AddressOfNames);
            DWORD*  pFunction = (DWORD*)(pImageBase + pimExD->AddressOfFunctions);
            WORD*  pNameOrdinals = (WORD*)(pImageBase + pimExD->AddressOfNameOrdinals);

            wchar_t szSysDirectory[MAX_PATH + 1];
            GetSystemDirectory(szSysDirectory, MAX_PATH);

            wchar_t szDLLPath[MAX_PATH + 1];
            lstrcpy(szDLLPath, szSysDirectory);
            lstrcat(szDLLPath, TEXT("\\wsock32.dll"));

            HINSTANCE module = LoadLibrary(szDLLPath);
            for (size_t i = 0; i < pimExD->NumberOfNames; i++)
            {
                uintptr_t Original = (uintptr_t)GetProcAddress(module, (char*)(pImageBase + pName[i]));
                if (Original)
                {
                    InstallJMP(pImageBase + pFunction[pNameOrdinals[i]], Original);
                }
            }
        }
    }
}

extern "C" void LoadSysDll(HINSTANCE hModule)
{
    LoadWsock32(hModule);
}
