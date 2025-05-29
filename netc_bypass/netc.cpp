#include "netc.h"
#include "sigscan.h"


// block shitty packets
bool __fastcall h_send_packet(void* pNet, void* edx, unsigned char ucPacketID, void* bitStream, int packetPriority, int packetReliability, int packetOrdering)
{
    if (ucPacketID == 33)
    {
        return true;
    }

    if (ucPacketID == 34 || ucPacketID == 91 || ucPacketID == 92 || ucPacketID == 93 || ucPacketID == 25)
    {
        return true;
    }



    if (!netc->c_net_manager)
    {
        netc->c_net_manager = pNet;
    }

    return netc->o_send_packet(pNet, ucPacketID, bitStream, packetPriority, packetReliability, packetOrdering);
}

// send your info to dutchman101
int __cdecl h_send_report(char ArgList, void* a2, int a3, int a4, int a5)
{
    return true;
}

// anti lua executor ( runtime ) bypass
typedef int(__thiscall* tSub_100CE380)(DWORD*, unsigned __int8); tSub_100CE380 oSub_100CE380;
int __fastcall hkSub_100CE380(DWORD* _this, void*, unsigned __int8 a2) {
    *(int*)(_this + 46) = 0;
    *(int*)(_this + 47) = 0;
    return oSub_100CE380(_this, a2);
}

void __fastcall h_send_report_2(int ecx, int ArgList, DWORD* a3, int a4, int a5, void* a6)
{
    return;
}

HANDLE __stdcall h_driver_send_report(LPCWSTR pszLogFileName, ACCESS_MASK fDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES psaLogFile, ULONG fCreateDisposition, ULONG fFlagsAndAttributes)
{
    return NULL;
}

// bypassing debuggers ( cheat engine, reclass.NET...)
void __fastcall h_client_kick(int ecx, int edx, unsigned int id, int argument4, DWORD* argument5, int argument6)
{
    return;
}

// kick you in local hostted game ( offline mode) 
void __fastcall h_local_kick(int ecx, char reason)
{
    return;
}
// Hook to suppress server-initiated custom kicks (e.g., from AntiCheat, reports, disconnect reasons).

void __fastcall h_client_ban(int ecx, int a2, int* client_id, int* reason, char ban_flags, int time)
{
    return;
}

typedef void(__thiscall* SendKickID_t)(int ECX, int EDX, int ID);
SendKickID_t oSendKickID = nullptr;
// anti cheat kicks, vf kicks, sd kicks
void __fastcall SendKickID(int ECX, int EDX, int ID)
{
    return;
}









typedef void(__thiscall* SendReportAndKick_t)(void** ECX, DWORD* Packet, int reportID);
SendReportAndKick_t oSendReportAndKick = nullptr;

void __fastcall SendReportAndKick(void** ECX, DWORD* Packet, int reportID)
{
    return;
}



bool c_netc::release()
{
    SigScan scan;
    DWORD Scan_Addres;

    MH_Initialize();

    o_send_report = (send_report_t)scan.FindPattern("netc.dll", "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x51\x56\xA1\x00\x00\x00\x00\x33\xC5\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x85\xC0\x75\x00\x68\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xF0\x33\xC0\x68\x00\x00\x00\x00\x83\xFE\x00\x8B\xCE\x6A\x00\x0F\x44\xC8\x51\xE8\x00\x00\x00\x00\x83\xC4\x00\x89\x75\x00\xC7\x45\x00\x00\x00\x00\x00\x85\xF6\x74\x00\x8B\xCE\xE8\x00\x00\x00\x00\xEB\x00\x33\xC0\xC7\x45\x00\x00\x00\x00\x00\xA3\x00\x00\x00\x00\xFF\x75\x00\x8B\xC8\xFF\x75\x00\xFF\x75\x00\xFF\x75\x00\xFF\x75\x00\xE8\x00\x00\x00\x00\xFF\x05", "xxxx?x????xx????xxxx????xxxxx?xx????x????xxx?x????x????xxxxx????xx?xxx?xxxxx????xx?xx?xx?????xxx?xxx????x?xxxx?????x????xx?xxxx?xx?xx?xx?x????xx");
    if (o_send_report != nullptr)
    {
        MH_CreateHook((LPVOID)o_send_report, &h_send_report, reinterpret_cast<LPVOID*>(&o_send_report));
        MH_EnableHook(MH_ALL_HOOKS);

    }



    o_send_packet = (send_packet_t)scan.FindPattern("netc.dll", "\x53\x8B\xDC\x83\xEC\x00\x83\xE4\x00\x83\xC4\x00\x55\x8B\x6B\x00\x89\x6C\x24\x00\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x53\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x56\x57\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\xF1\x89\xB5\x00\x00\x00\x00\x8B\x7B\x00\x89\xBD", "xxxxx?xx?xx?xxx?xxx?xxx?x????xx????xxxx????x????xxxx?xxxxx?xx????xxxx????xx?xx");
    if (o_send_packet != nullptr)
    {
        MH_CreateHook((LPVOID)o_send_packet, &h_send_packet, reinterpret_cast<LPVOID*>(&o_send_packet));
        MH_EnableHook(MH_ALL_HOOKS);

    }
    else
    {
    }

    o_client_ban = (client_ban_t)scan.FindPattern("netc.dll", "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x56\x57\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\xF1\x50\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\x58\x83\xBE", "xxxx?x????xx????xxx?x????xxxx?xxxxx?xx????xxxx????x????x????x????x????x????x????x????x????x????xxx");
    if (o_client_ban != nullptr)
    {
        MH_CreateHook((LPVOID)o_client_ban, &h_client_ban, reinterpret_cast<LPVOID*>(&o_client_ban));
        MH_EnableHook(MH_ALL_HOOKS);

    }

    o_driver_send_report = (driver_send_report_t)scan.FindPattern("netc.dll", "\xE8\x00\x00\x00\x00\x83\xC4\x00\xC7\x45\x00\x00\x00\x00\x00\x0F\x57\xC0\xC7\x45\x00\x00\x00\x00\x00\x8D\x4D\x00\x0F\x11\x45\x00\x6A\x00\x68\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xA1", "x????xx?xx?????xxxxx?????xx?xxx?x?x????x????x");
    if (o_driver_send_report != nullptr)
    {
        MH_CreateHook((LPVOID)o_driver_send_report, &h_driver_send_report, reinterpret_cast<LPVOID*>(&o_driver_send_report));
        MH_EnableHook(MH_ALL_HOOKS);

    }



    o_send_report_2 = (send_report_2_t)scan.FindPattern("netc.dll", "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x53\x56\x57\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\xF9\x50", "xxxx?x????xx????xxx????x????xxxx?xxxxxx?xx????xx");
    if (o_send_report_2 != nullptr)
    {
        MH_CreateHook((LPVOID)o_send_report_2, &h_send_report_2, reinterpret_cast<LPVOID*>(&o_send_report_2));
        MH_EnableHook(MH_ALL_HOOKS);

    }

    o_client_kick = (client_kick_t)scan.FindPattern("netc.dll", "\x53\x8B\xDC\x83\xEC\x00\x83\xE4\x00\x83\xC4\x00\x55\x8B\x6B\x00\x89\x6C\x24\x00\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x53\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x56\x57\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\xF1\x89\xB5\x00\x00\x00\x00\x50\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\x58\x8B\x0D", "xxxxx?xx?xx?xxx?xxx?xxx?x????xx????xxxx????x????xxxx?xxxxx?xx????xxxx????xx????x????x????x????x????x????x????x????x????x????xxx");
    if (o_client_kick != nullptr)
    {
        MH_CreateHook((LPVOID)o_client_kick, &h_client_kick, reinterpret_cast<LPVOID*>(&o_client_kick));
        MH_EnableHook(MH_ALL_HOOKS);

    }

    o_local_kick = (local_kick_t)scan.FindPattern("netc.dll", "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x56\x57\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\xF9\x89\x7D\x00\x50\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\x58\xE8", "xxxx?x????xx????xxx????x????xxxx?xxxxx?xx????xxxx?xx????x????x????x????x????x????x????x????x????x????xx");
    if (o_local_kick != nullptr)
    {
        MH_CreateHook((LPVOID)o_local_kick, &h_local_kick, reinterpret_cast<LPVOID*>(&o_local_kick));
        MH_EnableHook(MH_ALL_HOOKS);

    }

    printf("Anti Cheat Hooked sucessfuly!");

    return true;
}


