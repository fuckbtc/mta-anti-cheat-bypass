#include <Windows.h>
#include <thread>
#include "netc.h"
void initBypass()
{
    AllocConsole(); // debug
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);

    netc->release();
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)initBypass, hModule, NULL, NULL); // using createthread so we can use our mainthread to make the cheat

        break;
    }
    return TRUE;
}

