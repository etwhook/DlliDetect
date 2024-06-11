#include "./Detect/Detect.h"

VOID InitConsole() {
    FILE* conOut;
    AllocConsole();
    SetConsoleTitleA("DlliDetect");
    freopen_s(&conOut, "CONOUT$", "w", stdout);

}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpvReserved)
{

    if (fdwReason == DLL_PROCESS_ATTACH) {
        InitConsole();
        PrintInfo("DlliDetect Initializing...");
        SymInitialize(GetCurrentProcess(), NULL, TRUE);
        InitLdrInitializeThunkHook();
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        FreeConsole();
    }

    return TRUE;
}