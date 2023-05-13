#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void* reserved) {
  if (reason == DLL_PROCESS_ATTACH) {
    MessageBoxW(nullptr, L"Dll injected!", L"Apc2Dll", MB_OK);
  }
  return true;
}