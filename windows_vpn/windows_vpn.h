#pragma once

#ifdef WINDOWS_VPN_EXPORTS
#define WINDOWS_VPN_API __declspec(dllexport)
#else
#define WINDOWS_VPN_API __declspec(dllimport)
#endif

#include <windows.h>
#include <ras.h>
#include <raserror.h>
#include <iostream>

extern "C" WINDOWS_VPN_API int debug(int x, char* s);
extern "C" WINDOWS_VPN_API int create_profile(char* vpnEntryName, char* vpnServerAddress, char* username, char* password, char* pbkPath);
extern "C" WINDOWS_VPN_API int delete_profile();
extern "C" WINDOWS_VPN_API int connect_vpn(char* profileName, char* pbkPath);
extern "C" WINDOWS_VPN_API int disconnect_vpn(char* profileName);
extern "C" WINDOWS_VPN_API int status(char* profileName);