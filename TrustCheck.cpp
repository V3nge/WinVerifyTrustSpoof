// Taken from Microsoft Documentation
// https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust

#define _UNICODE 1
#define UNICODE 1

#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#pragma comment (lib, "wintrust")

BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
{
    LONG lStatus;
    DWORD dwLastError;

    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = pwszSourceFile;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;

    memset(&WinTrustData, 0, sizeof(WinTrustData));

    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.pPolicyCallbackData = NULL;
    WinTrustData.pSIPClientData = NULL;
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.hWVTStateData = NULL;
    WinTrustData.pwszURLReference = NULL;
    WinTrustData.dwUIContext = 0;
    WinTrustData.pFile = &FileData;

    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    switch (lStatus)
    {
    case ERROR_SUCCESS:
        wprintf_s(L"The file \"%s\" is signed and the signature "
            L"was verified.\n",
            pwszSourceFile);
        break;

    case TRUST_E_NOSIGNATURE:
        dwLastError = GetLastError();
        if (TRUST_E_NOSIGNATURE == dwLastError ||
            TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
            TRUST_E_PROVIDER_UNKNOWN == dwLastError)
        {
            wprintf_s(L"The file \"%s\" is not signed.\n",
                pwszSourceFile);
        }
        else
        {
            wprintf_s(L"An unknown error occurred trying to "
                L"verify the signature of the \"%s\" file.\n",
                pwszSourceFile);
        }

        break;

    case TRUST_E_EXPLICIT_DISTRUST:
        wprintf_s(L"The signature is present, but specifically "
            L"disallowed.\n");
        break;

    case TRUST_E_SUBJECT_NOT_TRUSTED:
        wprintf_s(L"The signature is present, but not "
            L"trusted.\n");
        break;

    case CRYPT_E_SECURITY_SETTINGS:
        wprintf_s(L"CRYPT_E_SECURITY_SETTINGS - The hash "
            L"representing the subject or the publisher wasn't "
            L"explicitly trusted by the admin and admin policy "
            L"has disabled user trust. No signature, publisher "
            L"or timestamp errors.\n");
        break;

    default:
        wprintf_s(L"Error is: 0x%x.\n",
            lStatus);
        break;
    }
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    return true;
}

int _tmain(int argc, _TCHAR* argv[])
{
    if (argc > 1)
    {
        while (true)
        {
            VerifyEmbeddedSignature(argv[1]);
            Sleep(3000);
        }
    }

    return 0;
}