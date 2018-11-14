#include "AuthUnesp.h"
#include "guid.h"

#include <WinHttp.h>
#include <Shlwapi.h>
#include <Strsafe.h>

#pragma comment(lib, "winhttp.lib")

LPSTR ConvertToUtf8(PWSTR pwsz, int cpwsz)
{
    int buf_size = cpwsz + 1;
    LPSTR buf = new char[buf_size];
    int size = WideCharToMultiByte(CP_UTF8, 0, pwsz, buf_size, buf, buf_size, NULL, NULL);
    if (size <= 0)
    {
        SecureZeroMemory(buf, cpwsz);
        delete buf;
        return NULL;
    }
    else
    {
        return buf;
    }
}

int CountUnsafeCharactes(LPCSTR string)
{
    int count = 0;
    for (int i = 0; i < lstrlenA(string); i++)
    {
        switch (string[i])
        {
        case '^':
        case '&':
        case '`':
        case '{':
        case '}':
        case '|':
        case ']':
        case '[':
        case '"':
        case '<':
        case '>':
        case '@':
        case '\\':
            count++;
        }
    }
    return count;
}

HRESULT ServiceAuth(PWSTR pwszUsername, PWSTR pwszPassword)
{
    HKEY hKey;
    LONG lRes;
    WCHAR server[512];
    BOOL bResults = FALSE;
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    HRESULT h = S_OK;

    int cpwszUsername = lstrlenW(pwszUsername);
    int cpwszPassword = lstrlenW(pwszPassword);
    LPSTR lpszUsername = ConvertToUtf8(pwszUsername, cpwszUsername);
    LPSTR lpszPassword = ConvertToUtf8(pwszPassword, cpwszPassword);

    DWORD clpszUsernameEscaped = 0;
    DWORD clpszPasswordEscaped = 0;
    LPSTR lpszUsernameEscaped = NULL;
    LPSTR lpszPasswordEscaped = NULL;
    char temp[1024];

    if (lpszUsername)
    {
        clpszUsernameEscaped = cpwszUsername + CountUnsafeCharactes(lpszUsername) * 2 + 1;
        lpszUsernameEscaped = new char[clpszUsernameEscaped];
    }
    if (lpszPassword)
    {
        clpszPasswordEscaped = cpwszPassword + CountUnsafeCharactes(lpszPassword) * 2 + 1;
        lpszPasswordEscaped = new char[clpszPasswordEscaped];
    }
    if (!lpszUsername || !lpszPassword)
    {
        h = S_FALSE;
        MessageBox(NULL, "Erro convertendo usuário e/ou senha", NULL, MB_OK);
    }
    if (SUCCEEDED(h))
    {
        h = UrlEscapeA(lpszUsername, lpszUsernameEscaped, &clpszUsernameEscaped, URL_ESCAPE_SEGMENT_ONLY);
    }
    if (FAILED(h))
    {
        MessageBox(NULL, "Erro codificando usuário", NULL, MB_OK);
    }
    if (SUCCEEDED(h))
    {
        h = UrlEscapeA(lpszPassword, lpszPasswordEscaped, &clpszPasswordEscaped, URL_ESCAPE_SEGMENT_ONLY);
    }
    if (FAILED(h))
    {
        MessageBox(NULL, "Erro codificando senha", NULL, MB_OK);
    }
    DWORD data_size = 0;
    LPSTR data = NULL;
    if (SUCCEEDED(h))
    {
        data_size = 20 + clpszUsernameEscaped + clpszPasswordEscaped;
        data = new char[data_size];
        data[0] = '\0';
        h = StringCchCatA(data, data_size, "username=");
    }
    if (FAILED(h))
    {
        MessageBox(NULL, "Erro gerando dados com usuário", NULL, MB_OK);
    }
    if (SUCCEEDED(h))
    {
        h = StringCchCatA(data, data_size, lpszUsernameEscaped);
    }
    if (FAILED(h))
    {
        MessageBox(NULL, "Erro gerando dados com usuário [2]", NULL, MB_OK);
    }
    if (SUCCEEDED(h))
    {
        h = StringCchCatA(data, data_size, "&password=");
    }
    if (FAILED(h))
    {
        MessageBox(NULL, "Erro gerando dados com senha", NULL, MB_OK);
    }
    if (SUCCEEDED(h))
    {
        h = StringCchCatA(data, data_size, lpszPasswordEscaped);
    }
    if (FAILED(h))
    {
        MessageBox(NULL, "Erro gerando dados com senha [2]", NULL, MB_OK);
    }
    if (FAILED(h))
    {
        MessageBox(NULL, "Erro gerando dados com fim de linha", NULL, MB_OK);
    }

    lRes = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{BEF82F88-BABB-47BB-B819-39E68277019E}", 0, KEY_QUERY_VALUE, &hKey);
    if (SUCCEEDED(h) && lRes == ERROR_SUCCESS)
    {
        DWORD dwKeyDataType;
        DWORD dwDataBufSize = 512;
        lRes = RegQueryValueExW(hKey, L"URL", NULL, &dwKeyDataType, (LPBYTE)&server, &dwDataBufSize);
        RegCloseKey(hKey);
    }
    else
    {
        MessageBox(NULL, "Erro abrindo registro", NULL, MB_OK);
    }
    if (SUCCEEDED(h) && lRes == ERROR_SUCCESS)
    {
        hSession = WinHttpOpen(L"AuthUnesp",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
    }
    if (hSession == NULL)
    {
        char buf[1024];
        snprintf(buf, 1024, "Erro WinHttpOpen: %u", GetLastError());
        MessageBox(NULL, "Erro WinHttpOpen", NULL, MB_OK);
        MessageBox(NULL, buf, NULL, MB_OK);
    }
    if (SUCCEEDED(h) && hSession)
    {
        hConnect = WinHttpConnect(hSession, server, INTERNET_DEFAULT_HTTPS_PORT, 0);
    }
    if (hConnect == NULL)
    {
        MessageBox(NULL, "Erro WinHttpConnect", NULL, MB_OK);
    }
    if (SUCCEEDED(h) && hConnect)
    {
        hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/login", NULL,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    }
    if (hRequest == NULL)
    {
        MessageBox(NULL, "Erro WinHttpOpenRequest", NULL, MB_OK);
    }
    if (SUCCEEDED(h) && hRequest)
    {
        bResults = WinHttpSendRequest(hRequest, L"Content-Type: application/x-www-form-urlencoded", 47,
            data, data_size - 1, data_size - 1, 0);
    }
    if (!bResults)
    {
        MessageBox(NULL, "Erro WinHttpSendRequest", NULL, MB_OK);
        snprintf(temp, 1024, "Erro WinHttpSendRequest: %d", GetLastError());
        MessageBox(NULL, temp, NULL, MB_OK);
    }
    if (SUCCEEDED(h) && !bResults)
    {
        h = E_FAIL;
        MessageBox(NULL, "Falhou", NULL, MB_OK);
    }
    if (hRequest)
    {
        WinHttpCloseHandle(hRequest);
    }
    if (hConnect)
    {
        WinHttpCloseHandle(hConnect);
    }
    if (hSession)
    {
        WinHttpCloseHandle(hSession);
    }
    if (lpszUsername)
    {
        delete lpszUsername;
    }
    if (lpszPassword)
    {
        SecureZeroMemory(lpszPassword, cpwszPassword);
        delete lpszPassword;
    }
    if (lpszUsernameEscaped)
    {
        delete lpszUsernameEscaped;
    }
    if (lpszPasswordEscaped)
    {
        SecureZeroMemory(lpszPasswordEscaped, clpszPasswordEscaped);
        delete lpszPasswordEscaped;
    }
    if (data)
    {
        SecureZeroMemory(data, data_size);
        delete data;
    }
    if (SUCCEEDED(h))
    {
        MessageBox(NULL, "Successo", NULL, MB_OK);
    }
    return h;
}
