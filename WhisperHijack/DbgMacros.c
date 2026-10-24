// Copyright 2026 MalDev Academy
// WhisperHijack - Licensed under the Apache License, Version 2.0 (the "License")
// https://github.com/Maldev-Academy/WhisperHijack

#include "DbgMacros.h"


VOID DbgWrite(LPCSTR pszFile, INT nLine, LPCSTR pszFmt, ...)
{
    DWORD       dwSavedError                = 0x00;
    INT         cchWritten                  = 0x00;
    CHAR        szBuffer[BUFFER_SIZE_2048]  = { 0 };
    va_list     pszVaArgs                   = NULL;

    // Capture the caller's last error before running our logic
    dwSavedError = GetLastError();

    va_start(pszVaArgs, pszFmt);
    cchWritten = wvsprintfA(szBuffer, pszFmt, pszVaArgs);
    va_end(pszVaArgs);

    if (cchWritten < 0)
        goto _END_OF_FUNC;

    // Append file and line tag if there's room
    if (cchWritten < BUFFER_SIZE_2048 - 1)
        wsprintfA(szBuffer + cchWritten, "     [%s:%d]\n", pszFile, nLine);
    else
    {
        // Message was too long. Add '...\n\0'
        szBuffer[BUFFER_SIZE_2048 - 5] = '.';
        szBuffer[BUFFER_SIZE_2048 - 4] = '.';
        szBuffer[BUFFER_SIZE_2048 - 3] = '.';
        szBuffer[BUFFER_SIZE_2048 - 2] = '\n';
        szBuffer[BUFFER_SIZE_2048 - 1] = '\0';
    }

    OutputDebugStringA(szBuffer);

_END_OF_FUNC:
    // Restore caller's last error 
    SetLastError(dwSavedError);
}