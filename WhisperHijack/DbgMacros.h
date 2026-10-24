// Copyright 2026 MalDev Academy
// WhisperHijack - Licensed under the Apache License, Version 2.0 (the "License")
// https://github.com/Maldev-Academy/WhisperHijack

#pragma once
#ifndef DEBUG_MACROS_H
#define DEBUG_MACROS_H

#include <Windows.h>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")


//                  //
//                  //
//                  //
//                  //
#define _DBG_FORCE
//                  //
//                  //
//                  //
//                  //


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#ifndef BUFFER_SIZE_2048
#define BUFFER_SIZE_2048        2048
#endif

#ifndef GET_FILENAMEA
#define GET_FILENAMEA(PATHA)   PathFindFileNameA(PATHA)
#endif

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#ifdef __cplusplus
extern "C" {
#endif

    VOID DbgWrite(LPCSTR pszFile, INT nLine, LPCSTR pszFmt, ...);

#ifdef __cplusplus
}
#endif

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#if defined(_DEBUG) || defined(_DBG_FORCE)
#define DBG(fmt, ...)       DbgWrite(GET_FILENAMEA(__FILE__), __LINE__, fmt, ##__VA_ARGS__)
#else
#define DBG(fmt, ...)       ((void)0)
#endif


#endif // !DEBUG_MACROS_H