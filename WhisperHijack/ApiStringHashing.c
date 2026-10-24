// Copyright 2026 MalDev Academy
// WhisperHijack - Licensed under the Apache License, Version 2.0 (the "License")
// https://github.com/Maldev-Academy/WhisperHijack

#include "ResolveAPIs.h"


#define INITIAL_HASH		0xFFFFFFFF		// Standard CRC32 initial value (all bits set)
#define CRC_POLYNOMIAL		0xEDB88320		// Reversed CRC-32/ISO-HDLC polynomial (canonical Crc32b)
 

// Generate Crc32b hashes from Ascii input string
UINT32 HashStringCrc32bA(IN PCHAR pszString) 
{
	UINT32	uHash		= INITIAL_HASH;
	SIZE_T	cbIndex		= 0x00;
	SIZE_T	cbLength	= (SIZE_T)lstrlenA(pszString);
 
	while (cbIndex != cbLength)
	{
		uHash ^= (BYTE)pszString[cbIndex++];
 
		for (INT i = 0; i < 8; i++)
			uHash = (uHash >> 1) ^ (CRC_POLYNOMIAL & (0 - (uHash & 1)));
	}
 
	return ~uHash;
}


// Generate Crc32b hashes from an ANSI input string, case-insensitive 
UINT32 HashIStringCrc32bA(IN PCHAR pszString)
{
	UINT32	uHash		= INITIAL_HASH;
	SIZE_T	cbIndex		= 0x00;
	SIZE_T	cbLength	= (SIZE_T)lstrlenA(pszString);
	BYTE	bChar		= 0x00;

	while (cbIndex != cbLength)
	{
		bChar = (BYTE)pszString[cbIndex++];

		// Flip bit 5 (0x20) on uppercase ASCII to map it to its lowercase counterpart
		if (bChar >= 'A' && bChar <= 'Z')
			bChar += 0x20;

		uHash ^= bChar;

		for (INT i = 0; i < 8; i++)
			uHash = (uHash >> 1) ^ (CRC_POLYNOMIAL & (0 - (uHash & 1)));
	}

	return ~uHash;
}

 
// Generate Crc32b hashes from wide-character input string
UINT32 HashStringCrc32bW(IN PWCHAR pwszString) 
{
	UINT32	uHash		= INITIAL_HASH;
	SIZE_T	cbIndex		= 0x00;
	SIZE_T	cbLength	= (SIZE_T)lstrlenW(pwszString);
 
	while (cbIndex != cbLength)
	{
		uHash ^= (WCHAR)pwszString[cbIndex++];
 
		for (INT i = 0; i < 8; i++)
			uHash = (uHash >> 1) ^ (CRC_POLYNOMIAL & (0 - (uHash & 1)));
	}
 
	return ~uHash;
}


// Generate Crc32b hashes from wide-character input string, case-insensitive 
UINT32 HashIStringCrc32bW(IN PWCHAR pwszString)
{
	UINT32	uHash		= INITIAL_HASH;
	SIZE_T	cbIndex		= 0x00;
	SIZE_T	cbLength	= (SIZE_T)lstrlenW(pwszString);
	WCHAR	wChar		= 0x00;

	while (cbIndex != cbLength)
	{
		wChar = (WCHAR)pwszString[cbIndex++];

		// Flip bit 5 (0x20) on uppercase ASCII to map it to its lowercase counterpart
		if (wChar >= L'A' && wChar <= L'Z')
			wChar += 0x20;

		uHash ^= wChar;

		for (INT i = 0; i < 8; i++)
			uHash = (uHash >> 1) ^ (CRC_POLYNOMIAL & (0 - (uHash & 1)));
	}

	return ~uHash;
}
