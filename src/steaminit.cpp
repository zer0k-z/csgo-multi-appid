#include "steaminit.h"
#include "platform.h"
#include "steam_min.h"

#include <cstdint>
#include <cstring>

#if defined( _WIN32 )
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace steaminit
{
namespace
{

const char *const kInitName = "SteamInternal_GameServer_Init";

#if defined( _WIN32 )
const char *const kEngineModule = "engine.dll";
const char *const kSteamApiModule = "steam_api.dll";
#define INIT_CALL __cdecl
#else
const char *const kEngineModule = "engine.so";
const char *const kSteamApiModule = "libsteam_api.so";
#define INIT_CALL
#endif

typedef bool( INIT_CALL *InitFn )( uint32_t unIP, uint16_t usLegacySteamPort, uint16_t usGamePort,
									uint16_t usQueryPort, int eServerMode, const char *pchVersionString );

// An import slot on Windows, a call's rel32 on Linux; either way four bytes.
struct Patch_t
{
	void		*pAddr;
	uint32_t	nOriginal;
};

const int	kMaxPatches = 4;

InitFn		s_pfnOriginal;
Callback	s_pfnAfter;
Patch_t		s_Patches[ kMaxPatches ];
int			s_nPatches;

bool INIT_CALL Hook_Init( uint32_t unIP, uint16_t usLegacySteamPort, uint16_t usGamePort,
						  uint16_t usQueryPort, int eServerMode, const char *pchVersionString )
{
	const bool bOK = s_pfnOriginal( unIP, usLegacySteamPort, usGamePort, usQueryPort, eServerMode, pchVersionString );
	if ( bOK && s_pfnAfter )
		s_pfnAfter();
	return bOK;
}

bool Patch( void *pAddr, uint32_t nValue )
{
	if ( s_nPatches >= kMaxPatches )
		return false;

	uint32_t nOriginal;
	memcpy( &nOriginal, pAddr, sizeof( nOriginal ) );
	if ( !plat::WriteMemory( pAddr, &nValue, sizeof( nValue ) ) )
		return false;

	s_Patches[ s_nPatches++ ] = { pAddr, nOriginal };
	return true;
}

#if defined( _WIN32 )
// The engine's import slot for the init, and with it the original.
void RedirectCalls()
{
	unsigned char *pBase = (unsigned char *)GetModuleHandleA( kEngineModule );
	if ( !pBase )
		return;

	IMAGE_NT_HEADERS *pNt = (IMAGE_NT_HEADERS *)( pBase + ( (IMAGE_DOS_HEADER *)pBase )->e_lfanew );
	const IMAGE_DATA_DIRECTORY &dir = pNt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
	if ( !dir.VirtualAddress )
		return;

	for ( IMAGE_IMPORT_DESCRIPTOR *pImport = (IMAGE_IMPORT_DESCRIPTOR *)( pBase + dir.VirtualAddress );
		  pImport->Name; ++pImport )
	{
		if ( _stricmp( (const char *)( pBase + pImport->Name ), kSteamApiModule ) != 0 || !pImport->OriginalFirstThunk )
			continue;

		IMAGE_THUNK_DATA *pName = (IMAGE_THUNK_DATA *)( pBase + pImport->OriginalFirstThunk );
		IMAGE_THUNK_DATA *pSlot = (IMAGE_THUNK_DATA *)( pBase + pImport->FirstThunk );
		for ( ; pName->u1.AddressOfData; ++pName, ++pSlot )
		{
			if ( IMAGE_SNAP_BY_ORDINAL( pName->u1.Ordinal ) )
				continue;

			const IMAGE_IMPORT_BY_NAME *pByName = (const IMAGE_IMPORT_BY_NAME *)( pBase + pName->u1.AddressOfData );
			if ( strcmp( (const char *)pByName->Name, kInitName ) != 0 )
				continue;

			InitFn pfnCurrent = (InitFn)pSlot->u1.Function;
			if ( Patch( &pSlot->u1.Function, (uint32_t)(uintptr_t)&Hook_Init ) )
				s_pfnOriginal = pfnCurrent;
			return;
		}
	}
}
#else
// engine.so calls the init directly, relocated at load time (TEXTREL), so
// every E8 whose target is the export is one of its call sites.
void RedirectCalls()
{
	void *hSteamApi = dlopen( kSteamApiModule, RTLD_NOW | RTLD_NOLOAD );
	InitFn pfnInit = hSteamApi ? (InitFn)dlsym( hSteamApi, kInitName ) : nullptr;
	if ( !pfnInit )
		return;

	const unsigned char *pText = nullptr;
	size_t nSize = 0;
	if ( !plat::ModuleTextRange( kEngineModule, &pText, &nSize ) )
		return;

	for ( size_t i = 0; i + 5 <= nSize; ++i )
	{
		if ( pText[ i ] != 0xE8 )
			continue;

		int32_t nRel;
		memcpy( &nRel, pText + i + 1, sizeof( nRel ) );
		const uintptr_t pNext = (uintptr_t)( pText + i + 5 );
		if ( pNext + nRel != (uintptr_t)pfnInit )
			continue;

		const int32_t nHookRel = (int32_t)( (uintptr_t)&Hook_Init - pNext );
		if ( !Patch( (void *)( pText + i + 1 ), (uint32_t)nHookRel ) )
			break;
	}

	if ( s_nPatches )
		s_pfnOriginal = pfnInit;
}
#endif

} // namespace

bool Install( Callback pfnAfter )
{
	// Too late to see the init, and a hook that never fires would leave the
	// validator waiting for it forever.
	steam::Api api;
	if ( api.Load() && api.GetHSteamPipe() )
	{
		plat::Warn( "csgo-multi-appid: loaded after the engine's Steam session was set up;"
					" the validator will start from the frame loop, where it can hang the server\n" );
		return false;
	}

	s_pfnAfter = pfnAfter;
	RedirectCalls();
	if ( !s_pfnOriginal )
	{
		Remove();
		plat::Warn( "csgo-multi-appid: could not hook %s in %s;"
					" the validator will start from the frame loop, where it can hang the server\n",
					kInitName, kEngineModule );
		return false;
	}

	plat::Log( "csgo-multi-appid: the validator will start with the engine's Steam session (%d site%s)\n",
			   s_nPatches, s_nPatches == 1 ? "" : "s" );
	return true;
}

bool Installed()
{
	return s_pfnOriginal != nullptr;
}

void Remove()
{
	for ( int i = 0; i < s_nPatches; ++i )
		plat::WriteMemory( s_Patches[ i ].pAddr, &s_Patches[ i ].nOriginal, sizeof( uint32_t ) );
	s_nPatches = 0;
	s_pfnOriginal = nullptr;
	s_pfnAfter = nullptr;
}

} // namespace steaminit
