// Cross-appid client validation.
//
// A game server can only validate auth tickets for the app it logged on as, so
// a client running the same build under the other appid fails with
// k_EBeginAuthSessionResultGameMismatch. The tempting "fix" is to treat that
// result as success, but the SteamID the engine uses comes from the client's
// own connect packet and is only trustworthy once Steam has validated the
// ticket against it -- so accepting blindly lets anyone claim any SteamID.
//
// Instead the ticket goes to a second Steam session in this process, logged on
// as the other appid (see validator.h). BeginAuthSession there binds ticket to
// SteamID exactly as it would for a native client, so a forged ID is rejected
// and the engine's own rejection stands.
//
// Only GameMismatch is diverted. Invalid, expired, duplicate and version
// mismatch tickets keep the engine's own answer.

#include "authproxy.h"
#include "appid.h"
#include "platform.h"
#include "presence.h"
#include "steam_min.h"
#include "steaminit.h"
#include "validator.h"

#include <cstring>

namespace authproxy
{
namespace
{

const int kMaxTicketBytes = 1400;

#if defined( _WIN32 )
// Virtuals are __thiscall; __fastcall with an unused edx slot gives a free
// function the same register layout.
#define HOOK_CALL __fastcall
#define HOOK_THIS steam::ISteamGameServer *pThis, void * /*edx*/
#define HOOK_FORWARD pThis, nullptr
typedef steam::EBeginAuthSessionResult( HOOK_CALL *BeginAuthSessionFn )(
	steam::ISteamGameServer *, void *, const void *, int, uint64_t );
typedef void( HOOK_CALL *LogOffFn )( steam::ISteamGameServer *, void * );
typedef void( HOOK_CALL *EndAuthSessionFn )( steam::ISteamGameServer *, void *, uint64_t );
typedef bool( HOOK_CALL *BUpdateUserDataFn )(
	steam::ISteamGameServer *, void *, uint64_t, const char *, uint32_t );
#else
// Itanium ABI: this is simply the first argument.
#define HOOK_CALL
#define HOOK_THIS steam::ISteamGameServer *pThis
#define HOOK_FORWARD pThis
typedef steam::EBeginAuthSessionResult( *BeginAuthSessionFn )(
	steam::ISteamGameServer *, const void *, int, uint64_t );
typedef void( *LogOffFn )( steam::ISteamGameServer * );
typedef void( *EndAuthSessionFn )( steam::ISteamGameServer *, uint64_t );
typedef bool( *BUpdateUserDataFn )( steam::ISteamGameServer *, uint64_t, const char *, uint32_t );
#endif

// Set only if the hook cannot be installed; there is no way to turn the feature
// off, because a server without it is a server that rejects half its players.
// The engine's ISteamGameServer and the validator's may be instances of one
// adapter class sharing a vtable, or not, and which it is decides whether one
// patch covers both. Rather than depend on the answer, each distinct vtable
// seen gets patched once and restored on unload.
struct Patch_t
{
	void	**ppSlot;
	void	*pOriginal;
};

const int			kMaxPatches = 8;

steam::EBeginAuthSessionResult HOOK_CALL Hook_BeginAuthSession(
	HOOK_THIS, const void *pTicket, int cbTicket, uint64_t steamID );
void HOOK_CALL Hook_LogOff( HOOK_THIS );
void HOOK_CALL Hook_EndAuthSession( HOOK_THIS, uint64_t steamID );
bool HOOK_CALL Hook_BUpdateUserData( HOOK_THIS, uint64_t steamID, const char *pchName, uint32_t uScore );

bool				s_bBroken;
bool				s_bValidatorStarted;
BeginAuthSessionFn	s_pfnOriginal;
LogOffFn			s_pfnOriginalLogOff;
EndAuthSessionFn	s_pfnOriginalEndAuthSession;
BUpdateUserDataFn	s_pfnOriginalUpdateUserData;
Patch_t				s_Patches[ kMaxPatches ];
int					s_nPatches;
bool				s_bWarnedSecondVTable;
bool				s_bWarnedLogOff;
bool				s_bWarnedPresence;

// Setup() runs every frame and retries whatever did not take, so a hook that
// has failed for good would otherwise say so every frame.
void Complain( bool &bSaid, const char *pszMessage )
{
	if ( bSaid )
		return;

	bSaid = true;
	plat::Warn( "%s", pszMessage );
}

bool IsPatched( void **ppSlot )
{
	for ( int i = 0; i < s_nPatches; ++i )
	{
		if ( s_Patches[ i ].ppSlot == ppSlot )
		{
			return true;
		}
	}
	return false;
}

// Patches one slot, remembering the original so Shutdown can put it back.
// Returns what the slot held, which the caller keeps in its own typed pointer,
// or null if the slot could not be taken.
//
// pKnown is whatever a previously patched vtable found in the same slot. Every
// patched vtable has to forward to the same original, so a second distinct
// vtable is only taken if its slot agrees with the first one's.
void *PatchSlot( void **pVTable, int nSlot, void *pHook, void *pKnown )
{
	if ( nSlot < 0 )
		return nullptr;

	void **ppSlot = &pVTable[ nSlot ];
	if ( IsPatched( ppSlot ) )
		return pKnown;

	if ( s_nPatches >= kMaxPatches )
		return nullptr;

	// The original doubles as this function's answer, so an empty slot would
	// report failure having already installed a hook with nothing behind it.
	// No vtable has one; refusing is still cheaper than the crash.
	void *pOriginal = *ppSlot;
	if ( !pOriginal )
		return nullptr;

	if ( pKnown && pOriginal != pKnown )
		return nullptr;

	if ( !plat::WriteMemory( ppSlot, &pHook, sizeof( pHook ) ) )
		return nullptr;

	s_Patches[ s_nPatches ].ppSlot = ppSlot;
	s_Patches[ s_nPatches ].pOriginal = pOriginal;
	++s_nPatches;
	return pOriginal;
}

bool InstallHook( steam::ISteamGameServer *pServer )
{
	if ( !pServer )
		return false;

	void **pVTable = *(void ***)pServer;

	// The one hook the feature cannot do without.
	void *pOriginal = PatchSlot( pVTable, steam::BeginAuthSessionSlot(),
								 (void *)&Hook_BeginAuthSession, (void *)s_pfnOriginal );
	if ( !pOriginal )
	{
		// A hook already installed elsewhere means this is a second vtable that
		// does not match the first, not a feature that failed to start.
		if ( s_pfnOriginal )
		{
			Complain( s_bWarnedSecondVTable,
					  "csgo-multi-appid: a second ISteamGameServer vtable has a different"
					  " BeginAuthSession; leaving it alone\n" );
			return false;
		}

		plat::Warn( "csgo-multi-appid: could not install the BeginAuthSession hook;"
					" clients from appid %u will keep being rejected\n", appid::Other() );
		s_bBroken = true;
		return false;
	}
	s_pfnOriginal = (BeginAuthSessionFn)pOriginal;

	if ( void *p = PatchSlot( pVTable, steam::LogOffSlot(),
							  (void *)&Hook_LogOff, (void *)s_pfnOriginalLogOff ) )
	{
		s_pfnOriginalLogOff = (LogOffFn)p;
	}
	else
	{
		Complain( s_bWarnedLogOff,
				  "csgo-multi-appid: could not install the LogOff hook;"
				  " the validator session will outlive the engine's at shutdown\n" );
	}

	// These two are what keeps cross-appid clients visible in server queries;
	// see presence.h. They stand or fall together: listing a client without the
	// signal that retires them again would leave the server advertising players
	// who left, which is worse than the emptiness it set out to fix. Everything
	// else works without either, so this is not fatal.
	void *pUserData = PatchSlot( pVTable, steam::BUpdateUserDataSlot(),
								 (void *)&Hook_BUpdateUserData, (void *)s_pfnOriginalUpdateUserData );
	void *pEndAuth = PatchSlot( pVTable, steam::EndAuthSessionSlot(),
								(void *)&Hook_EndAuthSession, (void *)s_pfnOriginalEndAuthSession );
	// Whichever went in has to get its original, hooked slot or not: half a pair
	// still has a live hook, and it forwards.
	if ( pUserData )
		s_pfnOriginalUpdateUserData = (BUpdateUserDataFn)pUserData;
	if ( pEndAuth )
		s_pfnOriginalEndAuthSession = (EndAuthSessionFn)pEndAuth;

	if ( !pUserData || !pEndAuth )
	{
		presence::Disable( validator::EngineInterface() );
		Complain( s_bWarnedPresence,
				  "csgo-multi-appid: could not install the player-data hooks;"
				  " cross-appid clients will play but stay invisible in server queries\n" );
	}

	return true;
}

void StartValidator()
{
	if ( !s_bValidatorStarted && validator::Start() )
		s_bValidatorStarted = true;
}

void StopValidator()
{
	if ( !s_bValidatorStarted )
	{
		return;
	}

	validator::Stop();
	s_bValidatorStarted = false;
}

// Everything the feature needs, done as early as it can be done. Nothing here
// waits on the engine's own Steam session: the validator builds its own, and
// the vtable being patched belongs to steamclient's adapter class rather than
// to any one instance of it.
void Setup()
{
	if ( s_bBroken )
		return;

	if ( !s_bValidatorStarted )
	{
		// With the init hook in, the validator starts from there and nowhere
		// else: any later and CreateLocalUser can deadlock against steamclient's
		// own thread (see steaminit.h).
		if ( steaminit::Installed() )
			return;

		StartValidator();
		if ( !s_bValidatorStarted )
			return;
	}

	InstallHook( (steam::ISteamGameServer *)validator::Interface() );

	// If the engine has a session of its own by now, and it turns out not to
	// share a vtable with ours, this catches the other one.
	if ( steam::ISteamGameServer *pEngine = (steam::ISteamGameServer *)validator::EngineInterface() )
		InstallHook( pEngine );
}

steam::EBeginAuthSessionResult HOOK_CALL Hook_BeginAuthSession( HOOK_THIS, const void *pTicket, int cbTicket, uint64_t steamID )
{
	const steam::EBeginAuthSessionResult result = s_pfnOriginal( HOOK_FORWARD, pTicket, cbTicket, steamID );

	// The validator's own call, if it shares a vtable with the engine's
	// interface. Diverting it into itself is how this would recurse.
	if ( validator::IsOwnInterface( pThis ) )
		return result;

	// A hibernating server runs no frames, so this is the only chance to drain
	// the validator's callbacks before the answer below is needed.
	validator::Pump();

	// Every other verdict, including every other kind of failure, is the
	// engine's to act on unchanged.
	if ( result != steam::k_EBeginAuthSessionResultGameMismatch )
		return result;

	if ( cbTicket <= 0 || cbTicket > kMaxTicketBytes )
		return result;

	if ( !validator::Validate( steamID, pTicket, cbTicket ) )
		return result;

	// Steam has no record of this client, because the call above really did
	// fail; presence is what gets it counted and listed anyway.
	presence::Add( steamID );

	plat::Log( "csgo-multi-appid: %llu validated for appid %u\n",
			   (unsigned long long)steamID, appid::Other() );
	return steam::k_EBeginAuthSessionResultOK;
}

void HOOK_CALL Hook_LogOff( HOOK_THIS )
{
	const bool bOwn = validator::IsOwnInterface( pThis );
	if ( !bOwn )
	{
		presence::Clear( pThis );
		StopValidator();
	}

	s_pfnOriginalLogOff( HOOK_FORWARD );
}

// The engine ends its auth session for every client that leaves, whether or not
// the session existed, so this is where a cross-appid client's disconnect is.
void HOOK_CALL Hook_EndAuthSession( HOOK_THIS, uint64_t steamID )
{
	if ( !validator::IsOwnInterface( pThis ) )
		presence::Remove( pThis, steamID );

	s_pfnOriginalEndAuthSession( HOOK_FORWARD, steamID );
}

// CGameServer::UpdateMasterServerPlayers calls this for every client each time
// the server details go out, which is the one moment Steam is told a player
// exists. For a cross-appid client the real SteamID means nothing to Steam, so
// it goes out under the one presence opened for them instead.
bool HOOK_CALL Hook_BUpdateUserData( HOOK_THIS, uint64_t steamID, const char *pchName, uint32_t uScore )
{
	if ( !validator::IsOwnInterface( pThis ) )
	{
		if ( const uint64_t substitute = presence::Substitute( pThis, steamID ) )
			steamID = substitute;
	}

	return s_pfnOriginalUpdateUserData( HOOK_FORWARD, steamID, pchName, uScore );
}

} // namespace

void Init()
{
	plat::Log( "csgo-multi-appid: clients whose tickets are for appid %u will be validated separately\n",
			   appid::Other() );

	// Deliberately not left to the first frame. An empty server hibernates, and
	// SV_Think returns before it reaches g_pServerPluginHandler->GameFrame, so
	// on a server nobody has joined yet GameFrame may never run at all -- and
	// that is exactly the server a client is about to connect to.
	Setup();
}

void OnEngineSteamInit()
{
	if ( s_bBroken )
		return;

	StartValidator();
	Setup();
}

void Tick()
{
	if ( s_bBroken )
		return;

	// Frames are a convenience here, not the mechanism: Setup() has usually run
	// to completion during Load(). This retries whatever did not take, and is
	// also where the engine's interface gets picked up if it does not share a
	// vtable with the validator's.
	Setup();

	validator::Pump();
	presence::Expire();
}

void Shutdown()
{
	// Before the hooks go, while the engine's session is still there to hear
	// it: anyone this module had Steam listing is no longer its to list.
	presence::Clear( validator::EngineInterface() );

	// Unhook first: the validator's interface goes away with it, and a vtable
	// still pointing at this module would be a crash waiting to happen.
	for ( int i = 0; i < s_nPatches; ++i )
		plat::WriteMemory( s_Patches[ i ].ppSlot, &s_Patches[ i ].pOriginal, sizeof( void * ) );
	s_nPatches = 0;

	StopValidator();
}

} // namespace authproxy
