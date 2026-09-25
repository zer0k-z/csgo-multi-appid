#include "validator.h"
#include "appid.h"
#include "enginefwd.h"
#include "platform.h"
#include "steam_min.h"

#include <cstring>
#include <ctime>

namespace validator
{
namespace
{

// InitGameServer does bind a socket, so this session cannot be handed the real
// server's ports -- doing that gets
//
//   CreateBoundSocket: ::bind couldn't find an open port between 27015 and 27015
//
// k_unSteamGameServerQueryPortShared tells Steam not to stand up a query
// responder of its own, and the game port is whatever the OS had free a moment
// ago. Neither is ever reachable or advertised: this session does not heartbeat
// and answers nothing.
const uint16_t kQueryPortShared = 0xFFFF;
const int kPortAttempts = 4;

// How long an auth session may sit without a verdict before it is retired.
// Without this a client that never gets an answer would hold its session
// forever and reconnect as a duplicate request.
const int kSessionLingerSeconds = 60;

const int kMaxTracked = 64;

// Opening the second session can fail while the engine's own Steam session is
// still settling, so a failure is not taken as final -- it is retried for a
// couple of minutes first. Without this one early miss would leave cross-appid
// clients rejected for the life of the server.
const int kStartAttempts = 24;
const int kStartRetrySeconds = 5;

struct Tracked
{
	uint64_t	steamID;
	time_t		tStarted;
	bool		bUsed;
};

steam::Api				s_Steam;
steam::ISteamGameServer	*s_pServer;
steam::HSteamPipe		s_hPipe;
steam::HSteamUser		s_hUser;
bool					s_bStarted;
bool					s_bReady;
bool					s_bGaveUp;
int						s_nAttempts;
time_t					s_tNextAttempt;
Tracked					s_Tracked[ kMaxTracked ];

// The same failure line every five seconds for two minutes helps nobody: say it
// on the first attempt and again on the last.
bool Loud()
{
	return s_nAttempts == 1 || s_nAttempts >= kStartAttempts;
}

void Track( uint64_t steamID )
{
	for ( auto &t : s_Tracked )
	{
		if ( !t.bUsed )
		{
			t = { steamID, time( nullptr ), true };
			return;
		}
	}
	plat::Warn( "csgo-multi-appid: validator session table full\n" );
}

void Retire( uint64_t steamID )
{
	for ( auto &t : s_Tracked )
	{
		if ( t.bUsed && t.steamID == steamID )
		{
			if ( s_pServer )
				s_pServer->EndAuthSession( steamID );
			t.bUsed = false;
			return;
		}
	}
}

void HandleCallback( const steam::CallbackMsg_t &msg )
{
	if ( msg.m_iCallback != steam::ValidateAuthTicketResponse_t::k_iCallback )
		return;
	if ( !msg.m_pubParam || msg.m_cubParam < (int)sizeof( steam::ValidateAuthTicketResponse_t ) )
		return;

	const steam::ValidateAuthTicketResponse_t *p = (const steam::ValidateAuthTicketResponse_t *)msg.m_pubParam;

	// Identity was already settled synchronously; what arrives here is ban and
	// licence news about a client that is, by now, usually already playing.
	// Hand it to the engine's own handler so the client is dealt with exactly as
	// a native one would be -- ban checks, the reject path, and the state that
	// makes the client count as fully authenticated on an OK verdict.
	if ( !enginefwd::Forward( p->m_SteamID, (int)p->m_eAuthSessionResponse, p->m_OwnerSteamID ) )
	{
		plat::Warn( "csgo-multi-appid: %llu returned EAuthSessionResponse %d for appid %u,"
					" but the engine's auth handler is unavailable so nothing acted on it\n",
					(unsigned long long)p->m_SteamID, (int)p->m_eAuthSessionResponse, appid::Other() );
	}
	else if ( p->m_eAuthSessionResponse != steam::k_EAuthSessionResponseOK )
	{
		plat::Log( "csgo-multi-appid: %llu failed the follow-up check for appid %u"
				   " (EAuthSessionResponse %d); handed to the engine\n",
				   (unsigned long long)p->m_SteamID, appid::Other(), (int)p->m_eAuthSessionResponse );
	}

	Retire( p->m_SteamID );
}

bool TryStart()
{
	if ( !s_Steam.Load() )
		return false;
	if ( !s_Steam.BGetCallback || !s_Steam.FreeLastCallback )
	{
		if ( Loud() )
			plat::Warn( "csgo-multi-appid: Steam_BGetCallback is unavailable; cannot run a second session\n" );
		return false;
	}

	steam::ISteamClient *pClient = s_Steam.Client();
	if ( !pClient )
		return false;

	plat::Log( "csgo-multi-appid: opening the validator's Steam session (attempt %d)\n", s_nAttempts );

	// CreateLocalUser is the game server bootstrap: it opens the process's own
	// "Steam3Master-<pid>" pipe and overwrites the handle it is given, which is
	// how SteamGameServer_Init gets one. CreateSteamPipe would connect to the
	// Steam client's global "Steam3Master" pipe instead, which a server has no
	// use for, and whose handle CreateLocalUser would discard anyway.
	s_hPipe = 0;
	s_hUser = pClient->CreateLocalUser( &s_hPipe, steam::kEAccountTypeGameServer );

	if ( !s_hPipe || !s_hUser )
	{
		// The engine's own handles come along for the ride: if those are zero
		// too then Steam is simply not up yet and the retry will get it, and if
		// they are not then whatever refused us is specific to a second session.
		if ( Loud() )
			plat::Warn( "csgo-multi-appid: could not open a second Steam session"
						" (pipe %d, user %d; the engine has pipe %d, user %d)\n",
						(int)s_hPipe, (int)s_hUser,
						(int)( s_Steam.GetHSteamPipe ? s_Steam.GetHSteamPipe() : 0 ),
						(int)( s_Steam.GetHSteamUser ? s_Steam.GetHSteamUser() : 0 ) );
		Stop();
		return false;
	}

	plat::Log( "csgo-multi-appid: validator Steam session open (pipe %d, user %d)\n",
			   (int)s_hPipe, (int)s_hUser );

	s_pServer = s_Steam.GameServer( s_hUser, s_hPipe );
	if ( !s_pServer )
	{
		if ( Loud() )
			plat::Warn( "csgo-multi-appid: no ISteamGameServer on the validator pipe\n" );
		Stop();
		return false;
	}

	// The appid is explicit here, which is the whole reason this can live in the
	// same process as a server logged on as the other one. Picking a free port
	// and then binding it is a race, so a lost one is just retried.
	bool bInit = false;
	uint16_t nGamePort = 0;
	for ( int i = 0; i < kPortAttempts && !bInit; ++i )
	{
		nGamePort = plat::FreeUdpPort();
		if ( !nGamePort )
			break;

		bInit = s_pServer->InitGameServer( 0, nGamePort, kQueryPortShared,
										   steam::kServerFlagDedicated | steam::kServerFlagSecure,
										   appid::Other(), "1.0.0.0" );
	}

	if ( !bInit )
	{
		if ( Loud() )
			plat::Warn( "csgo-multi-appid: InitGameServer for appid %u failed\n", appid::Other() );
		Stop();
		return false;
	}

	s_pServer->SetProduct( "csgo" );
	s_pServer->SetGameDescription( "cross-appid ticket validator" );
	s_pServer->SetModDir( "csgo" );
	s_pServer->SetDedicatedServer( true );
	s_pServer->LogOnAnonymous();

	// authproxy only gets here once the engine has its own Steam session, which
	// means CSteam3Server exists and can be located.
	enginefwd::Init();

	plat::Log( "csgo-multi-appid: validator session on port %u, logging on as appid %u\n",
			   nGamePort, appid::Other() );
	return true;
}

} // namespace

bool Start()
{
	if ( s_bStarted )
		return true;
	if ( s_bGaveUp )
		return false;

	// Being called before the engine has loaded steamclient is the normal case
	// at plugin load, not a failure: it costs no attempt and says nothing.
	if ( !steam::ModulesReady() )
		return false;

	const time_t now = time( nullptr );
	if ( s_nAttempts && now < s_tNextAttempt )
		return false;

	s_tNextAttempt = now + kStartRetrySeconds;
	++s_nAttempts;

	if ( TryStart() )
	{
		s_bStarted = true;
		return true;
	}

	if ( s_nAttempts >= kStartAttempts )
	{
		s_bGaveUp = true;
		plat::Warn( "csgo-multi-appid: giving up on the validator session after %d attempts;"
					" clients from appid %u will keep being rejected\n",
					s_nAttempts, appid::Other() );
	}
	return false;
}

void Pump()
{
	if ( !s_bStarted || !s_hPipe )
		return;

	steam::CallbackMsg_t msg;
	while ( s_Steam.BGetCallback( s_hPipe, &msg ) )
	{
		HandleCallback( msg );
		s_Steam.FreeLastCallback( s_hPipe );
	}

	if ( !s_bReady && s_pServer && s_pServer->BLoggedOn() )
	{
		s_bReady = true;
		plat::Log( "csgo-multi-appid: validator ready (appid %u)\n", appid::Other() );
	}

	const time_t now = time( nullptr );
	for ( auto &t : s_Tracked )
	{
		if ( t.bUsed && now - t.tStarted > kSessionLingerSeconds )
		{
			if ( s_pServer )
				s_pServer->EndAuthSession( t.steamID );
			t.bUsed = false;
		}
	}
}

bool Ready()
{
	// Queried live: a server that hibernated straight after map load will not
	// have run a frame since the logon completed, so a flag set in Pump() would
	// still be false.
	return s_bStarted && s_pServer && s_pServer->BLoggedOn();
}

bool IsOwnInterface( const void *pInterface )
{
	return pInterface && pInterface == (const void *)s_pServer;
}

void *Interface()
{
	return s_pServer;
}

void *EngineInterface()
{
	return s_Steam.EngineGameServer();
}

bool Validate( uint64_t steamID, const void *pTicket, int cbTicket )
{
	if ( !s_bReady || !s_pServer || !steamID || !pTicket || cbTicket <= 0 )
		return false;

	// Retire any session this account still holds, or Steam answers the retry
	// with DuplicateRequest rather than judging the ticket.
	Retire( steamID );

	const steam::EBeginAuthSessionResult result = s_pServer->BeginAuthSession( pTicket, cbTicket, steamID );
	if ( result != steam::k_EBeginAuthSessionResultOK )
	{
		plat::Log( "csgo-multi-appid: validator rejected %llu for appid %u (EBeginAuthSessionResult %d)\n",
				   (unsigned long long)steamID, appid::Other(), (int)result );
		return false;
	}

	// Session stays open so the follow-up verdict can still arrive; Pump()
	// retires it when it does, or when it goes stale.
	Track( steamID );
	return true;
}

void Stop()
{
	if ( s_pServer )
	{
		for ( auto &t : s_Tracked )
		{
			if ( t.bUsed )
			{
				s_pServer->EndAuthSession( t.steamID );
				t.bUsed = false;
			}
		}

		if ( s_bStarted )
			s_pServer->LogOff();
	}

	steam::ISteamClient *pClient = s_Steam.Client();
	if ( pClient && s_hPipe )
	{
		if ( s_hUser )
			pClient->ReleaseUser( s_hPipe, s_hUser );
		pClient->BReleaseSteamPipe( s_hPipe );
	}

	s_pServer = nullptr;
	s_hPipe = 0;
	s_hUser = 0;
	s_bStarted = false;
	s_bReady = false;
}

} // namespace validator
