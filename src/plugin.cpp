// Valve server plugin entry point.
//
// IServerPluginCallbacks is mirrored here rather than pulled from an SDK: the
// plugin needs no other engine interface, and the interface has no virtual
// destructor, so the vtable layout is identical under MSVC and the Itanium ABI.
// Only the declaration order matters, and it is verified against the shipped
// engine (which asks for ISERVERPLUGINCALLBACKS004 and calls slot 0 as Load).

#include "appid.h"
#include "authproxy.h"
#include "gametick.h"
#include "steaminit.h"
#include "workshop.h"
#include "platform.h"

#include <cstdint>
#include <cstring>

#if defined( _WIN32 )
#define PLUGIN_EXPORT extern "C" __declspec( dllexport )
#else
#define PLUGIN_EXPORT extern "C" __attribute__( ( visibility( "default" ) ) )
#endif

namespace
{

typedef void *( *CreateInterfaceFn )( const char *pName, int *pReturnCode );

enum PluginResult_t
{
	PLUGIN_CONTINUE = 0,
	PLUGIN_OVERRIDE,
	PLUGIN_STOP,
};

class CMultiAppIdPlugin
{
public:
	virtual bool Load( CreateInterfaceFn, CreateInterfaceFn gameServerFactory )
	{
		appid::Apply();
		workshop::Apply();
		// Before authproxy::Init, which only starts the validator itself if
		// this could not be installed.
		steaminit::Install( &authproxy::OnEngineSteamInit );
		authproxy::Init();

		// Where the per-frame work actually comes from; see gametick.h for why
		// GameFrame is not good enough.
		gametick::Install( (gametick::CreateInterfaceFn)gameServerFactory, &authproxy::Tick );
		return true;
	}

	virtual void Unload()
	{
		gametick::Remove();
		steaminit::Remove();
		authproxy::Shutdown();
		workshop::Restore();
		appid::Restore();
	}

	virtual void			Pause() {}
	virtual void			UnPause() {}
	virtual const char		*GetPluginDescription() { return "csgo-multi-appid " PLUGIN_VERSION; }
	virtual void			LevelInit( const char * ) {}
	virtual void			ServerActivate( void *, int, int ) {}
	// Only a fallback: when the Think hook is in place this would just be a
	// second tick on the frames that run anyway.
	virtual void			GameFrame( bool ) { if ( !gametick::Installed() ) authproxy::Tick(); }
	virtual void			LevelShutdown() {}
	virtual void			ClientActive( void * ) {}
	virtual void			ClientFullyConnect( void * ) {}
	virtual void			ClientDisconnect( void * ) {}
	virtual void			ClientPutInServer( void *, const char * ) {}
	virtual void			SetCommandClient( int ) {}
	virtual void			ClientSettingsChanged( void * ) {}
	virtual PluginResult_t	ClientConnect( bool *, void *, const char *, const char *, char *, int ) { return PLUGIN_CONTINUE; }
	virtual PluginResult_t	ClientCommand( void *, const void * ) { return PLUGIN_CONTINUE; }
	virtual PluginResult_t	NetworkIDValidated( const char *, const char * ) { return PLUGIN_CONTINUE; }
	virtual void			OnQueryCvarValueFinished( int, void *, int, const char *, const char * ) {}
	virtual void			OnEdictAllocated( void * ) {}
	virtual void			OnEdictFreed( const void * ) {}
	virtual bool			BNetworkCryptKeyCheckRequired( uint32_t, uint16_t, uint32_t, bool ) { return false; }
	virtual bool			BNetworkCryptKeyValidate( uint32_t, uint16_t, uint32_t, int, int, unsigned char *, unsigned char * ) { return false; }
};

CMultiAppIdPlugin s_Plugin;

} // namespace

PLUGIN_EXPORT void *CreateInterface( const char *pName, int *pReturnCode )
{
	if ( pName && strcmp( pName, "ISERVERPLUGINCALLBACKS004" ) == 0 )
	{
		if ( pReturnCode )
			*pReturnCode = 0; // IFACE_OK
		return &s_Plugin;
	}

	if ( pReturnCode )
		*pReturnCode = 1; // IFACE_FAILED
	return nullptr;
}
