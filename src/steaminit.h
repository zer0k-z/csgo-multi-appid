// A hook on the engine's Steam game server init.
//
// The validator's second Steam session has to be opened with
// ISteamClient::CreateLocalUser, which holds steamclient's process-wide lock
// while it waits on a cross-thread pipe to steamclient's own worker thread.
// Once the engine has logged on, that worker needs the same lock for its own
// work, so the two can deadlock: a minidump shows the main thread inside
// CreateLocalUser and the worker in pthread_mutex_lock on exactly that lock,
// until steamclient's watchdog kills the process with "fatal stalled
// cross-thread pipe".
//
// The engine gets away with its own CreateLocalUser because it makes it inside
// SteamGameServer_Init, before anything is logged on. CSteam3Server::Activate
// calls LogOn only after that returns, so this runs a callback in between.
//
// The engine reaches SteamInternal_GameServer_Init through its import table on
// Windows and through a load-time-relocated direct call on Linux; whichever it
// is gets pointed here, and the original is called straight through.
#pragma once

namespace steaminit
{
typedef void ( *Callback )();

// pfnAfter runs right after the engine's init succeeds, before it logs on.
// False if the call could not be redirected, or if the engine's Steam session
// is already up (the plugin was loaded late), in which case it never will be.
bool Install( Callback pfnAfter );
bool Installed();
void Remove();
}
