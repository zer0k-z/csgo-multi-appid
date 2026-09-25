#pragma once

namespace authproxy
{
// Unconditional: this is what the plugin is for, and there is nothing to
// configure -- both appids are fixed constants, and the validator validates
// whichever one the server is not pinned to.
void Init();

// Called by steaminit between the engine's Steam init and its logon, the one
// point where the validator's session can be opened without deadlocking.
void OnEngineSteamInit();

// The engine creates its Steam game server session at map load, well after
// plugins load, so the hook is installed on the first frame it exists.
void Tick();

void Shutdown();
}
