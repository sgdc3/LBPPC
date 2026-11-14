# Running the game in an AppContainer: the broker (design)

Status: step 1 is in (`src/runtime_container.c`, `LBPPC_APPCONTAINER=1`: the game runs inside, keyboard only);
steps 2 to 5 are the design below. It comes from a prototype that ran LBP3 1.28 inside an AppContainer on 2026-11-14 (RTX 4080 Laptop,
Windows 11): Vulkan, the window, FSR 3.1, NVIDIA Reflex, WASAPI audio, save data and the shader caches all worked.
Two things did not: the controller (no DualSense) and the overlay's GPU usage (empty). This document is how LBPPC
would fix both with a broker, and everything else an AppContainer needs.

## Why

`src/runtime_sandbox.c` already stops the game process from starting programs and from writing outside its own
folders. It can still **read** everything the user can (documents, browser data) and send it away. An AppContainer
can read only what it is granted. Since LBP3's code parses levels and resources from the server and from other
players natively, this is the remaining way a parser bug could hurt the player.

## What the prototype found

| Area | Inside an AppContainer |
|---|---|
| Memory range | AppContainer forces high-entropy ASLR, which put the first thread's stack inside the PS4 range (`0x10_0000_0000`–`0xfc_0000_0000`) every time, and the range could not be reserved. Fixed by creating the process with `PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_OFF \| BOTTOM_UP_ASLR_ALWAYS_OFF` (LBPPC-Game.exe is linked without high-entropy VA anyway). |
| Files | Only what is granted to the container's SID: the install folder, the folders of the DLLs it loads, the game and update folders (read), its folders in `user/` and three files (write; they also need the low label `runtime_sandbox.c` gives them). |
| Vulkan, window, FSR, Reflex, audio, saves, caches | Work. |
| Controllers | Not seen. SDL reads DualSense, DualShock 4 and Switch Pro through HID, which an AppContainer cannot open: neither device capabilities (`humanInterfaceDevice`, `lowLevelDevices`, `usb`, `bluetooth`) nor SDL's Windows.Gaming.Input backend helped. |
| GPU usage (overlay) | Empty: it reads Windows' performance counters (PDH, `\GPU Engine(*)\Utilization Percentage`), which an AppContainer cannot query. |
| Not tried | Online play, DLSS frame generation, overlays injected into the game (Discord, Steam, OBS). |

## Shape

One executable, two processes, nothing in `probe.c`:

```
run.py ──starts──> LBPPC-Game.exe (outer: the broker, the user's own rights)
                      │  grants the container its folders, makes the shared memory,
                      │  starts the same command line inside the AppContainer,
                      │  then only: controllers in, rumble out, GPU usage, until the game ends
                      └──> LBPPC-Game.exe (inner: the game, AppContainer "LBPPC.Game", low integrity)
                              runtime_sandbox.c as today; controllers are SDL virtual gamepads fed by the broker
```

- A new runtime module, `src/runtime_container.c`, picked up by both builds (`src/runtime*.c`). It is called first
  thing from `runtime_memory_reserve()`, before the PS4 range is reserved, as `restart_with_range()` already is.
  The outer process never runs game code: it becomes the broker and exits with the game's exit code (so the in-game
  "Apply and restart", exit 75, still reaches `run.py`).
- Switched by `LBPPC_APPCONTAINER=1` (a launcher setting, "Isolate the game", experimental and off at first). If any
  step of the setup fails, the game runs as today and the log says why; `LBPPC_APPCONTAINER=require` refuses to start
  instead (for testing).

## Outer process: setup

1. **Profile**: `CreateAppContainerProfile("LBPPC.Game")` (or `DeriveAppContainerSidFromAppContainerName` when it
   exists). Capabilities: `internetClient`, `internetClientServer` (peers connect to us), `privateNetworkClientServer`
   (players on the same network).
2. **Loopback**: an AppContainer cannot reach `127.0.0.1` without an exemption that needs administrator rights. If
   `LBPPC_SERVER` or shadNet is on this PC, skip the container and say so.
3. **Grants** (one inheritable ACE for the container's SID, added only when missing):
   - read and execute: the install folder, and the folder of every non-system module this process has loaded (covers
     MSYS2's `clang64\bin` in development builds and nothing extra in packaged ones);
   - read: the game folder (`--app0`), the update folder (`--update`), the DLC folders;
   - modify: the folders and files `runtime_sandbox.c` labels low. The list moves to `runtime.h` so both modules use
     one copy.
   The grants stay (they are permissions, not file changes; the files themselves are untouched). Turning the setting
   off in the launcher removes them and deletes the profile (`DeleteAppContainerProfile`). The launcher must say,
   when the setting is turned on, that it adds a permission to the game's folders: LBPPC otherwise promises not to
   change them.
4. **Shared memory**: an unnamed, inheritable section (`CreateFileMappingW(INVALID_HANDLE_VALUE, ...)`, fixed size,
   layout below), mapped by both.
5. **Start the game**: the same command line, `CreateProcessW` with `EXTENDED_STARTUPINFO_PRESENT` and three
   attributes: `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`, `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` (the ASLR
   flags above) and `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` (stdin/stdout/stderr and the section only). Environment: the
   current one plus `LBPPC_CONTAINER=1`, `LBPPC_BROKER=<section handle>`, and SDL's hints turning off every real
   joystick backend inside (`SDL_JOYSTICK_HIDAPI=0`, `SDL_JOYSTICK_RAWINPUT=0`, `SDL_JOYSTICK_XINPUT=0`,
   `SDL_JOYSTICK_WGI=0`), so that an Xbox pad seen through XInput is not counted twice. The game goes into a job
   with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, so it ends with the broker (the launcher's Stop kills the tree).

## Shared memory

One page-aligned struct, version-checked by the inner side, written with a sequence lock (the writer makes `seq`
odd, writes, makes it even; the reader retries while it is odd or changed).

```c
typedef struct {
    uint32_t magic;            /* 'LBRK' */
    uint32_t version, size;
    uint64_t broker_heartbeat; /* the broker's tick count, every loop */

    struct BrokerPad {         /* broker -> game, one per physical pad (up to 8) */
        uint32_t seq;
        uint32_t generation;   /* changes when another pad takes the slot */
        uint8_t  connected, type;            /* SDL_GamepadType */
        uint16_t vendor, product;
        char     name[64];
        int16_t  axes[6];                    /* SDL_GamepadAxis order */
        uint32_t buttons;                    /* bit = SDL_GamepadButton */
        uint8_t  touchpads, fingers;         /* layout, from SDL */
        struct { uint8_t down; float x, y, pressure; } finger[2];
        uint8_t  has_accel, has_gyro;
        uint32_t sensor_seq;                 /* changes with each new sample */
        uint64_t sensor_timestamp_ns;
        float    accel[3], gyro[3];
    } pad[8];

    struct BrokerOut {         /* game -> broker, the only part the game writes */
        uint32_t seq;
        uint16_t low, high, left_trigger, right_trigger;
        uint32_t duration_ms;
        uint8_t  led_set, led[3];
        uint8_t  sensors_enabled;
        uint8_t  effect_size, effect[62];    /* SDL_SendGamepadEffect (DualSense trigger effects) */
    } out[8];

    uint32_t gpu_seq;
    float    gpu_usage;        /* percent, the busiest engine of the game's process */
} BrokerShared;
```

The broker treats `out[]` as untrusted: pad index, durations (capped), effect size (≤ 62) and LED values are checked
before any SDL call, and nothing else in the section is ever read back from the game.

## Outer process: broker loop

- `SDL_InitSubSystem(SDL_INIT_GAMEPAD)` without video, with `SDL_HINT_JOYSTICK_ALLOW_BACKGROUND_EVENTS=1` (it has
  no window, so it never has focus).
- Every 2 ms (`SDL_WaitEventTimeout` plus `SDL_UpdateGamepads`): open and close pads as SDL reports them, enable
  their sensors, and publish each pad's state, touchpad fingers and latest accelerometer and gyro sample. 2 ms
  keeps the state at most one DualSense report old; the pad thread inside reads at 83 Hz.
- Each loop, apply new `out[]` entries: `SDL_RumbleGamepad`, `SDL_RumbleGamepadTriggers`, `SDL_SetGamepadLED`,
  `SDL_SendGamepadEffect`, `SDL_SetGamepadSensorEnabled`.
- Once a second: GPU usage for the game's PID, with the overlay's PDH code moved to a shared helper and given the
  child's PID instead of its own.
- `WaitForSingleObject` on the game's process handle ends the loop; the broker exits with its code.

## Inner process: virtual gamepads

`runtime_container.c` (inner side) starts a thread when `LBPPC_BROKER` is set. Every 100 ms it compares each slot's
`connected` and `generation` with what it has attached:

- New pad: `SDL_AttachVirtualJoystick` with the real pad's name, type, vendor and product (so `runtime_pad.c`'s
  "DualSense Wireless Controller: ps5" and its PlayStation button labels stay right), 6 axes, all buttons, its
  touchpads and an accelerometer and gyro sensor at the pad's rate.
- Gone: `SDL_DetachVirtualJoystick`.

The virtual joystick's `Update` callback, which SDL calls from `SDL_UpdateGamepads()` (the pad thread already calls
it before each read), copies the slot under its sequence lock into `SDL_SetJoystickVirtualAxis/Button/Touchpad` and,
when `sensor_seq` moved, `SDL_SendJoystickVirtualSensorData`. `Rumble`, `RumbleTriggers`, `SetLED`, `SendEffect`
and `SetSensorsEnabled` write the slot's `out` entry.

`runtime_pad.c` is unchanged: it sees ordinary SDL gamepads. Keyboard and mouse stay as they are (the window is the
game's).

The overlay reads `gpu_usage` from the section when `LBPPC_BROKER` is set, instead of its PDH query.

`runtime_sandbox.c` inside the container: the job and mitigations as today; the folders are already labelled by the
outer process; lowering the integrity is skipped (an AppContainer token is already low).

## Security of the broker itself

- It runs with the user's rights, so it must stay small: SDL's gamepad subsystem, PDH, and the struct above. It
  never parses anything else the game sends, and the section's size is fixed, mapped once.
- The game cannot reach the broker any other way: no pipes, no named objects, no window messages. Its handles to
  the broker are the section and its standard handles only (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`).
- The container's capabilities are network only; no `documentsLibrary`, no device capabilities.

## Limits that stay

- A server on this PC (loopback): no container.
- DLSS frame generation, overlays injected into the game (Discord, Steam, OBS hook capture) and online play are
  untested inside.
- Windows 10 1809 or later (the mitigation policy flags and `DeleteAppContainerProfile`).

## Test plan

1. DualSense over USB and Bluetooth, DualShock 4, Switch Pro, an Xbox pad: buttons, sticks, triggers, the touchpad,
   motion (head tilt), rumble; unplug and plug back in a level; two pads.
2. The log's `Input: ... input X ms old when read` before and after: the broker must not add more than ~2 ms.
3. The overlay's GPU usage against Task Manager.
4. Saves, trophies, the in-game menu's settings, frame generation (DLSS and FSR), "Apply and restart".
5. Online with an account, co-op with a second player.
6. A file outside the granted folders (a text file in Documents): the game must not be able to open it (a debug
   switch that tries, logged).
7. The setting off: grants and the profile removed.

## Work, in order

1. Done: `runtime_container.c`, outer side: profile, grants, launch, exit code; no broker yet (keyboard only). Tested
   offline: the game runs inside at 30 FPS, saves mount, caches are written, the exit code reaches `run.py`, nothing
   is left running; granting takes about 3.5 s the first time and 30 ms after. The shared section comes with step 2.
2. Broker loop and inner virtual gamepads: input, then rumble, LED, effects, sensors.
3. GPU usage through the broker; the overlay switch.
4. Launcher setting with the explanation, removal of grants and profile.
5. The test plan; then decide whether it can be on by default.
