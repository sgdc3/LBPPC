/* lbppc: the controller broker for the game in an AppContainer (docs/appcontainer-broker.md, step 2).
 *
 * Inside an AppContainer SDL can't open a DualSense, DualShock 4 or Switch Pro (HID). The process outside
 * (runtime_container.c) reads them with SDL and publishes each one in a shared memory section; inside, each becomes
 * an SDL virtual gamepad with the same name, type, IDs, touchpad and motion sensors, so runtime_pad.c sees ordinary
 * gamepads and is unchanged. Rumble, trigger rumble, the light bar and effects go back the same way.
 *
 * The section is the only link: an unnamed mapping the game gets by handle inheritance. Each slot is written by one
 * side only, under a sequence lock (odd while being written). The broker checks what the game writes (sizes, the slot)
 * before any SDL call and reads nothing else from it. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runtime.h"

#ifndef _WIN32
void *runtime_broker_create(void) { return NULL; }
void runtime_broker_child_environment(int set) { (void)set; }
void runtime_broker_run(void *process) { (void)process; }
void runtime_broker_attach(void) {}
#else
#include <windows.h>
#include <SDL3/SDL.h>

#define BROKER_MAGIC 0x4b52424cu /* 'LBRK' */
#define BROKER_VERSION 1u
#define BROKER_PADS 8
#define BROKER_EFFECT 64

typedef struct {
    float x, y, pressure;
    uint8_t down, unused[3];
} BrokerFinger;

typedef struct { /* broker -> game */
    volatile LONG seq;
    uint32_t generation; /* changes when another pad takes the slot */
    uint8_t connected, has_accel, has_gyro, fingers; /* fingers: on touchpad 0, 0 when it has none */
    uint16_t vendor, product;
    char name[64];
    int16_t axes[SDL_GAMEPAD_AXIS_COUNT]; /* as the gamepad reports them (triggers 0..32767) */
    uint32_t buttons;                     /* bit = SDL_GamepadButton */
    BrokerFinger finger[2];
    uint32_t sensor_seq;                  /* changes with each new sample */
    float accel_rate, gyro_rate;
    uint64_t sensor_timestamp_ns;
    float accel[3], gyro[3];
} BrokerPad;

typedef struct { /* game -> broker: the only part the game writes */
    volatile LONG seq;
    uint16_t low, high, left_trigger, right_trigger;
    uint8_t led_set, led[3];
    uint8_t effect_size, unused[3];
    uint32_t effect_count;
    uint8_t effect[BROKER_EFFECT];
} BrokerOut;

typedef struct {
    uint32_t magic, version, size, unused;
    volatile LONG64 heartbeat;
    BrokerPad pad[BROKER_PADS];
    BrokerOut out[BROKER_PADS];
} BrokerShared;

static BrokerShared *shared;

static void write_begin(volatile LONG *seq) { InterlockedIncrement(seq); } /* odd: being written */
static void write_end(volatile LONG *seq) { InterlockedIncrement(seq); }   /* even again, after a full barrier */
/* A consistent copy of what the other side writes under seq. */
static void read_copy(volatile LONG *seq, const volatile void *from, void *to, size_t size) {
    for (int tries = 0; tries < 1000; ++tries) {
        const LONG before = *seq;
        MemoryBarrier();
        if (before & 1) { YieldProcessor(); continue; }
        memcpy(to, (const void *)from, size);
        MemoryBarrier();
        if (*seq == before) return;
    }
    memset(to, 0, size); /* never settled: as if nothing were there */
}

/* ---- outside: the broker -------------------------------------------------------------------------------------- */

void *runtime_broker_create(void) {
    SECURITY_ATTRIBUTES inherit = {sizeof(inherit), NULL, TRUE};
    HANDLE section = CreateFileMappingW(INVALID_HANDLE_VALUE, &inherit, PAGE_READWRITE, 0, sizeof(BrokerShared), NULL);
    if (!section) return NULL;
    shared = MapViewOfFile(section, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(BrokerShared));
    if (!shared) {
        CloseHandle(section);
        return NULL;
    }
    memset(shared, 0, sizeof(*shared));
    shared->magic = BROKER_MAGIC;
    shared->version = BROKER_VERSION;
    shared->size = sizeof(BrokerShared);
    char value[32];
    snprintf(value, sizeof(value), "%llu", (unsigned long long)(uintptr_t)section);
    SetEnvironmentVariableA("LBPPC_BROKER", value);
    return section;
}

/* Inside, SDL sees only the virtual pads: every real joystick backend off (an Xbox pad through XInput would
   otherwise count twice). Set for the game's start only; this process's own SDL needs them. */
void runtime_broker_child_environment(int set) {
    static const char *const hints[] = {"SDL_JOYSTICK_HIDAPI", "SDL_JOYSTICK_RAWINPUT", "SDL_JOYSTICK_XINPUT",
                                        "SDL_JOYSTICK_DIRECTINPUT", "SDL_JOYSTICK_WGI", "SDL_JOYSTICK_GAMEINPUT"};
    for (size_t i = 0; i < sizeof(hints) / sizeof(*hints); ++i) SetEnvironmentVariableA(hints[i], set ? "0" : NULL);
    if (!set) SetEnvironmentVariableA("LBPPC_BROKER", NULL);
}

typedef struct {
    SDL_Gamepad *gamepad;
    SDL_JoystickID id;
    BrokerOut applied; /* the last request carried out */
    uint64_t rumble_sent_ms, triggers_sent_ms;
} BrokerSlot;

static uint32_t generations;

static void publish_open(BrokerSlot *slot, int index) {
    BrokerPad *p = &shared->pad[index];
    SDL_Gamepad *g = slot->gamepad;
    write_begin(&p->seq);
    p->generation = ++generations;
    p->connected = 1;
    p->vendor = SDL_GetGamepadVendor(g);
    p->product = SDL_GetGamepadProduct(g);
    const char *name = SDL_GetGamepadName(g);
    snprintf(p->name, sizeof(p->name), "%s", name ? name : "Controller");
    p->has_accel = SDL_GamepadHasSensor(g, SDL_SENSOR_ACCEL) && SDL_SetGamepadSensorEnabled(g, SDL_SENSOR_ACCEL, true);
    p->has_gyro = SDL_GamepadHasSensor(g, SDL_SENSOR_GYRO) && SDL_SetGamepadSensorEnabled(g, SDL_SENSOR_GYRO, true);
    p->accel_rate = p->has_accel ? SDL_GetGamepadSensorDataRate(g, SDL_SENSOR_ACCEL) : 0.0f;
    p->gyro_rate = p->has_gyro ? SDL_GetGamepadSensorDataRate(g, SDL_SENSOR_GYRO) : 0.0f;
    const int fingers = SDL_GetNumGamepadTouchpads(g) > 0 ? SDL_GetNumGamepadTouchpadFingers(g, 0) : 0;
    p->fingers = (uint8_t)(fingers > 2 ? 2 : fingers < 0 ? 0 : fingers);
    write_end(&p->seq);
    memset(&slot->applied, 0, sizeof(slot->applied));
    read_copy(&shared->out[index].seq, &shared->out[index], &slot->applied, sizeof(slot->applied));
    printf("Broker: %s in slot %d (motion sensors: %s)\n", p->name, index, p->has_gyro ? "yes" : "no");
    fflush(stdout);
}

static void publish_state(BrokerSlot *slot, int index) {
    BrokerPad *p = &shared->pad[index];
    SDL_Gamepad *g = slot->gamepad;
    float accel[3] = {0}, gyro[3] = {0};
    const int new_accel = p->has_accel && SDL_GetGamepadSensorData(g, SDL_SENSOR_ACCEL, accel, 3);
    const int new_gyro = p->has_gyro && SDL_GetGamepadSensorData(g, SDL_SENSOR_GYRO, gyro, 3);
    write_begin(&p->seq);
    for (int a = 0; a < SDL_GAMEPAD_AXIS_COUNT; ++a) p->axes[a] = SDL_GetGamepadAxis(g, (SDL_GamepadAxis)a);
    uint32_t buttons = 0;
    for (int b = 0; b < SDL_GAMEPAD_BUTTON_COUNT && b < 32; ++b)
        if (SDL_GetGamepadButton(g, (SDL_GamepadButton)b)) buttons |= 1u << b;
    p->buttons = buttons;
    for (int f = 0; f < p->fingers; ++f) {
        bool down = false;
        float x = 0, y = 0, pressure = 0;
        SDL_GetGamepadTouchpadFinger(g, 0, f, &down, &x, &y, &pressure);
        p->finger[f] = (BrokerFinger){x, y, pressure, (uint8_t)down, {0}};
    }
    if ((new_accel && memcmp(accel, p->accel, sizeof(accel))) || (new_gyro && memcmp(gyro, p->gyro, sizeof(gyro)))) {
        memcpy(p->accel, accel, sizeof(accel));
        memcpy(p->gyro, gyro, sizeof(gyro));
        p->sensor_timestamp_ns = SDL_GetTicksNS();
        ++p->sensor_seq;
    }
    write_end(&p->seq);
}

static void publish_closed(int index) {
    BrokerPad *p = &shared->pad[index];
    write_begin(&p->seq);
    p->connected = 0;
    write_end(&p->seq);
}

/* What the game asked of this pad, checked, then done. Rumble is sent again each second while it lasts (SDL's own
   rumble stops after its duration; the game's stop arrives as zeros). */
static void apply_requests(BrokerSlot *slot, int index) {
    BrokerOut want;
    read_copy(&shared->out[index].seq, &shared->out[index], &want, sizeof(want));
    SDL_Gamepad *g = slot->gamepad;
    const uint64_t now = SDL_GetTicks();
    BrokerOut *had = &slot->applied;
    if (want.low != had->low || want.high != had->high || ((want.low || want.high) && now - slot->rumble_sent_ms >= 1000)) {
        SDL_RumbleGamepad(g, want.low, want.high, want.low || want.high ? 2000 : 0);
        slot->rumble_sent_ms = now;
    }
    if (want.left_trigger != had->left_trigger || want.right_trigger != had->right_trigger ||
        ((want.left_trigger || want.right_trigger) && now - slot->triggers_sent_ms >= 1000)) {
        SDL_RumbleGamepadTriggers(g, want.left_trigger, want.right_trigger,
                                  want.left_trigger || want.right_trigger ? 2000 : 0);
        slot->triggers_sent_ms = now;
    }
    if (want.led_set && (!had->led_set || memcmp(want.led, had->led, 3)))
        SDL_SetGamepadLED(g, want.led[0], want.led[1], want.led[2]);
    if (want.effect_count != had->effect_count && want.effect_size && want.effect_size <= BROKER_EFFECT)
        SDL_SendGamepadEffect(g, want.effect, want.effect_size);
    *had = want;
}

void runtime_broker_run(void *process) {
    SDL_SetHint(SDL_HINT_JOYSTICK_ALLOW_BACKGROUND_EVENTS, "1"); /* no window here, never focused */
    if (!shared || !SDL_InitSubSystem(SDL_INIT_GAMEPAD)) {
        fprintf(stderr, "Broker: no controllers for the game (%s)\n", shared ? SDL_GetError() : "no shared memory");
        WaitForSingleObject(process, INFINITE);
        return;
    }
    HANDLE timer = CreateWaitableTimerExW(NULL, NULL, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    if (!timer) timer = CreateWaitableTimerW(NULL, FALSE, NULL);
    BrokerSlot slots[BROKER_PADS];
    memset(slots, 0, sizeof(slots));
    for (;;) {
        /* Every 2 ms: a DualSense report is about 4 ms apart over Bluetooth, 1 ms over USB. */
        LARGE_INTEGER due = {.QuadPart = -20000};
        SetWaitableTimer(timer, &due, 0, NULL, NULL, FALSE);
        HANDLE waits[2] = {process, timer};
        if (WaitForMultipleObjects(2, waits, FALSE, INFINITE) != WAIT_OBJECT_0 + 1) break;

        SDL_PumpEvents();
        SDL_FlushEvents(SDL_EVENT_FIRST, SDL_EVENT_LAST);
        SDL_UpdateGamepads();
        for (int i = 0; i < BROKER_PADS; ++i) {
            if (slots[i].gamepad && !SDL_GamepadConnected(slots[i].gamepad)) {
                printf("Broker: slot %d disconnected\n", i);
                fflush(stdout);
                SDL_CloseGamepad(slots[i].gamepad);
                memset(&slots[i], 0, sizeof(slots[i]));
                publish_closed(i);
            }
        }
        int count = 0;
        SDL_JoystickID *ids = SDL_GetGamepads(&count);
        for (int k = 0; ids && k < count; ++k) {
            int known = 0, free_slot = -1;
            for (int i = 0; i < BROKER_PADS; ++i) {
                if (slots[i].gamepad && slots[i].id == ids[k]) known = 1;
                if (!slots[i].gamepad && free_slot < 0) free_slot = i;
            }
            if (known || free_slot < 0) continue;
            SDL_Gamepad *g = SDL_OpenGamepad(ids[k]);
            if (!g) continue;
            slots[free_slot].gamepad = g;
            slots[free_slot].id = ids[k];
            publish_open(&slots[free_slot], free_slot);
        }
        SDL_free(ids);
        for (int i = 0; i < BROKER_PADS; ++i) {
            if (!slots[i].gamepad) continue;
            publish_state(&slots[i], i);
            apply_requests(&slots[i], i);
        }
        InterlockedExchange64(&shared->heartbeat, (LONG64)SDL_GetTicks());
    }
    for (int i = 0; i < BROKER_PADS; ++i)
        if (slots[i].gamepad) SDL_CloseGamepad(slots[i].gamepad);
    if (timer) CloseHandle(timer);
    SDL_QuitSubSystem(SDL_INIT_GAMEPAD);
}

/* ---- inside: virtual gamepads -------------------------------------------------------------------------------- */

static SDL_JoystickID virtual_id[BROKER_PADS];
static uint32_t virtual_generation[BROKER_PADS];
static uint32_t virtual_sensor_seq[BROKER_PADS];

static void SDLCALL virtual_update(void *userdata) {
    const int index = (int)(intptr_t)userdata;
    BrokerPad p;
    read_copy(&shared->pad[index].seq, &shared->pad[index], &p, sizeof(p));
    SDL_Joystick *joystick = SDL_GetJoystickFromID(virtual_id[index]);
    if (!joystick || !p.connected) return;
    for (int a = 0; a < SDL_GAMEPAD_AXIS_COUNT; ++a) {
        int value = p.axes[a];
        /* Triggers go over the whole Sint16 range on a virtual joystick (at rest: the minimum). */
        if (a == SDL_GAMEPAD_AXIS_LEFT_TRIGGER || a == SDL_GAMEPAD_AXIS_RIGHT_TRIGGER) value = value * 2 - 32768;
        SDL_SetJoystickVirtualAxis(joystick, a, (Sint16)(value < -32768 ? -32768 : value > 32767 ? 32767 : value));
    }
    for (int b = 0; b < SDL_GAMEPAD_BUTTON_COUNT && b < 32; ++b)
        SDL_SetJoystickVirtualButton(joystick, b, (p.buttons >> b) & 1);
    for (int f = 0; f < p.fingers && f < 2; ++f)
        SDL_SetJoystickVirtualTouchpad(joystick, 0, f, p.finger[f].down, p.finger[f].x, p.finger[f].y,
                                       p.finger[f].pressure);
    if (p.sensor_seq != virtual_sensor_seq[index]) {
        virtual_sensor_seq[index] = p.sensor_seq;
        if (p.has_accel) SDL_SendJoystickVirtualSensorData(joystick, SDL_SENSOR_ACCEL, p.sensor_timestamp_ns, p.accel, 3);
        if (p.has_gyro) SDL_SendJoystickVirtualSensorData(joystick, SDL_SENSOR_GYRO, p.sensor_timestamp_ns, p.gyro, 3);
    }
}

static BrokerOut *out_for(void *userdata) { return &shared->out[(int)(intptr_t)userdata]; }
static bool SDLCALL virtual_rumble(void *userdata, Uint16 low, Uint16 high) {
    BrokerOut *o = out_for(userdata);
    write_begin(&o->seq);
    o->low = low;
    o->high = high;
    write_end(&o->seq);
    return true;
}
static bool SDLCALL virtual_rumble_triggers(void *userdata, Uint16 left, Uint16 right) {
    BrokerOut *o = out_for(userdata);
    write_begin(&o->seq);
    o->left_trigger = left;
    o->right_trigger = right;
    write_end(&o->seq);
    return true;
}
static bool SDLCALL virtual_led(void *userdata, Uint8 red, Uint8 green, Uint8 blue) {
    BrokerOut *o = out_for(userdata);
    write_begin(&o->seq);
    o->led_set = 1;
    o->led[0] = red;
    o->led[1] = green;
    o->led[2] = blue;
    write_end(&o->seq);
    return true;
}
static bool SDLCALL virtual_effect(void *userdata, const void *data, int size) {
    if (!data || size <= 0 || size > BROKER_EFFECT) return false;
    BrokerOut *o = out_for(userdata);
    write_begin(&o->seq);
    memcpy(o->effect, data, (size_t)size);
    o->effect_size = (uint8_t)size;
    ++o->effect_count;
    write_end(&o->seq);
    return true;
}
static bool SDLCALL virtual_sensors(void *userdata, bool enabled) {
    (void)userdata; (void)enabled; /* the broker keeps the real pad's sensors on */
    return true;
}

static void attach(int index, const BrokerPad *p) {
    SDL_VirtualJoystickTouchpadDesc touchpad = {p->fingers, {0}};
    SDL_VirtualJoystickSensorDesc sensors[2];
    int sensor_count = 0;
    if (p->has_accel) sensors[sensor_count++] = (SDL_VirtualJoystickSensorDesc){SDL_SENSOR_ACCEL, p->accel_rate};
    if (p->has_gyro) sensors[sensor_count++] = (SDL_VirtualJoystickSensorDesc){SDL_SENSOR_GYRO, p->gyro_rate};
    SDL_VirtualJoystickDesc desc;
    SDL_INIT_INTERFACE(&desc);
    desc.type = SDL_JOYSTICK_TYPE_GAMEPAD;
    desc.vendor_id = p->vendor;
    desc.product_id = p->product;
    desc.naxes = SDL_GAMEPAD_AXIS_COUNT;
    desc.nbuttons = SDL_GAMEPAD_BUTTON_COUNT;
    desc.axis_mask = (1u << SDL_GAMEPAD_AXIS_COUNT) - 1;
    desc.button_mask = (uint32_t)((1ull << SDL_GAMEPAD_BUTTON_COUNT) - 1);
    desc.ntouchpads = p->fingers ? 1 : 0;
    desc.touchpads = p->fingers ? &touchpad : NULL;
    desc.nsensors = (Uint16)sensor_count;
    desc.sensors = sensor_count ? sensors : NULL;
    desc.name = p->name;
    desc.userdata = (void *)(intptr_t)index;
    desc.Update = virtual_update;
    desc.Rumble = virtual_rumble;
    desc.RumbleTriggers = virtual_rumble_triggers;
    desc.SetLED = virtual_led;
    desc.SendEffect = virtual_effect;
    desc.SetSensorsEnabled = virtual_sensors;
    virtual_id[index] = SDL_AttachVirtualJoystick(&desc);
    virtual_generation[index] = p->generation;
    if (virtual_id[index]) printf("Broker: %s attached for the game\n", p->name);
    else fprintf(stderr, "Broker: %s could not be attached (%s)\n", p->name, SDL_GetError());
    fflush(stdout);
}

/* Follows the broker's slots: a virtual gamepad for each real one, gone when it goes. */
static DWORD WINAPI follow_slots(void *unused) {
    (void)unused;
    for (;;) {
        Sleep(100);
        if (!SDL_WasInit(SDL_INIT_JOYSTICK)) continue; /* the game's SDL isn't up yet */
        for (int i = 0; i < BROKER_PADS; ++i) {
            BrokerPad p;
            read_copy(&shared->pad[i].seq, &shared->pad[i], &p, sizeof(p));
            if (virtual_id[i] && (!p.connected || p.generation != virtual_generation[i])) {
                SDL_DetachVirtualJoystick(virtual_id[i]);
                virtual_id[i] = 0;
            }
            if (!virtual_id[i] && p.connected) attach(i, &p);
        }
    }
    return 0;
}

void runtime_broker_attach(void) {
    const char *value = getenv("LBPPC_BROKER");
    if (!value || !*value) return;
    HANDLE section = (HANDLE)(uintptr_t)strtoull(value, NULL, 10);
    BrokerShared *view = MapViewOfFile(section, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(BrokerShared));
    if (!view || view->magic != BROKER_MAGIC || view->version != BROKER_VERSION || view->size != sizeof(BrokerShared)) {
        fprintf(stderr, "Broker: no usable shared memory from the broker; no controllers\n");
        if (view) UnmapViewOfFile(view);
        return;
    }
    shared = view;
    HANDLE thread = CreateThread(NULL, 0, follow_slots, NULL, 0, NULL);
    if (thread) CloseHandle(thread);
}
#endif
