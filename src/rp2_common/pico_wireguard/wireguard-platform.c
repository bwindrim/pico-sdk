#include "wireguard-platform.h"

#include <stdlib.h>
#include "crypto.h"
#include "lwip/sys.h"
#include "lwip/init.h"
#include "pico/time.h"
#include "pico.h"
#include "hardware/structs/rosc.h"

// This file contains a Wireguard platform integration for Raspberry Pi Pico/Pico-W

// Stolen from pico_lwip/random.c, as we can't link to it - BW
static uint8_t pico_lwip_random_byte(int cycles) {
    static uint8_t byte;
    assert(cycles >= 8);
    assert(rosc_hw->status & ROSC_STATUS_ENABLED_BITS);
    for(int i=0;i<cycles;i++) {
        // picked a fairly arbitrary polynomial of 0x35u - this doesn't have to be crazily uniform.
        byte = ((byte << 1) | rosc_hw->randombit) ^ (byte & 0x80u ? 0x35u : 0);
        // delay a little because the random bit is a little slow
        busy_wait_at_least_cycles(30);
    }
    return byte;
}

// We trust kilograham's random numbers to be better than rand() - BW
void wireguard_random_bytes(void *bytes, size_t size) {
	int x;
	uint8_t *out = (uint8_t *)bytes;
	for (x=0; x < size; x++) {
		out[x] = pico_lwip_random_byte(32);
	}
}

uint32_t wireguard_sys_now() {
	// This is what the LwIP system time defaults to - BW
	return to_ms_since_boot(get_absolute_time());
}

// Get the system time in nanoseconds - HANDSHAKES WILL FAIL IF THIS DOESN'T INCREASE EACH TIME CALLED
void wireguard_tai64n_now(uint8_t *output) {
	// See https://cr.yp.to/libtai/tai64.html
	// 64 bit seconds from 1970 = 8 bytes
	// 32 bit nano seconds from current second

	static uint64_t time_save __attribute__((section(".uninitialized_data"))); // non-resetting time count
	static uint64_t prev_now = 0ULL;
	uint64_t now = to_us_since_boot(get_absolute_time()); // microseconds since boot
	uint64_t diff = now - prev_now; // usec increase since last call, or since boot
	uint64_t microsec = time_save;
	time_save += (uint64_t)diff; // increment the non-resetting time by the number of usec since last call (or boot)

	// Split into seconds offset + nanos
	uint64_t seconds = 0x400000000000000aULL + (microsec / 1000000ULL);
	uint32_t nanos = (microsec % 1000000) * 1000;
	U64TO8_BIG(output + 0, seconds);
	U32TO8_BIG(output + 8, nanos);
}

bool wireguard_is_under_load() {
	return false;
}

