#include "wireguard-platform.h"

#include <stdlib.h>
#include "crypto.h"
#include "lwip/sys.h"
#include "lwip/init.h"
#include "pico/time.h"
#include "pico.h"
#include "hardware/structs/rosc.h"
#include "hardware/rtc.h"
#include "pico/util/datetime.h"

// This file contains a Wireguard platform integration for Raspberry Pi Pico-W

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

// Convert a datetime_t from the Pico RTC into a roughly TAI64-compatible value of
// seconds since 1970. We don't need this to be strictly correct (which woud be needlessly
// complicated) but just to:
// - always produce the same result for the same value of datetime_t
// - always produce a larger value for later values of datatime_t
// These two properties are sufficient to give the "monotonically increasing" behaviour
// that is required for WireGuard handshake timestamps. This property will be maintained
// across power-off restarts, provided that the RTC remains correct (but that is not our
// responsibility here).
static uint64_t datetime_to_seconds(datetime_t *pDateTime) {
	const uint64_t days = 372 *(pDateTime->year - 1970) + 31 * (pDateTime->month - 1) + (pDateTime->day - 1);
	const uint64_t seconds = ((((days * 24) + pDateTime->hour) * 60) + pDateTime->min) * 60 + pDateTime->sec;
	return seconds;
}

// Get the system time in nanoseconds - HANDSHAKES WILL FAIL IF THIS DOESN'T INCREASE EACH TIME CALLED
void wireguard_tai64n_now(uint8_t *output) {
	// See https://cr.yp.to/libtai/tai64.html
	// 64 bit seconds from 1970 = 8 bytes
	// 32 bit nanoseconds from current second
	static uint64_t microseconds_base = 0;
	static uint64_t tai64seconds __attribute__((section(".uninitialized_data"))); // non-resetting time count
	const uint64_t microseconds_since_boot = to_us_since_boot(get_absolute_time());
	const uint64_t microseconds = microseconds_since_boot - microseconds_base; // usec increment
	if (0u == microseconds_base) { // first-time setup
		microseconds_base = microseconds_since_boot;
		// If the real-time clock (RTC) is running then we use that as the basis for timestamps
		// (we assume that the RTC will not be started until it has a valid time).
		// This allows the timestamps to be monotonically-increasing wrt. absolute time, and hence across
		// cold reboots, provided that the RTC is correct (or at least consistent), i.e. that it is either
		// maintained by battery or initialised from NTP at startup.
		if (rtc_running()) {
			// Once we have initialised tai64seconds and microseconds_base, here, all time is 
			// based on the system time (from the 64-bit microsecond counter). This ensures that there
			// is only one source of change, and hence that the timestamp is monotonically increasing.
			datetime_t t;
			rtc_get_datetime(&t);
			tai64seconds = datetime_to_seconds(&t);
		} else {
			// The RTC is not running (yet), so all we have to go by is the non-resetting count. If we're
			// coming out of a cold boot then we're probably stuffed, as the count will be random and hence
			// there is a high likelihood that timestamps based on it will be rejected by our WireGuard peers.
			// However, if we're coming out of a warm boot, but the RTC is not yet running, then the non-resetting
			// count may still be valid from the previous run, so we can keep using (and incrementing) it.
		}
	}
	const uint64_t seconds = microseconds / 1000000ull;
	tai64seconds += seconds; // increment the non-resetting time by the number of seconds since last call (or boot)
	microseconds_base += seconds * 1000000u;
	const uint32_t nanoseconds = (uint32_t)(microseconds % 1000000ull) * 1000ul;
	U64TO8_BIG(output + 0, tai64seconds); // TAI64N seconds
	U32TO8_BIG(output + 8, nanoseconds); // TAI64N nanoseconds
}

bool wireguard_is_under_load() {
	return false;
}

