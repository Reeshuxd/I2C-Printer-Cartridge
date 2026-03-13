// ============================================================
//  PRINTER FIRMWARE  —  IIT Madras Printer Security Demo
// ============================================================

#include <Wire.h>
#include <string.h>

#define CART_ADDR  0x08
#define FRAME_SIZE 48
#define CHUNK      32
#define SYNC_BYTE  0xFF
#define MAX_PAGES  4

// framebuf[48] is immediately followed by auth_flag.
// Any write past offset 47 directly corrupts auth_flag.
struct __attribute__((packed)) {
    uint8_t framebuf[48];
    uint8_t auth_flag;
    uint8_t _pad[31];
} pmem;

const uint8_t INK_MASK[FRAME_SIZE] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
    0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
    0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
    0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
    0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x01
};

// ── CRC-8 (poly 0x07, init 0x00) ─────────────────────────────
uint8_t crc8(const uint8_t *data, uint8_t len) {
    uint8_t crc = 0x00;
    for (uint8_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (uint8_t b = 0; b < 8; b++)
            crc = (crc & 0x80) ? (crc << 1) ^ 0x07 : (crc << 1);
    }
    return crc;
}

// ── Hamming weight (popcount) ─────────────────────────────────
// Used by the power-attack analyser to count set bits per chunk.
uint16_t hamming_weight(const uint8_t *buf, uint8_t len) {
    uint16_t hw = 0;
    for (uint8_t i = 0; i < len; i++) {
        uint8_t v = buf[i];
        while (v) { hw += (v & 1); v >>= 1; }
    }
    return hw;
}

// ── sync_cartridge ───────────────────────────────────────────
void sync_cartridge() {
    Wire.beginTransmission(CART_ADDR);
    Wire.write(SYNC_BYTE);
    Wire.endTransmission();
    delay(100);
}

// ── prim_read ────────────────────────────────────────────────
// Reads claimed_len bytes from cartridge into pmem, verifying CRC.
bool prim_read(uint8_t claimed_len) {
    memset(&pmem, 0, sizeof(pmem));
    uint8_t *dst  = (uint8_t *)&pmem;
    uint8_t  idx  = 0;
    uint8_t  left = claimed_len;
    uint8_t  calls = 0;
    bool     any_crc_fail = false;

    while (left > 0) {
        uint8_t ask      = (left > CHUNK) ? CHUNK : left;
        uint8_t ask_wire = ask + 1;   // +1 for trailing CRC

        Wire.requestFrom((uint8_t)CART_ADDR, (uint8_t)ask_wire);

        uint8_t chunk_buf[CHUNK];
        uint8_t got = 0;
        while (Wire.available() && got < ask && idx < (uint8_t)sizeof(pmem)) {
            uint8_t byte_val = Wire.read();
            chunk_buf[got]  = byte_val;
            dst[idx++]      = byte_val;
            got++;
        }

        uint8_t rx_crc   = Wire.available() ? Wire.read() : 0xFF;
        uint8_t calc_crc = crc8(chunk_buf, got);

        if (rx_crc != calc_crc) {
            Serial.print(F("  [CRC]   FAIL chunk #")); Serial.print(calls);
            Serial.print(F(" rx=0x")); Serial.print(rx_crc,  HEX);
            Serial.print(F(" calc=0x")); Serial.println(calc_crc, HEX);
            any_crc_fail = true;
        } else {
            Serial.print(F("  [CRC]   OK   chunk #")); Serial.print(calls);
            Serial.print(F(" crc=0x")); Serial.println(rx_crc, HEX);
        }

        left -= ask;
        calls++;
        yield();
    }

    Serial.print(F("  [READ]  claimed_len=")); Serial.print(claimed_len);
    Serial.print(F("  calls="));              Serial.print(calls);
    Serial.print(F("  bytes_written="));      Serial.print(idx);
    Serial.print(F("  crc_faults="));         Serial.println(any_crc_fail ? "YES" : "none");

    if (pmem.auth_flag != 0x00) {
        Serial.print(F("\n  *** OVERFLOW DETECTED AFTER CRC PASSED ***\n"));
        Serial.print(F("  auth_flag=0x"));
        if (pmem.auth_flag < 0x10) Serial.print('0');
        Serial.print(pmem.auth_flag, HEX);
        Serial.println(F(" — CRC was valid. Cartridge forged it."));
        Serial.println(F("  LESSON: CRC cannot stop intentional manipulation."));
    }
    Serial.println();

    return (idx >= sizeof(pmem.framebuf));
}

// ── prim_read_timed ──────────────────────────────────────────
// Timing-attack-aware variant of prim_read.
// Reads num_chunks chunks of chunk_bytes each, measures round-trip
// time per chunk, decodes bits using TIMING_THRESHOLD_MS, and
// reconstructs the nibble the cartridge encoded in response latency.
// CRCs still pass — the covert channel is in the delay, not the data.
//
// Parameters:
//   num_chunks   — how many timed chunks to pull (≤ 4 for nibble decode)
//   chunk_bytes  — bytes per chunk (not counting the CRC byte)
//   threshold_ms — round-trip ≥ threshold → bit 1, else bit 0
//
void prim_read_timed(uint8_t num_chunks, uint8_t chunk_bytes,
                     uint8_t threshold_ms) {
    memset(&pmem, 0, sizeof(pmem));
    uint8_t *dst = (uint8_t *)&pmem;
    uint8_t  idx = 0;
    bool     any_crc_fail = false;

    Serial.println(F("  [TIMING] Measuring chunk round-trip latency..."));
    Serial.print  (F("  [TIMING] Threshold = ")); Serial.print(threshold_ms);
    Serial.println(F(" ms  |  slow=bit1  fast=bit0"));

    uint8_t decoded_nibble = 0;

    for (uint8_t c = 0; c < num_chunks; c++) {
        uint8_t ask_wire = chunk_bytes + 1;  // data + CRC

        // ── Measure round-trip time ───────────────────────────
        uint32_t t_start = millis();
        Wire.requestFrom((uint8_t)CART_ADDR, (uint8_t)ask_wire);
        uint32_t t_rtt = millis() - t_start;

        // ── Read chunk data ───────────────────────────────────
        uint8_t chunk_buf[CHUNK];
        uint8_t got = 0;
        while (Wire.available() && got < chunk_bytes &&
               idx < (uint8_t)sizeof(pmem)) {
            uint8_t byte_val = Wire.read();
            chunk_buf[got]  = byte_val;
            dst[idx++]      = byte_val;
            got++;
        }
        uint8_t rx_crc   = Wire.available() ? Wire.read() : 0xFF;
        uint8_t calc_crc = crc8(chunk_buf, got);

        if (rx_crc != calc_crc) {
            Serial.print(F("  [CRC]    FAIL chunk #")); Serial.print(c);
            Serial.print(F(" rx=0x")); Serial.print(rx_crc, HEX);
            Serial.print(F(" calc=0x")); Serial.println(calc_crc, HEX);
            any_crc_fail = true;
        } else {
            Serial.print(F("  [CRC]    OK   chunk #")); Serial.print(c);
            Serial.print(F(" crc=0x")); Serial.print(rx_crc, HEX);
            Serial.print(F("  rtt=")); Serial.print(t_rtt);
            Serial.print(F("ms"));

            // ── Bit decision ─────────────────────────────────
            uint8_t bit = (t_rtt >= threshold_ms) ? 1 : 0;
            decoded_nibble = (decoded_nibble << 1) | bit;

            Serial.print(F("  → bit")); Serial.print(3 - c);
            Serial.print(F("="));       Serial.println(bit);
        }

        yield();
    }

    Serial.println();
    Serial.println(F("  ┌─────────────────────────────────────────────┐"));
    Serial.print  (F("  │ TIMING ATTACK RESULT                        │\n"));
    Serial.print  (F("  │ Decoded nibble : 0x"));
    if (decoded_nibble < 0x10) Serial.print('0');
    Serial.print  (decoded_nibble, HEX);
    Serial.println(F("                          │"));
    Serial.println(F("  │ CRC verdict    : ALL PASSED                 │"));
    Serial.println(F("  │ LESSON: CRC is blind to timing side-channel │"));
    Serial.println(F("  └─────────────────────────────────────────────┘"));
    Serial.println();

    if (any_crc_fail)
        Serial.println(F("  [WARNING] Some chunks had CRC faults."));
}

// ── prim_read_power ──────────────────────────────────────────
// Power-analysis-aware variant of prim_read.
// Reads num_chunks chunks of CHUNK bytes each, computes the Hamming
// weight of each chunk, and reports the power profile.
// On real hardware HW=256 ↔ all SDA lines toggling = peak current draw;
// HW=0 ↔ no toggling = baseline current.  A power probe / EM antenna
// can distinguish these even when CRC integrity is satisfied.
//
void prim_read_power(uint8_t num_chunks) {
    memset(&pmem, 0, sizeof(pmem));
    uint8_t *dst = (uint8_t *)&pmem;
    uint8_t  idx = 0;
    bool     any_crc_fail = false;

    Serial.println(F("  [POWER]  Reading chunks & logging hamming weights..."));

    for (uint8_t c = 0; c < num_chunks; c++) {
        uint8_t ask_wire = CHUNK + 1;

        Wire.requestFrom((uint8_t)CART_ADDR, (uint8_t)ask_wire);

        uint8_t chunk_buf[CHUNK];
        uint8_t got = 0;
        while (Wire.available() && got < CHUNK &&
               idx < (uint8_t)sizeof(pmem)) {
            uint8_t byte_val = Wire.read();
            chunk_buf[got]  = byte_val;
            dst[idx++]      = byte_val;
            got++;
        }
        uint8_t rx_crc   = Wire.available() ? Wire.read() : 0xFF;
        uint8_t calc_crc = crc8(chunk_buf, got);

        uint16_t hw = hamming_weight(chunk_buf, got);

        if (rx_crc != calc_crc) {
            Serial.print(F("  [CRC]    FAIL chunk #")); Serial.print(c);
            Serial.print(F(" rx=0x")); Serial.print(rx_crc, HEX);
            Serial.print(F(" calc=0x")); Serial.println(calc_crc, HEX);
            any_crc_fail = true;
        } else {
            Serial.print(F("  [CRC]    OK   chunk #")); Serial.print(c);
            Serial.print(F(" crc=0x"));   Serial.print(rx_crc, HEX);
            Serial.print(F("  HW="));     Serial.print(hw);
            Serial.print(F("/"));         Serial.print(got * 8);

            // Simple visual power bar (each '#' = 16 HW units)
            Serial.print(F("  ["));
            uint8_t bars = (uint8_t)(hw / 16);
            for (uint8_t b = 0; b < 16; b++)
                Serial.print(b < bars ? '#' : '.');
            Serial.print(F("]  "));

            // Classify the power signature
            if (hw == (uint16_t)got * 8)
                Serial.println(F("← PEAK  (all 1s — max current)"));
            else if (hw == 0)
                Serial.println(F("← FLOOR (all 0s — min current)"));
            else
                Serial.println(F("← mixed"));
        }

        yield();
    }

    Serial.println();
    Serial.println(F("  ┌─────────────────────────────────────────────┐"));
    Serial.println(F("  │ POWER ATTACK RESULT                         │"));
    Serial.println(F("  │ Chunks alternate PEAK / FLOOR deliberately. │"));
    Serial.println(F("  │ A power trace distinguishes 0xFF from 0x00. │"));
    Serial.println(F("  │ CRC verdict    : ALL PASSED                 │"));
    Serial.println(F("  │ LESSON: CRC is blind to power side-channel  │"));
    Serial.println(F("  └─────────────────────────────────────────────┘"));
    Serial.println();

    if (any_crc_fail)
        Serial.println(F("  [WARNING] Some chunks had CRC faults."));
}

// ── prim_write ───────────────────────────────────────────────
void prim_write() {
    for (uint8_t i = 0; i < sizeof(pmem.framebuf); i++)
        pmem.framebuf[i] |= INK_MASK[i];
    Serial.println(F("  [WRITE] Ink mask applied."));
}

// ── prim_execute ─────────────────────────────────────────────
void prim_execute(uint8_t page_num) {
    Serial.print(F("  [EXEC]  Page ")); Serial.println(page_num);
    Serial.println(F("  +--------+"));
    for (uint8_t r = 0; r < 6; r++) {
        Serial.print(F("  |"));
        for (uint8_t c = 0; c < 8; c++) {
            uint8_t b = pmem.framebuf[r * 8 + c];
            for (int8_t bit = 7; bit >= 0; bit--)
                Serial.print((b >> bit) & 1 ? '#' : '.');
        }
        Serial.println(F("|"));
        delay(15);
    }
    Serial.println(F("  +--------+"));

    if (pmem.auth_flag == 0xAD) {
        Serial.println(F("\n  [!!] SERVICE MODE UNLOCKED"));
        Serial.println(F("       auth_flag=0xAD set by buffer overflow."));
        Serial.println(F("       CRC on the poisoned chunk was: VALID."));
        Serial.println(F("       Cartridge recalculated CRC after embedding 0xAD."));
        Serial.println(F("       CRC checked → passed → printer accepted 64 bytes"));
        Serial.println(F("       into a 48-byte buffer. Overflow wins anyway."));
    } else {
        Serial.println(F("  [OK]    auth_flag clean. Normal job."));
    }

    pmem.auth_flag = 0x00;
}

// ── run_job ──────────────────────────────────────────────────
void run_job() {
    sync_cartridge();

    // Read 3-byte header: page_count | frame_len | crc8(pc,fl)
    Wire.requestFrom((uint8_t)CART_ADDR, (uint8_t)3);
    if (!Wire.available()) {
        Serial.println(F("[ERR] No cartridge."));
        return;
    }

    uint8_t page_count = Wire.read();
    uint8_t frame_len  = Wire.available() ? Wire.read() : FRAME_SIZE;
    uint8_t rx_hcrc    = Wire.available() ? Wire.read() : 0x00;

    uint8_t hdr[2]     = { page_count, frame_len };
    uint8_t calc_hcrc  = crc8(hdr, 2);

    if (rx_hcrc != calc_hcrc) {
        Serial.print(F("[HDR CRC FAIL] rx=0x")); Serial.print(rx_hcrc, HEX);
        Serial.print(F(" calc=0x"));             Serial.println(calc_hcrc, HEX);
        Serial.println(F("Aborting job — header corrupt."));
        return;
    }
    Serial.print(F("[HDR CRC OK] 0x")); Serial.println(rx_hcrc, HEX);

    if (page_count == 0 || frame_len == 0) {
        Serial.println(F("[ERR] Zero header fields."));
        return;
    }

    Serial.print(F("\n=== JOB | pages="));
    Serial.print(page_count);
    Serial.print(F(" | frame_len="));
    Serial.print(frame_len);
    Serial.print(F(" | hdr_crc=0x"));
    Serial.println(rx_hcrc, HEX);

    // ── Detect TIMING attack ─────────────────────────────────
    // Heuristic: frame_len == 48, page_count == 1, but the payload
    // consists of 4 small chunks of 12 bytes (not 1.5 × CHUNK).
    // We detect this by checking if frame_len is exactly FRAME_SIZE
    // AND frame_len % CHUNK != 0 — meaning chunks won't be CHUNK-aligned.
    // Alternatively the printer could track timing variance across jobs.
    // Here we use a simple structural hint: 4 chunks of 12 bytes each.
    //
    // In a real system the printer would need a separate authenticated
    // channel to know which mode the cartridge is in. For the demo we
    // detect it from observed header values matching the cartridge's
    // TIMING mode specification (page_count==1, frame_len==48, and
    // the chunk granularity of 12 bytes revealed by frame_len/4).
    bool is_timing_job = (page_count == 1 && frame_len == 48 &&
                          (frame_len % 4) == 0 && (frame_len / 4) < CHUNK);

    // ── Detect POWER attack ──────────────────────────────────
    // The POWER mode sends frame_len=64 like OVERFLOW, but page_count==1.
    // OVERFLOW also sends page_count==1 and frame_len=64, so the printer
    // cannot distinguish them from the header alone — it will try to read
    // 64 bytes and discover the power profile in the chunk hamming weights.
    // We detect it post-read if auth_flag was NOT corrupted (the POWER
    // payload never writes past framebuf) and hamming variance was extreme.
    // For the demo we print the power analysis during the read phase.

    for (uint8_t p = 0; p < page_count; p++) {
        Serial.print(F("\n--- Page ")); Serial.print(p + 1);
        Serial.print(F("/")); Serial.println(page_count);

        if (is_timing_job) {
            // ── TIMING SIDE-CHANNEL JOB ───────────────────────
            Serial.println(F("  [DETECT] Timing side-channel job identified."));
            Serial.println(F("           frame_len=48 split into 4×12-byte chunks."));
            Serial.println(F("           Measuring per-chunk RTT to extract covert bits."));
            Serial.println();

            // 4 chunks × 12 bytes = 48. Threshold from cartridge spec.
            prim_read_timed(
                /*num_chunks=*/  4,
                /*chunk_bytes=*/ 12,
                /*threshold_ms=*/8
            );

            // The framebuf still got written (innocuous data); we can
            // still execute prim_write and prim_execute to show normal flow.
            prim_write();
            prim_execute(p + 1);

        } else {
            // ── STANDARD / OVERFLOW / DOS / POWER JOB ─────────
            // For POWER: frame_len=64 causes two CHUNK-sized reads.
            // prim_read fills framebuf + overflow region as normal.
            // After prim_read we check whether the two chunks showed
            // extreme hamming-weight contrast (power attack signature).

            if (!prim_read(frame_len)) {
                Serial.println(F("  [READ] Short read — skip."));
                continue;
            }

            // ── Power analysis on the received chunks ─────────
            // We retrospectively analyse: if frame_len == 64 AND
            // auth_flag was NOT set (not an overflow), it's a power job.
            // We log the hamming weights of the two halves of framebuf.
            bool looks_like_power = (frame_len == 64 && pmem.auth_flag == 0x00);
            if (looks_like_power) {
                Serial.println(F("  [DETECT] Power side-channel signature detected."));
                Serial.println(F("           frame_len=64, auth_flag clean (not overflow)."));
                Serial.println(F("           Analysing hamming weights of received chunks..."));
                Serial.println();

                uint16_t hw1 = hamming_weight(pmem.framebuf,      CHUNK);
                uint16_t hw2 = hamming_weight(pmem.framebuf + CHUNK, CHUNK);

                Serial.print(F("  [POWER]  Chunk 1 HW = ")); Serial.print(hw1);
                Serial.print(F(" / ")); Serial.print(CHUNK * 8);
                Serial.print(F("  ["));
                for (uint8_t b = 0; b < 16; b++)
                    Serial.print(b < (hw1 / 16) ? '#' : '.');
                Serial.println(F("]"));

                Serial.print(F("  [POWER]  Chunk 2 HW = ")); Serial.print(hw2);
                Serial.print(F(" / ")); Serial.print(CHUNK * 8);
                Serial.print(F("  ["));
                for (uint8_t b = 0; b < 16; b++)
                    Serial.print(b < (hw2 / 16) ? '#' : '.');
                Serial.println(F("]"));

                Serial.println();
                Serial.println(F("  ┌─────────────────────────────────────────────┐"));
                Serial.println(F("  │ POWER ATTACK RESULT                         │"));
                Serial.println(F("  │ Chunk 1 ≈ all-1s → peak bus switching       │"));
                Serial.println(F("  │ Chunk 2 ≈ all-0s → no bus switching         │"));
                Serial.println(F("  │ CRC verdict : ALL PASSED                    │"));
                Serial.println(F("  │ LESSON: CRC is blind to power side-channel  │"));
                Serial.println(F("  └─────────────────────────────────────────────┘"));
                Serial.println();
            }

            prim_write();
            prim_execute(p + 1);
        }
    }

    Serial.println(F("\n=== JOB DONE ===\n"));
}

// ── Arduino entry points ─────────────────────────────────────
void setup() {
    Serial.begin(115200);
    Wire.begin(21, 22);
    Wire.setTimeout(500);
    memset(&pmem, 0, sizeof(pmem));
    delay(2000);

    Serial.println(F("=== PRINTER v3 | IIT Madras Printer Security ==="));
    Serial.println(F("  CRC-8 verification enabled on all packets."));
    Serial.println(F("  Attack sequence: NORMAL, OVERFLOW, DoS, TIMING, POWER."));
    Serial.println(F("  Type 'print' to run a job."));
    Serial.println(F("================================================\n"));
}

void loop() {
    if (!Serial.available()) return;
    String s = Serial.readStringUntil('\n');
    s.trim();
    s.toLowerCase();
    if (s == "print") run_job();
    else Serial.println(F("Command: print"));
}
