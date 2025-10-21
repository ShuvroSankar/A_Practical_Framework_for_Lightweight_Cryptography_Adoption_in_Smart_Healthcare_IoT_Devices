// MASTER: ESP32 + MAX30102 -> ASCON-128 -> ESP-NOW -> ESP32-C6
#include <Wire.h>
#include "MAX30105.h"
#include "heartRate.h"
#include <WiFi.h>
#include <esp_now.h>
#include <ASCON.h>   // rweather/ascon-suite

#define WIFI_CH 6
const byte RATE_SIZE = 4;

// ==== Goodput test switches ====
#define RUN_STREAM_GOODPUT    1      // 1 = run test at boot, 0 = skip
#define GOODPUT_ONLY          1      // 1 = run test then halt; 0 = continue normal loop
#define GOODPUT_MS            5000   // test duration (ms)
#define GOODPUT_INTERVAL_MS   0      // 0=max rate; 100 ~10 Hz, etc.

// ==== Flow control for ESP-NOW flood ====
#define MAX_INFLIGHT          8
static volatile uint16_t inflight = 0;
static volatile uint32_t tx_ack_ok = 0, tx_ack_fail = 0;

// Paste the SLAVE MAC (from its Serial)
uint8_t SLAVE_MAC[6] = { 0x40, 0x4C, 0xCA, 0x4C, 0x6E, 0x60 };

// === ASCON demo key (replace in production) ===
static const uint8_t K[16] = {
  0x60,0x4A,0x2C,0x10,0x91,0x22,0x33,0x44,0x55,0x66,0x87,0x98,0xAA,0xBB,0xCC,0xDD
};

// Heart-rate globals
MAX30105 particleSensor;
byte  rates[RATE_SIZE] = {0};
byte  rateSpot = 0;
long  lastBeat = 0;
float beatsPerMinute = 0;
int   beatAvg = 0;
uint32_t g_counter = 0;

struct __attribute__((packed)) HRPacket {
  uint32_t ts_ms;
  uint32_t ir;
  float    bpm;
  uint16_t avg;
  uint8_t  finger;
};

// Packet size for buffer pool
static const size_t PKT_MAX = 4 + 16 + sizeof(HRPacket) + ASCON128_TAG_SIZE;
static uint8_t pkt_pool[MAX_INFLIGHT][PKT_MAX];

static void fill_nonce(uint8_t nonce[16], uint32_t ctr) {
  for (int i=0;i<12;i+=4) { uint32_t r = esp_random(); memcpy(nonce+i, &r, 4); }
  memcpy(nonce+12, &ctr, 4);
}

void onSent(const uint8_t*, esp_now_send_status_t s) {
  if (s == ESP_NOW_SEND_SUCCESS) tx_ack_ok++; else tx_ack_fail++;
  if (inflight) inflight--;
}

// ====== GOODPUT: build packet into provided buffer; return length ======
static inline size_t build_packet_into(uint8_t* pkt_out, bool minimal_payload) {
  HRPacket plain{
    .ts_ms = (uint32_t)millis(),
    .ir    = minimal_payload ? 0 : (uint32_t)0, // real IR filled in normal loop
    .bpm   = minimal_payload ? 0.0f : beatsPerMinute,
    .avg   = minimal_payload ? 0    : (uint16_t)beatAvg,
    .finger= 1
  };

  // AAD = counter || master_mac
  uint8_t ad[4 + 6];
  memcpy(ad, &g_counter, 4);
  uint8_t mymac[6]; WiFi.macAddress(mymac);
  memcpy(ad+4, mymac, 6);

  // Nonce
  uint8_t nonce[16]; fill_nonce(nonce, g_counter);

  // Encrypt: cipher || tag
  uint8_t cipher[sizeof(HRPacket) + ASCON128_TAG_SIZE];
  size_t  clen = 0;
  ascon128_aead_encrypt(cipher, &clen,
                        (const uint8_t*)&plain, sizeof(plain),
                        ad, sizeof(ad),
                        nonce, K);
  const size_t ct_len = clen - ASCON128_TAG_SIZE;
  const uint8_t *tag  = cipher + ct_len;

  // Wire packet: counter | nonce | ciphertext | tag
  uint8_t *p = pkt_out;
  memcpy(p, &g_counter, 4);            p+=4;
  memcpy(p, nonce, 16);                p+=16;
  memcpy(p, cipher, ct_len);           p+=ct_len;
  memcpy(p, tag, ASCON128_TAG_SIZE);   p+=ASCON128_TAG_SIZE;

  return (size_t)(p - pkt_out);
}

// ====== GOODPUT runner ======
void run_stream_goodput(uint32_t duration_ms, uint16_t interval_ms) {
  Serial.println("# STREAM goodput test (ciphertext bytes/sec)");
  const size_t P = sizeof(HRPacket) + ASCON128_TAG_SIZE + 4 + 16;

  tx_ack_ok = tx_ack_fail = 0;
  inflight = 0;

  uint32_t t0 = millis();
  uint32_t bytes_attempt = 0, pkts_attempt = 0;
  uint32_t next_send = millis();
  uint8_t  buf_idx = 0;

  while ((millis() - t0) < duration_ms) {
    // Pace to target rate
    if (interval_ms && (int32_t)(millis() - next_send) < 0) { delay(1); continue; }

    // Back-pressure: cap in-flight frames
    if (inflight >= MAX_INFLIGHT) { delay(0); continue; }

    // Build into a free buffer (minimal payload to keep CPU cost low)
    uint8_t* pkt = pkt_pool[buf_idx];
    size_t pkt_len = build_packet_into(pkt, /*minimal_payload=*/true);

    // Queue for TX
    esp_err_t rc = esp_now_send(SLAVE_MAC, pkt, pkt_len);
    if (rc == ESP_OK) {
      inflight++;
      bytes_attempt += pkt_len;
      pkts_attempt++;
      g_counter++;
      buf_idx = (uint8_t)((buf_idx + 1) % MAX_INFLIGHT);
      if (interval_ms) next_send += interval_ms;
    } else {
      // Queue full / not ready — brief backoff
      delay(1);
    }
  }

  // Drain callbacks so ACK counts are final
  uint32_t drain_t0 = millis();
  while (inflight && (millis() - drain_t0) < 200) delay(1);
  delay(50);

  float secs = (millis() - t0) / 1000.0f;
  float attempt_bps = bytes_attempt / secs;
  float ack_bps     = (tx_ack_ok * P) / secs;

  Serial.printf("GOODPUT,%.2f s,attempt=%u bytes,%u pkts,%.2f bytes/s, ACK_OK=%lu, ACK_FAIL=%lu, ack_bytes/s=%.2f, bytes/packet=%u\n",
                secs, bytes_attempt, pkts_attempt, attempt_bps,
                (unsigned long)tx_ack_ok, (unsigned long)tx_ack_fail,
                ack_bps, (unsigned)P);
}

// ===================== normal telemetry helpers =====================
long readIRandUpdateHR() {
  long ir = particleSensor.getIR();
  if (checkForBeat(ir)) {
    long delta = millis() - lastBeat; lastBeat = millis();
    beatsPerMinute = 60.0f / (delta / 1000.0f);
    if (beatsPerMinute > 20 && beatsPerMinute < 255) {
      rates[rateSpot++] = (byte)beatsPerMinute; rateSpot %= RATE_SIZE;
      int sum=0; for (byte i=0;i<RATE_SIZE;i++) sum += rates[i];
      beatAvg = sum / RATE_SIZE;
    }
  }
  return ir;
}

void setup() {
  Serial.begin(115200);
  delay(200);

  // ESP-NOW first (needed for goodput)
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.setChannel(WIFI_CH);
  if (esp_now_init() != ESP_OK) { Serial.println("esp_now_init failed"); while(1){} }
  esp_now_register_send_cb(onSent);

  esp_now_peer_info_t peer{};
  memcpy(peer.peer_addr, SLAVE_MAC, 6);
  peer.channel = WIFI_CH; peer.encrypt = false;  // AEAD is end-to-end
  if (esp_now_add_peer(&peer) != ESP_OK) { Serial.println("add_peer failed"); while(1){} }

#if RUN_STREAM_GOODPUT
  run_stream_goodput(GOODPUT_MS, GOODPUT_INTERVAL_MS);
#if GOODPUT_ONLY
  while (true) { delay(1000); }  // keep output clean after test
#endif
#endif

  // Sensor (used only when GOODPUT_ONLY == 0)
  if (!particleSensor.begin(Wire, I2C_SPEED_FAST)) { Serial.println("MAX30105 not found"); while(1){} }
  particleSensor.setup();
  particleSensor.setPulseAmplitudeRed(0x0A);
  particleSensor.setPulseAmplitudeGreen(0);

  Serial.print("MASTER MAC: "); Serial.println(WiFi.macAddress());
}

void loop() {
#if RUN_STREAM_GOODPUT && GOODPUT_ONLY
  // never reached
#else
  // Normal ~10 Hz encrypted telemetry
  long ir = readIRandUpdateHR();

  HRPacket plain{
    .ts_ms = (uint32_t)millis(),
    .ir    = (uint32_t)ir,
    .bpm   = beatsPerMinute,
    .avg   = (uint16_t)beatAvg,
    .finger= (ir >= 50000) ? 1 : 0
  };

  // AAD = counter || master_mac
  uint8_t ad[4 + 6];
  memcpy(ad, &g_counter, 4);
  uint8_t mymac[6]; WiFi.macAddress(mymac);
  memcpy(ad+4, mymac, 6);

  uint8_t nonce[16]; fill_nonce(nonce, g_counter);

  // Encrypt: cipher || tag
  uint8_t cipher[sizeof(HRPacket) + ASCON128_TAG_SIZE];
  size_t  clen = 0;
  ascon128_aead_encrypt(cipher, &clen,
                        (const uint8_t*)&plain, sizeof(plain),
                        ad, sizeof(ad),
                        nonce, K);

  const size_t ct_len = clen - ASCON128_TAG_SIZE;
  const uint8_t *tag  = cipher + ct_len;

  // Packet: [u32 counter][16B nonce][ciphertext][16B tag]
  const size_t pkt_len = 4 + 16 + ct_len + ASCON128_TAG_SIZE;
  uint8_t *pkt = pkt_pool[0]; // reuse slot 0 in normal loop
  uint8_t *p = pkt;
  memcpy(p, &g_counter, 4);            p+=4;
  memcpy(p, nonce, 16);                p+=16;
  memcpy(p, cipher, ct_len);           p+=ct_len;
  memcpy(p, tag, ASCON128_TAG_SIZE);   p+=ASCON128_TAG_SIZE;

  esp_now_send(SLAVE_MAC, pkt, pkt_len);
  g_counter++;
  delay(100); // ~10 Hz
#endif
}
