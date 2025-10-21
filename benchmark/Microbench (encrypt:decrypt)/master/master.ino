// MASTER: ESP32 + MAX30102 -> ASCON-128 -> ESP-NOW -> ESP32-C6
#include <Wire.h>
#include "MAX30105.h"
#include "heartRate.h"
#include <WiFi.h>
#include <esp_now.h>
#include <ASCON.h>   // rweather/ascon-suite

#define WIFI_CH 6

const byte RATE_SIZE = 4;

// === Enable/disable the microbench at boot ===
#define RUN_ASCON_MICROBENCH   0   // set 0 after you collect numbers
#define BENCH_ONLY             0   // 1 = run bench and halt (clean output)

// Paste the SLAVE MAC (from its Serial)
uint8_t SLAVE_MAC[6] = { 0x40, 0x4C, 0xCA, 0x4C, 0x6E, 0x60 };

static const uint8_t K[16] = { // demo key (replace in real use)
  0x60,0x4A,0x2C,0x10,0x91,0x22,0x33,0x44,0x55,0x66,0x87,0x98,0xAA,0xBB,0xCC,0xDD
};

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

static void fill_nonce(uint8_t nonce[16], uint32_t ctr) {
  for (int i=0;i<12;i+=4) { uint32_t r = esp_random(); memcpy(nonce+i, &r, 4); }
  memcpy(nonce+12, &ctr, 4);
}

void onSent(const uint8_t *mac, esp_now_send_status_t s) {
  Serial.printf("Send -> %02X:%02X:%02X:%02X:%02X:%02X : %s\n",
    mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],
    (s==ESP_NOW_SEND_SUCCESS) ? "ACKED" : "NO_ACK");
}

// ====== ASCON-128 microbench (runs once at boot if enabled) ======
#if RUN_ASCON_MICROBENCH
static const uint8_t K_BENCH[16] = {
  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
};

static void bench_one_size(size_t mlen, int iters) {
  static uint8_t plain[1024];
  static uint8_t cipher[1024 + ASCON128_TAG_SIZE];
  static uint8_t nonce[16];
  static uint8_t ad[10];

  for (size_t i=0;i<mlen;i++) plain[i] = (uint8_t)(i*31u + 7u);
  for (size_t i=0;i<sizeof(ad);i++) ad[i] = (uint8_t)i;

  // Warm-up
  size_t clen=0;
  for (int i=0;i<10;i++) {
    for (int j=0;j<12;j+=4){ uint32_t r=esp_random(); memcpy(nonce+j,&r,4); }
    uint32_t ctr=i; memcpy(nonce+12,&ctr,4);
    ascon128_aead_encrypt(cipher, &clen, plain, mlen, ad, sizeof(ad), nonce, K_BENCH);
  }

  // Measure encrypt
  uint64_t sum_us_enc=0, min_us_enc=0xFFFFFFFFULL, max_us_enc=0;
  for (int i=0;i<iters;i++) {
    for (int j=0;j<12;j+=4){ uint32_t r=esp_random(); memcpy(nonce+j,&r,4); }
    memcpy(nonce+12,&i,4);
    uint32_t t0 = micros();
    ascon128_aead_encrypt(cipher, &clen, plain, mlen, ad, sizeof(ad), nonce, K_BENCH);
    uint32_t dt = micros()-t0;
    sum_us_enc += dt; if (dt<min_us_enc) min_us_enc=dt; if (dt>max_us_enc) max_us_enc=dt;
    if ((i % 50) == 0) delay(0); // yield a bit
  }

  // Measure decrypt (using last produced cipher)
  uint64_t sum_us_dec=0, min_us_dec=0xFFFFFFFFULL, max_us_dec=0;
  size_t mlen_out=0;
  for (int i=0;i<iters;i++) {
    uint32_t t0 = micros();
    int ok = ascon128_aead_decrypt(plain, &mlen_out, cipher, mlen + ASCON128_TAG_SIZE, ad, sizeof(ad), nonce, K_BENCH);
    uint32_t dt = micros()-t0;
    if (ok!=0 || mlen_out!=mlen) { Serial.println("! decrypt fail in bench"); break; }
    sum_us_dec += dt; if (dt<min_us_dec) min_us_dec=dt; if (dt>max_us_dec) max_us_dec=dt;
    if ((i % 50) == 0) delay(0);
  }

  float avg_enc = (float)sum_us_enc/iters;
  float avg_dec = (float)sum_us_dec/iters;

  // CSV: ALG,SIZE,ITERS,ENC_AVG,ENC_MIN,ENC_MAX,DEC_AVG,DEC_MIN,DEC_MAX,HEAP
  Serial.printf("ASCON,%u,%d,%.2f,%llu,%llu,%.2f,%llu,%llu,%u\n",
    (unsigned)mlen, iters,
    avg_enc, (unsigned long long)min_us_enc, (unsigned long long)max_us_enc,
    avg_dec, (unsigned long long)min_us_dec, (unsigned long long)max_us_dec,
    ESP.getFreeHeap());
}

static void run_ascon_microbench() {
  Serial.println();
  Serial.println("# ASCON-128 microbench (us)");
  Serial.println("# ALG,SIZE,ITERS,ENC_AVG,ENC_MIN,ENC_MAX,DEC_AVG,DEC_MIN,DEC_MAX,HEAP");

  const size_t sizes[] = {16,32,64,128,256,512};
  for (size_t i=0;i<sizeof(sizes)/sizeof(sizes[0]); ++i) {
    bench_one_size(sizes[i], /*iters=*/200);
    Serial.flush();
    delay(250);   // give USB time to drain before next line
  }
}

#endif
// ===================== end microbench ============================

void setup() {
  Serial.begin(115200);
  Serial.setTxBufferSize(4096);       // help flush CSV quickly
  for (int i=0;i<50 && !Serial; ++i) delay(20);

#if RUN_ASCON_MICROBENCH
  run_ascon_microbench();
  Serial.println("---- microbench done ----");
  Serial.flush();
#if BENCH_ONLY
  while (true) { delay(1000); }       // stay here to keep output clean
#endif
#endif

  // Sensor
  if (!particleSensor.begin(Wire, I2C_SPEED_FAST)) { Serial.println("MAX30105 not found"); while(1){} }
  particleSensor.setup();
  particleSensor.setPulseAmplitudeRed(0x0A);
  particleSensor.setPulseAmplitudeGreen(0);

  // ESPNOW
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.setChannel(WIFI_CH);
  if (esp_now_init() != ESP_OK) { Serial.println("esp_now_init failed"); while(1){} }
  esp_now_register_send_cb(onSent);

  esp_now_peer_info_t peer{};
  memcpy(peer.peer_addr, SLAVE_MAC, 6);
  peer.channel = WIFI_CH; peer.encrypt = false;
  if (esp_now_add_peer(&peer) != ESP_OK) { Serial.println("add_peer failed"); while(1){} }

  Serial.print("MASTER MAC: "); Serial.println(WiFi.macAddress());
}

void loop() {
  long ir = particleSensor.getIR();

  if (checkForBeat(ir)) {
    long delta = millis() - lastBeat; lastBeat = millis();
    beatsPerMinute = 60.0 / (delta / 1000.0);
    if (beatsPerMinute > 20 && beatsPerMinute < 255) {
      rates[rateSpot++] = (byte)beatsPerMinute; rateSpot %= RATE_SIZE;
      int sum=0; for (byte i=0;i<RATE_SIZE;i++) sum += rates[i];
      beatAvg = sum / RATE_SIZE;
    }
  }

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

  // Encrypt: cipher || tag (tag is 16B)
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
  static uint8_t pkt[4 + 16 + sizeof(HRPacket) + ASCON128_TAG_SIZE];
  uint8_t *p = pkt;
  memcpy(p, &g_counter, 4);            p+=4;
  memcpy(p, nonce, 16);                p+=16;
  memcpy(p, cipher, ct_len);           p+=ct_len;
  memcpy(p, tag, ASCON128_TAG_SIZE);   p+=ASCON128_TAG_SIZE;

  esp_now_send(SLAVE_MAC, pkt, pkt_len);
  g_counter++;
  delay(100); // ~10 Hz
}
