// SLAVE: ESP32-C6  ← ESP-NOW  ← ASCON-128 AEAD
#include <WiFi.h>
#include <esp_now.h>
#include <ASCON.h>
#include <string.h>

#define WIFI_CH 6
#define RUN_ASCON_MICROBENCH 1   // set to 0 after you collect numbers

struct __attribute__((packed)) HRPacket {
  uint32_t ts_ms;
  uint32_t ir;
  float    bpm;
  uint16_t avg;
  uint8_t  finger;
};

static const uint8_t K[16] = {
  0x60,0x4A,0x2C,0x10,0x91,0x22,0x33,0x44,0x55,0x66,0x87,0x98,0xAA,0xBB,0xCC,0xDD
};

volatile uint32_t highest_ctr_seen = 0;

// ---------- ASCON-128 microbench (runs once at boot if enabled) ----------
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

  // Encrypt timing
  uint64_t sum_us_enc=0, min_us_enc=0xFFFFFFFFULL, max_us_enc=0;
  for (int i=0;i<iters;i++) {
    for (int j=0;j<12;j+=4){ uint32_t r=esp_random(); memcpy(nonce+j,&r,4); }
    memcpy(nonce+12,&i,4);
    uint32_t t0 = micros();
    ascon128_aead_encrypt(cipher, &clen, plain, mlen, ad, sizeof(ad), nonce, K_BENCH);
    uint32_t dt = micros()-t0;
    sum_us_enc += dt; if (dt<min_us_enc) min_us_enc=dt; if (dt>max_us_enc) max_us_enc=dt;
  }

  // Decrypt timing (last produced cipher)
  uint64_t sum_us_dec=0, min_us_dec=0xFFFFFFFFULL, max_us_dec=0;
  size_t mlen_out=0;
  for (int i=0;i<iters;i++) {
    uint32_t t0 = micros();
    int ok = ascon128_aead_decrypt(plain, &mlen_out, cipher, mlen + ASCON128_TAG_SIZE, ad, sizeof(ad), nonce, K_BENCH);
    uint32_t dt = micros()-t0;
    if (ok!=0 || mlen_out!=mlen) { Serial.println("! decrypt fail in bench"); break; }
    sum_us_dec += dt; if (dt<min_us_dec) min_us_dec=dt; if (dt>max_us_dec) max_us_dec=dt;
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
    bench_one_size(sizes[i], 500);
    Serial.flush();
    delay(250);   // give USB time to drain
  }
}

#endif
// ------------------------------------------------------------------------

void onRecv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
  if (len < (int)(4 + 16 + ASCON128_TAG_SIZE)) return;

  const uint8_t *p = data;
  uint32_t counter = *(const uint32_t*)p; p += 4;
  const uint8_t *nonce = p;               p += 16;
  const uint8_t *cipher = p;
  size_t cipher_len = len - (4 + 16 + ASCON128_TAG_SIZE);
  const uint8_t *tag = data + len - ASCON128_TAG_SIZE;

  if (counter <= highest_ctr_seen) { Serial.println("[DROP] replay/old"); return; }
  if (cipher_len != sizeof(HRPacket)) { Serial.println("[DROP] size"); return; }

  uint8_t ad[4 + 6];
  memcpy(ad, &counter, 4);
  memcpy(ad + 4, info->src_addr, 6);

  // Build cipher||tag buffer
  uint8_t cbuf[sizeof(HRPacket) + ASCON128_TAG_SIZE];
  memcpy(cbuf, cipher, cipher_len);
  memcpy(cbuf + cipher_len, tag, ASCON128_TAG_SIZE);

  HRPacket plain{};
  size_t   mlen = sizeof(plain);

  int ok = ascon128_aead_decrypt((uint8_t*)&plain, &mlen,
                                 cbuf, sizeof(cbuf),
                                 ad, sizeof(ad),
                                 nonce, K);
  if (ok == 0 && mlen == sizeof(plain)) {
    highest_ctr_seen = counter;
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             info->src_addr[0],info->src_addr[1],info->src_addr[2],
             info->src_addr[3],info->src_addr[4],info->src_addr[5]);
    Serial.printf("[OK from %s] ctr=%lu t=%lu IR=%u BPM=%.1f Avg=%u finger=%s\n",
      macStr, (unsigned long)counter, (unsigned long)plain.ts_ms,
      plain.ir, plain.bpm, plain.avg, plain.finger ? "yes":"no");
  } else {
    Serial.println("[DROP] auth fail");
  }
}

void setup() {
  Serial.begin(115200);
  for (int i=0; i<50 && !Serial; ++i) delay(50);

#if RUN_ASCON_MICROBENCH
  // Run the microbench BEFORE turning on Wi-Fi/ESP-NOW to keep timings clean
  run_ascon_microbench();
  Serial.println("---- microbench done; starting receiver ----");
#endif

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.setChannel(WIFI_CH);

  if (esp_now_init() != ESP_OK) { Serial.println("esp_now_init failed"); while(1){} }
  esp_now_register_recv_cb(onRecv);

  Serial.print("SLAVE MAC: "); Serial.println(WiFi.macAddress());
  Serial.println("Waiting for encrypted packets...");
}

void loop() {}
