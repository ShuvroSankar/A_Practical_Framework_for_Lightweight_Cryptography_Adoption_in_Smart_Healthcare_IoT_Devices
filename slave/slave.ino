// SLAVE: ESP32-C6  ← ESP-NOW  ← ASCON-128 AEAD
#include <WiFi.h>
#include <esp_now.h>
#include <ASCON.h>               // <- use the library directly
#include <string.h>

#define WIFI_CH 6

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

  // Build cipher||tag buffer for decrypt call
  uint8_t cbuf[sizeof(HRPacket) + ASCON128_TAG_SIZE];
  memcpy(cbuf, cipher, cipher_len);
  memcpy(cbuf + cipher_len, tag, ASCON128_TAG_SIZE);

  HRPacket plain{};
  size_t   mlen = sizeof(plain);

  int ok = ascon128_aead_decrypt((uint8_t*)&plain, &mlen,
                                 cbuf, sizeof(cbuf),
                                 ad, sizeof(ad),
                                 nonce, K);        // decrypt returns int
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
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.setChannel(WIFI_CH);
  if (esp_now_init() != ESP_OK) { Serial.println("esp_now_init failed"); while(1){} }
  esp_now_register_recv_cb(onRecv);
  Serial.print("SLAVE MAC: "); Serial.println(WiFi.macAddress());
  Serial.println("Waiting for encrypted packets...");
}
void loop() {}
