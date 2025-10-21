// MASTER: ESP32 + MAX30102 -> ASCON-128 -> ESP-NOW -> ESP32-C6
#include <Wire.h>
#include "MAX30105.h"
#include "heartRate.h"
#include <WiFi.h>
#include <esp_now.h>
#include <ASCON.h>                 // <- use the library directly

#define WIFI_CH 6
const byte RATE_SIZE = 4;

// Paste the SLAVE MAC (from its Serial)
uint8_t SLAVE_MAC[6] = { 0x40, 0x4C, 0xCA, 0x4C, 0x6E, 0x60 };

static const uint8_t K[16] = {     // demo key (replace in real use)
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

void setup() {
  Serial.begin(115200);
  delay(300);

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
                        nonce, K);   // encrypt is 'void' in this lib

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
