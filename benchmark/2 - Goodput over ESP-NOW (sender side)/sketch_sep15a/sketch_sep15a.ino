// SLAVE: ESP32-C6  ← ESP-NOW  ← ASCON-128 AEAD
// Queue-based RX + 2s ticker + auto-armed 5s E2E window
#include <WiFi.h>
#include <esp_now.h>
#include <ASCON.h>
#include <string.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

#define WIFI_CH 6

static const uint8_t K[16] = {
  0x60,0x4A,0x2C,0x10,0x91,0x22,0x33,0x44,0x55,0x66,0x87,0x98,0xAA,0xBB,0xCC,0xDD
};

struct __attribute__((packed)) HRPacket {
  uint32_t ts_ms;
  uint32_t ir;
  float    bpm;
  uint16_t avg;
  uint8_t  finger;
};
static_assert(sizeof(HRPacket) == 15, "HRPacket must be 15 bytes");

volatile uint32_t e2e_ok   = 0;
volatile uint32_t e2e_drop = 0;
volatile uint32_t highest_ctr_seen = 0;

static const size_t MAX_PKT = 4 + 16 + sizeof(HRPacket) + ASCON128_TAG_SIZE; // 51
typedef struct {
  uint8_t  mac[6];
  uint16_t len;
  uint8_t  data[MAX_PKT];
} RxItem;

static QueueHandle_t rxq = nullptr;

// ----- E2E window reporter -----
const float   E2E_WINDOW_S = 5.0f;
uint32_t      e2e_win_start_ms = 0;
uint32_t      e2e_ok_start = 0, e2e_drop_start = 0;
bool          e2e_win_armed = false;         // arm on first packet
const uint32_t REARM_IDLE_MS = 3000;         // re-arm if idle this long
uint32_t      last_pkt_ms = 0;

uint32_t last_print_ms = 0; // 2s ticker

static bool parse_and_decrypt(const RxItem& it, HRPacket &out_plain) {
  if (it.len < (int)(4 + 16 + ASCON128_TAG_SIZE)) return false;

  const uint8_t *p = it.data;
  uint32_t counter; memcpy(&counter, p, 4); p += 4;  // unaligned-safe
  const uint8_t *nonce  = p;  p += 16;
  const uint8_t *cipher = p;
  size_t cipher_len = it.len - (4 + 16 + ASCON128_TAG_SIZE);
  const uint8_t *tag   = it.data + it.len - ASCON128_TAG_SIZE;

  if (counter <= highest_ctr_seen) return false;
  if (cipher_len != sizeof(HRPacket)) return false;

  uint8_t ad[4 + 6];
  memcpy(ad, &counter, 4);
  memcpy(ad + 4, it.mac, 6);

  uint8_t cbuf[sizeof(HRPacket) + ASCON128_TAG_SIZE];
  memcpy(cbuf, cipher, cipher_len);
  memcpy(cbuf + cipher_len, tag, ASCON128_TAG_SIZE);

  size_t mlen = sizeof(HRPacket);
  int ok = ascon128_aead_decrypt((uint8_t*)&out_plain, &mlen,
                                 cbuf, sizeof(cbuf),
                                 ad, sizeof(ad),
                                 nonce, K);
  if (ok != 0 || mlen != sizeof(HRPacket)) return false;

  highest_ctr_seen = counter;
  return true;
}

void onRecv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
  if (!rxq) return;
  RxItem item{};
  item.len = (len > (int)MAX_PKT) ? MAX_PKT : (uint16_t)len;
  memcpy(item.data, data, item.len);
  memcpy(item.mac, info->src_addr, 6);
  if (xQueueSend(rxq, &item, 0) != pdTRUE)
    e2e_drop++; // queue full -> drop
}

void setup() {
  Serial.begin(115200);
  Serial.setTxBufferSize(4096);
  delay(300);

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.setChannel(WIFI_CH);

  if (esp_now_init() != ESP_OK) { Serial.println("esp_now_init failed"); while(1){} }
  rxq = xQueueCreate(64, sizeof(RxItem));   // deeper queue for max-rate bursts
  if (!rxq) { Serial.println("queue create failed"); while(1){} }
  esp_now_register_recv_cb(onRecv);

  Serial.println("\n== SLAVE E2E (auto-window) ==");
  Serial.print("MAC: "); Serial.println(WiFi.macAddress());
  Serial.printf("WiFi channel: %d\n", WIFI_CH);
  Serial.println("Waiting for encrypted packets...");
}

void loop() {
  // Process frames
  RxItem it;
  bool got_pkt = false;
  while (xQueueReceive(rxq, &it, 0) == pdTRUE) {
    got_pkt = true;
    HRPacket plain{};
    if (parse_and_decrypt(it, plain)) e2e_ok++; else e2e_drop++;
  }
  if (got_pkt) last_pkt_ms = millis();

  // Auto-arm the 5s window on first packet (or after long idle)
  if (!e2e_win_armed && (e2e_ok > 0 || e2e_drop > 0)) {
    e2e_win_armed  = true;
    e2e_win_start_ms = millis();
    e2e_ok_start     = e2e_ok;
    e2e_drop_start   = e2e_drop;
  }
  if (e2e_win_armed && (millis() - last_pkt_ms > REARM_IDLE_MS)) {
    // no traffic recently -> re-arm for next burst
    e2e_win_armed = false;
  }

  // 2s cumulative ticker
  if (millis() - last_print_ms >= 2000) {
    last_print_ms = millis();
    Serial.printf("E2E,2s,cum_ok=%lu,cum_drop=%lu\n",
                  (unsigned long)e2e_ok, (unsigned long)e2e_drop);
  }

  // 5s authenticated-goodput window
  if (e2e_win_armed && (millis() - e2e_win_start_ms >= (uint32_t)(E2E_WINDOW_S * 1000))) {
    uint32_t ok   = e2e_ok   - e2e_ok_start;
    uint32_t drop = e2e_drop - e2e_drop_start;

    const float CT_PER_PKT = 51.0f;  // 4 ctr + 16 nonce + 15 HR + 16 tag
    const float PT_PER_PKT = 15.0f;

    float ct_bps = (ok * CT_PER_PKT) / E2E_WINDOW_S;
    float pt_bps = (ok * PT_PER_PKT) / E2E_WINDOW_S;

    Serial.printf("E2E_WINDOW,%.1fs,ok=%lu,drop=%lu,ct=%.2f B/s,pt=%.2f B/s\n",
                  E2E_WINDOW_S, (unsigned long)ok, (unsigned long)drop,
                  ct_bps, pt_bps);

    // re-arm for next burst
    e2e_win_armed   = false;
  }

  delay(1);
}
