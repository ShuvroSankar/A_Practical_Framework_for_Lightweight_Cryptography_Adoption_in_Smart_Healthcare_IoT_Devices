// SLAVE: ESP32-C6  ← ESP-NOW  ← ASCON-128 AEAD  (E2E counters, queue-based)
// Board: ESP32C6 Dev Module
#include <WiFi.h>
#include <esp_now.h>
#include <ASCON.h>
#include <string.h>

// FreeRTOS queue for safe handoff out of the esp_now callback
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

#define WIFI_CH 6

// Same 16B key as master
static const uint8_t K[16] = {
  0x60,0x4A,0x2C,0x10,0x91,0x22,0x33,0x44,0x55,0x66,0x87,0x98,0xAA,0xBB,0xCC,0xDD
};

// Payload shape — PACKED to 15 bytes (matches master)
struct __attribute__((packed)) HRPacket {
  uint32_t ts_ms;  // 4
  uint32_t ir;     // 4
  float    bpm;    // 4
  uint16_t avg;    // 2
  uint8_t  finger; // 1  => total 15
};
static_assert(sizeof(HRPacket) == 15, "HRPacket must be 15 bytes");

// E2E counters
volatile uint32_t e2e_ok   = 0;
volatile uint32_t e2e_drop = 0;

// Replay guard
volatile uint32_t highest_ctr_seen = 0;

// RX queue item: copy src MAC and entire ESPNOW payload
static const size_t MAX_PKT = 4 + 16 + sizeof(HRPacket) + ASCON128_TAG_SIZE; // 4+16+15+16 = 51
typedef struct {
  uint8_t  mac[6];
  uint16_t len;
  uint8_t  data[MAX_PKT];
} RxItem;

static QueueHandle_t rxq = nullptr;

// --- Parser+decrypt in the main task (no heavy work in callback) ---
static bool parse_and_decrypt(const RxItem& it, HRPacket &out_plain)
{
  if (it.len < (int)(4 + 16 + ASCON128_TAG_SIZE))
    return false;

  const uint8_t *p = it.data;

  // counter (unaligned-safe)
  uint32_t counter;
  memcpy(&counter, p, 4); p += 4;

  const uint8_t *nonce  = p;  p += 16;
  const uint8_t *cipher = p;
  size_t cipher_len = it.len - (4 + 16 + ASCON128_TAG_SIZE);
  const uint8_t *tag   = it.data + it.len - ASCON128_TAG_SIZE;

  // Early checks
  if (counter <= highest_ctr_seen) return false;
  if (cipher_len != sizeof(HRPacket)) return false;

  // AAD = counter || sender_mac
  uint8_t ad[4 + 6];
  memcpy(ad, &counter, 4);
  memcpy(ad + 4, it.mac, 6);

  // Build cipher||tag
  uint8_t cbuf[sizeof(HRPacket) + ASCON128_TAG_SIZE];
  memcpy(cbuf, cipher, cipher_len);
  memcpy(cbuf + cipher_len, tag, ASCON128_TAG_SIZE);

  size_t mlen = sizeof(HRPacket);
  int ok = ascon128_aead_decrypt((uint8_t*)&out_plain, &mlen,
                                 cbuf, sizeof(cbuf),
                                 ad, sizeof(ad),
                                 nonce, K);  // 0 on success
  if (ok != 0 || mlen != sizeof(HRPacket))
    return false;

  highest_ctr_seen = counter;
  return true;
}

// esp-now RX callback: copy to queue and return quickly
void onRecv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
  if (!rxq) return;

  RxItem item{};
  item.len = (len > (int)MAX_PKT) ? MAX_PKT : (uint16_t)len;
  memcpy(item.data, data, item.len);
  memcpy(item.mac, info->src_addr, 6);

  // Non-blocking send; if queue is full, count drop and return
  if (xQueueSend(rxq, &item, 0) != pdTRUE) {
    e2e_drop++;
  }
}

void setup() {
  Serial.begin(115200);
  Serial.setTxBufferSize(4096);
  for (int i=0; i<50 && !Serial; ++i) delay(20);

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.setChannel(WIFI_CH);

  if (esp_now_init() != ESP_OK) {
    Serial.println("esp_now_init failed");
    while(1){}
  }

  // Create RX queue (depth 16)
  rxq = xQueueCreate(16, sizeof(RxItem));
  if (!rxq) { Serial.println("queue create failed"); while(1){} }

  esp_now_register_recv_cb(onRecv);

  Serial.println("\n== SLAVE E2E (queue-based) ==");
  Serial.print("MAC: "); Serial.println(WiFi.macAddress());
  Serial.printf("WiFi channel: %d\n", WIFI_CH);
  Serial.println("Waiting for encrypted packets...");
}

void loop() {
  // Drain queue and process frames in the main task
  RxItem it;
  while (xQueueReceive(rxq, &it, 0) == pdTRUE) {
    HRPacket plain{};
    if (parse_and_decrypt(it, plain)) {
      e2e_ok++;
      // (Optional) per-packet debug off to keep logs clean
      // Serial.printf("[OK] bpm=%.1f ir=%u\n", plain.bpm, plain.ir);
    } else {
      e2e_drop++;
    }
  }

  // Print E2E stats every 2 seconds
  static uint32_t last_print_ms = 0;
  uint32_t now = millis();
  if (now - last_print_ms >= 2000) {
    last_print_ms = now;
    Serial.printf("E2E,2s,cum_ok=%lu,cum_drop=%lu\n",
                  (unsigned long)e2e_ok, (unsigned long)e2e_drop);
    Serial.flush();
  }

  // Let other tasks run
  delay(1);
}
