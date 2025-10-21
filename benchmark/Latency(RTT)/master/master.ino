// MASTER (ESP32): RTT probe over ESP-NOW with ASCON-128 (Arduino-ESP32 3.x)
#include <WiFi.h>
#include <esp_now.h>
#include <ASCON.h>
#include <string.h>
#include <stdint.h>

#define WIFI_CH 6
static const uint8_t SLAVE_MAC[6] = { 0x40,0x4C,0xCA,0x4C,0x6E,0x60 }; // <-- paste your C6 STA MAC

// --- verbosity controls ---
#define PRINT_PER_PACKET 0
#define REPORT_EVERY 50   // change to 100/200 if you want fewer summaries
#if PRINT_PER_PACKET
  #define DBG(...)  Serial.printf(__VA_ARGS__)
#else
  #define DBG(...)  do{}while(0)
#endif


static const uint8_t K[16] = {
  0x60,0x4A,0x2C,0x10,0x91,0x22,0x33,0x44,0x55,0x66,0x87,0x98,0xAA,0xBB,0xCC,0xDD
};

struct __attribute__((packed)) Ping { uint8_t type; uint32_t seq; };

static inline void fill_nonce(uint8_t n[16], uint32_t ctr){
  for (int i=0;i<12;i+=4){ uint32_t r=esp_random(); memcpy(n+i,&r,4); }
  memcpy(n+12,&ctr,4);
}


// ---------------- Running RTT stats ----------------
uint32_t rtt_min_us = 0xFFFFFFFFUL, rtt_max_us = 0, rtt_sum_us = 0, rtt_n = 0;
const uint16_t REPORT_EVERY = 50;  // print every 50 samples
// ---------------------------------------------------

volatile bool     got = false;
volatile uint32_t got_seq = 0;
volatile uint32_t rtt_us  = 0;
uint32_t send_t0 = 0;
uint32_t ctr = 0, seq = 0;

static void ensure_peer(const uint8_t mac[6]){
  esp_now_peer_info_t p{};
  memcpy(p.peer_addr, mac, 6);
  p.channel = WIFI_CH; p.ifidx = WIFI_IF_STA; p.encrypt = false;
  esp_now_del_peer(mac);
  esp_err_t e = esp_now_add_peer(&p);
  if (e != ESP_OK) Serial.printf("[MST] add_peer err=%d\n", e);
}

static void onSent(const uint8_t* mac, esp_now_send_status_t s){
  Serial.printf("[MST] PING to %02X:%02X:%02X:%02X:%02X:%02X : %s\n",
    mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],
    (s==ESP_NOW_SEND_SUCCESS) ? "ACKED" : "NO_ACK");
}

void onRecv(const esp_now_recv_info_t* info, const uint8_t* data, int len){
  Serial.printf("[MST] RX len=%d from %02X:%02X:%02X:%02X:%02X:%02X\n",
    len, info->src_addr[0],info->src_addr[1],info->src_addr[2],
         info->src_addr[3],info->src_addr[4],info->src_addr[5]);

  if (len < (int)(4 + 16 + ASCON128_TAG_SIZE)) { Serial.println("[MST] drop: too short"); return; }

  const uint8_t *p = data;
  uint32_t ctrx; memcpy(&ctrx, p, 4); p += 4;
  const uint8_t *nonce = p; p += 16;
  const uint8_t *c = p;
  size_t clen = len - (4 + 16 + ASCON128_TAG_SIZE);
  const uint8_t *tag = data + len - ASCON128_TAG_SIZE;

  Serial.printf("[MST] ctr=%lu clen=%u (expect %u)\n",
                (unsigned long)ctrx, (unsigned)clen, (unsigned)sizeof(Ping));
  if (clen != sizeof(Ping)) { Serial.println("[MST] drop: clen mismatch"); return; }

  // AD = ctrx || sender MAC
  uint8_t ad[4 + 6]; memcpy(ad, &ctrx, 4); memcpy(ad + 4, info->src_addr, 6);

  // decrypt
  uint8_t buf[sizeof(Ping) + ASCON128_TAG_SIZE];
  memcpy(buf, c, clen);
  memcpy(buf + clen, tag, ASCON128_TAG_SIZE);

  Ping pong{}; size_t mlen = sizeof(pong);
  int dec = ascon128_aead_decrypt((uint8_t*)&pong, &mlen,
                                  buf, sizeof(buf), ad, sizeof(ad),
                                  nonce, K);
  if (dec != 0) { Serial.println("[MST] drop: auth fail"); return; }
  if (mlen != sizeof(pong)) { Serial.println("[MST] drop: size after dec"); return; }
  if (pong.type != 2)      { Serial.printf("[MST] drop: type=%u not PONG\n", pong.type); return; }

  rtt_us  = micros() - send_t0;
  got_seq = pong.seq;
  got     = true;

  Serial.printf("[MST] PONG ok seq=%lu RTT=%.2f ms\n",
                (unsigned long)pong.seq, rtt_us/1000.0);

  // ---- Update running stats and report every REPORT_EVERY samples ----
  rtt_n++; rtt_sum_us += rtt_us;
  if (rtt_us < rtt_min_us) rtt_min_us = rtt_us;
  if (rtt_us > rtt_max_us) rtt_max_us = rtt_us;
  if (rtt_n % REPORT_EVERY == 0) {
    Serial.printf("RTT_ASCON,n=%lu,avg=%.2f ms,min=%.2f,max=%.2f\n",
                  (unsigned long)rtt_n,
                  (double)rtt_sum_us/rtt_n/1000.0,
                  rtt_min_us/1000.0,
                  rtt_max_us/1000.0);
  }
}

void setup(){
  Serial.begin(115200); delay(300);
  WiFi.mode(WIFI_STA); WiFi.setSleep(false); WiFi.setChannel(WIFI_CH);
  if (esp_now_init() != ESP_OK){ Serial.println("esp_now_init failed"); while(1){} }
  ensure_peer(SLAVE_MAC);
  esp_now_register_recv_cb(onRecv);
  esp_now_register_send_cb(onSent);
  Serial.print("RTT PROBE READY ch="); Serial.print(WIFI_CH);
  Serial.print(" sizeof(Ping)="); Serial.println(sizeof(Ping));
  Serial.print("MASTER STA="); Serial.println(WiFi.macAddress());
}

void loop(){
  // send one ping every 200ms; print timeout if no PONG in 300ms
  Ping ping{1, ++seq};
  uint8_t nonce[16]; fill_nonce(nonce, ++ctr);

  uint8_t ad[4 + 6]; memcpy(ad, &ctr, 4);
  uint8_t my[6]; WiFi.macAddress(my);
  memcpy(ad + 4, my, 6);

  uint8_t out[sizeof(Ping) + ASCON128_TAG_SIZE]; size_t outlen = 0;
  ascon128_aead_encrypt(out, &outlen,
                        (const uint8_t*)&ping, sizeof(ping),
                        ad, sizeof(ad), nonce, K);

  const size_t ct_len = outlen - ASCON128_TAG_SIZE;
  uint8_t pkt[4 + 16 + sizeof(Ping) + ASCON128_TAG_SIZE], *q = pkt;
  memcpy(q, &ctr, 4);           q += 4;
  memcpy(q, nonce, 16);         q += 16;
  memcpy(q, out, ct_len);       q += ct_len;
  memcpy(q, out + ct_len, ASCON128_TAG_SIZE);

  got = false; send_t0 = micros();
  esp_now_send(SLAVE_MAC, pkt, sizeof(pkt));

  uint32_t twait = millis();
  while (!got && millis() - twait < 300) { delay(1); }
  if (!got || got_seq != seq) {
    Serial.printf("[MST] timeout seq=%lu\n", (unsigned long)seq);
  }

  delay(200);
}
