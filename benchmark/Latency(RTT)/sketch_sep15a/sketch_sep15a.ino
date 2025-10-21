#include <WiFi.h>
#include <esp_now.h>
#include <ASCON.h>
#include <string.h>

#define WIFI_CH 6
static const uint8_t K[16] = {
  0x60,0x4A,0x2C,0x10,0x91,0x22,0x33,0x44,
  0x55,0x66,0x87,0x98,0xAA,0xBB,0xCC,0xDD
};

struct __attribute__((packed)) Ping { uint8_t type; uint32_t seq; };

static inline void fill_nonce(uint8_t n[16], uint32_t ctr){
  for (int i=0;i<12;i+=4){ uint32_t r=esp_random(); memcpy(n+i,&r,4); }
  memcpy(n+12,&ctr,4);
}

static uint32_t ctr_guard = 0;

static void ensure_peer(const uint8_t mac[6]){
  esp_now_peer_info_t p{};
  memcpy(p.peer_addr, mac, 6);
  p.channel = WIFI_CH; p.ifidx = WIFI_IF_STA; p.encrypt = false;
  esp_now_del_peer(mac);
  esp_err_t e = esp_now_add_peer(&p);
  if (e != ESP_OK) Serial.printf("[SLV] add_peer err=%d\n", e);
}

static void onSent(const uint8_t* mac, esp_now_send_status_t s){
  Serial.printf("[SLV] PONG to %02X:%02X:%02X:%02X:%02X:%02X : %s\n",
    mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],
    (s==ESP_NOW_SEND_SUCCESS) ? "ACKED" : "NO_ACK");
}

void onRecv(const esp_now_recv_info_t *info, const uint8_t *data, int len){
  if (len < (int)(4 + 16 + ASCON128_TAG_SIZE)) return;

  const uint8_t *p = data;
  uint32_t ctr_in; memcpy(&ctr_in, p, 4); p += 4;
  const uint8_t *nonce_in = p; p += 16;
  const uint8_t *c = p;
  size_t clen = len - (4 + 16 + ASCON128_TAG_SIZE);
  const uint8_t *tag = data + len - ASCON128_TAG_SIZE;

  Serial.printf("[SLV] RX len=%d from %02X:%02X:%02X:%02X:%02X:%02X\n",
    len, info->src_addr[0],info->src_addr[1],info->src_addr[2],
         info->src_addr[3],info->src_addr[4],info->src_addr[5]);

  if (clen != sizeof(Ping)) { Serial.println("[SLV] drop: clen mismatch"); return; }

  uint8_t ad[4 + 6]; memcpy(ad, &ctr_in, 4); memcpy(ad + 4, info->src_addr, 6);

  uint8_t buf[sizeof(Ping) + ASCON128_TAG_SIZE];
  memcpy(buf, c, clen);
  memcpy(buf + clen, tag, ASCON128_TAG_SIZE);

  Ping ping{}; size_t mlen = sizeof(ping);
  int dec = ascon128_aead_decrypt((uint8_t*)&ping, &mlen,
                                  buf, sizeof(buf), ad, sizeof(ad),
                                  nonce_in, K);
  if (dec != 0 || mlen != sizeof(ping) || ping.type != 1){
    Serial.println("[SLV] drop: auth/type");
    return;
  }
  Serial.printf("[SLV] PING ok seq=%lu\n", (unsigned long)ping.seq);

  // one fresh counter for AD + nonce + header
  uint32_t ctr_out = ++ctr_guard;

  uint8_t ad2[4 + 6];
  memcpy(ad2, &ctr_out, 4);
  uint8_t my[6]; WiFi.macAddress(my);
  memcpy(ad2 + 4, my, 6);

  uint8_t n2[16]; fill_nonce(n2, ctr_out);

  ping.type = 2; // PONG
  uint8_t out[sizeof(Ping) + ASCON128_TAG_SIZE]; size_t outlen = 0;
  ascon128_aead_encrypt(out, &outlen,
                        (const uint8_t*)&ping, sizeof(ping),
                        ad2, sizeof(ad2), n2, K);

  const size_t ct_len = outlen - ASCON128_TAG_SIZE;
  uint8_t pkt[4 + 16 + sizeof(Ping) + ASCON128_TAG_SIZE], *q = pkt;
  memcpy(q, &ctr_out, 4); q += 4;
  memcpy(q, n2, 16);      q += 16;
  memcpy(q, out, ct_len); q += ct_len;
  memcpy(q, out + ct_len, ASCON128_TAG_SIZE);

  ensure_peer(info->src_addr);
  esp_now_send(info->src_addr, pkt, sizeof(pkt));
}

void setup(){
  Serial.begin(115200); delay(300);
  WiFi.mode(WIFI_STA); WiFi.setSleep(false); WiFi.setChannel(WIFI_CH);
  if (esp_now_init() != ESP_OK){ Serial.println("esp_now_init failed"); while(1){} }
  esp_now_register_recv_cb(onRecv);
  esp_now_register_send_cb(onSent);
  Serial.print("RTT ECHO READY (C6)  STA="); Serial.println(WiFi.macAddress());
}
void loop(){ delay(1); }
