// ESP32-C6 serial sanity check
void setup() {
  pinMode(8, OUTPUT);             // many C6 boards tie LED to GPIO8; harmless if not
  Serial.begin(115200);
  delay(500);
  Serial.println("BOOT OK (C6)");
}

void loop() {
  static unsigned long t0=0;
  if (millis()-t0 >= 1000) {
    t0 = millis();
    digitalWrite(8, !digitalRead(8)); // blink if LED exists
    Serial.printf("tick %lu ms\n", millis());
    Serial.flush();
  }
}
