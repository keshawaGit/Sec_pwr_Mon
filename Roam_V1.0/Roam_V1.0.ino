#include <Wire.h>
#include <INA219_WE.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <WiFi.h>

#define I2C_ADDRESS_Rpi 0x40
#define I2C_ADDRESS_usb1 0x41
#define I2C_ADDRESS_usb2 0x44

float shuntVoltage_Rpi = 0.0;
float loadVoltage_Rpi = 0.0;
float busVoltage_Rpi = 0.0;
float current_Rpi = 0.0;
float power_Rpi = 0.0; 
bool ina219_overflow_Rpi = false;

float shuntVoltage_usb1 = 0.0;
float loadVoltage_usb1 = 0.0;
float busVoltage_usb1 = 0.0;
float current_usb1 = 0.0;
float power_usb1 = 0.0; 
bool ina219_overflow_usb1 = false;

/* There are several ways to create your INA219 object:
 * INA219_WE ina219 = INA219_WE()              -> uses Wire / I2C Address = 0x40
 * INA219_WE ina219 = INA219_WE(ICM20948_ADDR) -> uses Wire / I2C_ADDRESS
 * INA219_WE ina219 = INA219_WE(&wire2)        -> uses the TwoWire object wire2 / I2C_ADDRESS
 * INA219_WE ina219 = INA219_WE(&wire2, I2C_ADDRESS) -> all together
 * Successfully tested with two I2C busses on an ESP32
 */
INA219_WE Rpi = INA219_WE(I2C_ADDRESS_Rpi);
INA219_WE usb2 = INA219_WE(I2C_ADDRESS_usb2);

// Add your MQTT Broker IP address, example:
const char* ssid = "BIXBY";//"SLT 141";
const char* password = "passwordIS@321";//"subha@123";
const char* mqtt_server = "192.168.1.100";

WiFiClient espclient2;
PubSubClient client2(espclient2);

void callback(char* topic, byte* message, unsigned int length) {
  Serial.print("Message arrived on topic: ");
  Serial.print(topic);
  Serial.print(". Message: ");
  String messageTemp;
  
  for (int i = 0; i < length; i++) {
    Serial.print((char)message[i]);
    messageTemp += (char)message[i];
  }
  Serial.println();

  // If a message is received on the topic esp32/bus1_output, you check if the message  
  // Changes the bus1_output state according to the message
  if (String(topic) == "esp32/output") {
    Serial.print("Changing bus1_output to ");
    if(messageTemp == "bv1ON"){
      //bv1Request = true;
      //isAll_1 =true;
      Serial.println("bv1ON");
    }
    else if(messageTemp == "bv1OFF"){
      //bv1Request = false;
    }     
    else if(messageTemp == "lv1ON"){
      //Serial.println("Transmitter ON");
      //lv1Request = true;
      //isAll_1 =true;
    }
  }
}

void setup_wifi() {
  delay(10);
  // We start by connecting to a WiFi network
  Serial.println();
  Serial.print("Connecting to ");
  Serial.println(ssid);

  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("");
  Serial.println("WiFi connected");
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());
}

void reconnect() {
  // Loop until we're reconnected
  while (!client2.connected()) {
    Serial.print("Attempting MQTT connection...");
    // Attempt to connect
    if (client2.connect("dev/data")) {
      Serial.println("connected");
      // Subscribe
      client2.subscribe("esp32/output");
    } else {
      Serial.print("failed, rc=");
      Serial.print(client2.state());
      Serial.println(" try again in 5 seconds");
      // Wait 5 seconds before retrying
      delay(5000);
    }
  }
}

void device_data(){
 StaticJsonDocument<200> doc;

    doc["Node"] = "Roaming";
    doc["status"] = wl_status_to_string(WiFi.status());
    doc["network"] = String(WiFi.SSID());
    doc["rssi"] = String(WiFi.RSSI());
    String ip = WiFi.localIP().toString();
    doc["mqttIP"] = String(ip);
    //Serial.println(ip);
    
    char output[200];
    size_t n = serializeJson(doc, output);
    //client2.publish("outTopic", buffer, n);
    
    serializeJson(doc, output);
    
   // Serial.println("Sending message to MQTT topic..");
    //Serial.println(output);
   
    if (client2.publish("dev2/data", output) == true) {
      Serial.println("Success sending message");
    } else {
      Serial.println("Error sending message");
    }  
  
}

void bus_data(){
  shuntVoltage_Rpi = Rpi.getShuntVoltage_mV();
  busVoltage_Rpi = Rpi.getBusVoltage_V();
  current_Rpi = Rpi.getCurrent_mA();
  power_Rpi = Rpi.getBusPower();
  loadVoltage_Rpi  = busVoltage_Rpi + (shuntVoltage_Rpi/1000);
  //ina219_overflow_Rpi = Rpi.getOverflow();

  shuntVoltage_usb1 = usb2.getShuntVoltage_mV();
  busVoltage_usb1 = usb2.getBusVoltage_V();
  current_usb1 = usb2.getCurrent_mA();
  power_usb1 = usb2.getBusPower();
  loadVoltage_usb1  = busVoltage_usb1 + (shuntVoltage_usb1/1000);
  //ina219_overflow_usb1 = usb2.getOverflow();
    
 StaticJsonDocument<160> doc;

    doc["shuntV_Rpi"] = shuntVoltage_Rpi ;
    doc["busV_Rpi"] = busVoltage_Rpi;
    doc["currV_Rpi"] = current_Rpi;
    doc["loadV_Rpi"] = loadVoltage_Rpi;
    doc["pwr_Rpi"] = power_Rpi;
    
    doc["shuntV_usb1"] = shuntVoltage_usb1 ;
    doc["busV_usb1"] = busVoltage_usb1;
    doc["currV_usb1"] = current_usb1;
    doc["loadV_usb1"] = loadVoltage_usb1;
    doc["pwr_usb1"] = power_usb1;   

    
    char output[200];
    size_t n = serializeJson(doc, output);
    //client2.publish("outTopic", buffer, n);
    
    serializeJson(doc, output);
    
   // Serial.println("Sending message to MQTT topic..");
    //Serial.println(output);
   
    if (client2.publish("esp32/roam", output) == true) {
      Serial.println("Success sending message");
    } else {
      Serial.println("Error sending message");
    }  
  
}

void setup() {
 Serial.begin(115200);
  Wire.begin();
  
  setup_wifi();
  client2.setServer(mqtt_server, 1883);
  client2.setCallback(callback);
  
  if(!Rpi.init()){
    Serial.println("Rpi not connected!");
  }
  if(!usb2.init()){
    Serial.println("USB 01 not connected!");
  }
  /* Set ADC Mode for Bus and ShuntVoltage
  * Mode *            * Res / Samples *       * Conversion Time *
  BIT_MODE_9        9 Bit Resolution             84 µs
  BIT_MODE_10       10 Bit Resolution            148 µs  
  BIT_MODE_11       11 Bit Resolution            276 µs
  BIT_MODE_12       12 Bit Resolution            532 µs  (DEFAULT)
  SAMPLE_MODE_2     Mean Value 2 samples         1.06 ms
  SAMPLE_MODE_4     Mean Value 4 samples         2.13 ms
  SAMPLE_MODE_8     Mean Value 8 samples         4.26 ms
  SAMPLE_MODE_16    Mean Value 16 samples        8.51 ms     
  SAMPLE_MODE_32    Mean Value 32 samples        17.02 ms
  SAMPLE_MODE_64    Mean Value 64 samples        34.05 ms
  SAMPLE_MODE_128   Mean Value 128 samples       68.10 ms
  */
  //ina219.setADCMode(SAMPLE_MODE_128); // choose mode and uncomment for change of default
  
  /* Set measure mode
  POWER_DOWN - INA219 switched off
  TRIGGERED  - measurement on demand
  ADC_OFF    - Analog/Digital Converter switched off
  CONTINUOUS  - Continuous measurements (DEFAULT)
  */
  // ina219.setMeasureMode(CONTINUOUS); // choose mode and uncomment for change of default
  
  /* Set PGain
  * Gain *  * Shunt Voltage Range *   * Max Current (if shunt is 0.1 ohms) *
   PG_40       40 mV                    0.4 A
   PG_80       80 mV                    0.8 A
   PG_160      160 mV                   1.6 A
   PG_320      320 mV                   3.2 A (DEFAULT)
  */
  // ina219.setPGain(PG_320); // choose gain and uncomment for change of default
  
  /* Set Bus Voltage Range
   BRNG_16   -> 16 V
   BRNG_32   -> 32 V (DEFAULT)
  */
  // ina219.setBusRange(BRNG_32); // choose range and uncomment for change of default

  Serial.println("Power monitoring starting .....");

  /* If the current values delivered by the INA219 differ by a constant factor
     from values obtained with calibrated equipment you can define a correction factor.
     Correction factor = current delivered from calibrated equipment / current delivered by INA219
  */
  // ina219.setCorrectionFactor(0.98); // insert your correction factor if necessary
  
  /* If you experience a shunt voltage offset, that means you detect a shunt voltage which is not 
     zero, although the current should be zero, you can apply a correction. For this, uncomment the 
     following function and apply the offset you have detected.   
  */
  // ina219.setShuntVoltOffset_mV(0.5); // insert the shunt voltage (millivolts) you detect at zero current 
}

void loop() {
    // Roming Node
    
    if (!client2.connected()) {
    reconnect();
  }
  /*
  char output[] ="test";
    if (client2.publish("bus/data", output) == true) {
      Serial.println("Success sending message");
    } else {
      Serial.println("Error sending message");
    } 

    */
  bus_data();
  //device_data();
  client2.loop();
  delay(1);
      
  //delayMicroseconds(50);

     
    
}

const char* wl_status_to_string(wl_status_t status) {
  switch (status) {
    case WL_NO_SHIELD: return "WL_NO_SHIELD";
    case WL_IDLE_STATUS: return "WL_IDLE_STATUS";
    case WL_NO_SSID_AVAIL: return "WL_NO_SSID_AVAIL";
    case WL_SCAN_COMPLETED: return "WL_SCAN_COMPLETED";
    case WL_CONNECTED: return "WL_CONNECTED";
    case WL_CONNECT_FAILED: return "WL_CONNECT_FAILED";
    case WL_CONNECTION_LOST: return "WL_CONNECTION_LOST";
    case WL_DISCONNECTED: return "WL_DISCONNECTED";
  }
}
