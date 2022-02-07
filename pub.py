import paho.mqtt.client as mqtt 
from random import randrange, uniform
import time
import sys

#mqttBroker ="192.168.1.104"
mqttBroker =sys.argv[1]
msg = sys.argv[2]

client = mqtt.Client("Temperature_Inside")
client.connect(mqttBroker) 
count =0

while count <2:
    #msg = "start"
    count = count +1
    client.publish("esp32/Rx/key", msg)
    print("Just published " + str(msg) + " to topic esp32/Rx/key")
    time.sleep(1)
    
    print("count :"+str(count))
