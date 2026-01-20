Master device : Raspberry pi 5

---- Fingerprint sensor ----
UART Fingerprint Reader
SKU:        8552
Part No.:   UART Fingerprint Reader
Brand:      Waveshare

Links:
    - Device overview: https://www.waveshare.com/uart-fingerprint-reader.htm
    - Resources, user mannual : https://www.waveshare.com/wiki/UART_Fingerprint_Reader


Issue we are facing :

When we turn on the raspberrypi 5 and we connect the fingerprint sensor to the
raspberry tx & rx pin uart gpio pin and we send the command packet as specified
in the user manual of the fingerprint sensor to perform a specific task, the 
command never reach the sensor, but if before we connect the raspberry to sensor
we connect first both the tx & rx pins of the raspberry pi 5 together and send 
a packet (loopback) -> meaning the packet goes from raspberry tx pins and then 
comes back to rx raspberry pin, the packet flows without issues, and then we 
reconnect the raspberry pins to the sensor the and send command to the sensor
the command reach the sensor and the task is performed.

So it seems like theres is an issues with the rapsberry because when we connect
sensor to an arduino the packet (or command) always reach the sensor without 
issues.
