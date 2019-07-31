# panopticon-nfc-scanner
> NFC Tag Scanner for the Panopticon Project.

Reads NFC tag placements and removals and sends notifcations via MQTT. 

## Build

Requires [libnfc](https://github.com/nfc-tools/libnfc) and 
[libmosquitto](https://mosquitto.org/man/libmosquitto-3.html)

```
make
```

## Run

```
./nfc-scanner <NFC device address> <NFC device name>
```
