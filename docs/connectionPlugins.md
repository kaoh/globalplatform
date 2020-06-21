# Abstract

Previous versions of the [GlobalPlatform Library] did only support smart cards connected to the system by a card reader using [PC/SC](http://en.wikipedia.org/wiki/PC/SC ). The connectivity was limited to local connected cards in general. Since version 6.0.0 of the GlobalPlatform Library it is possible to integrate other means of connecting to a card.

With the arrival of NFC capable phones and the vision of
installing authentication applications, debit cards, credit cards and other cryptographically oriented applications this communication path is often not sufficient. So now it is possible to use the GlobalPlatform Library as middleware layer and plug in a remote connection. E.g. an NFC phone might require an OTA installation so a socket connection could be implemented and a proxy application on the phone would transmit the commands.

# Implement Connection Plugin

If you want to write your own connection plugin you must implemented the functions from the [Connection Plugin Header](https://github.com/kaoh/globalplatform/blob/master/globalplatform/src/globalplatform/connectionplugin.h) file. A good template is the [source code](https://github.com/kaoh/globalplatform/tree/master/gppcscconnectionplugin) of the PC-SC Connection Plugin.
