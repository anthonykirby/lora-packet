lora-packet
===========

A library to decode and encode packets for LoRa/LoRaWAN<sup>TM</sup> radio communication, based on the specification from the [LoRa Alliance](https://www.lora-alliance.org/) (based on V1.0.1 Draft 3), as used by [The Things Network](https://www.thethingsnetwork.org/)


## Why?

* as a debugging tool, to check and decrypt packets.  
* LoRa packets are encrypted at the radio link level.  They can be decrypted at the radio receiver, but frequently they're transferred onwards as-is, which can make it hard to verify/debug operation.
* node.js is available both on the application server, and on network gateways, which are otherwise hard to write code to run on
* a gateway can use this library to generate packets in LoRa format, which can then be used to transmit gateway monitoring/stats etc via the same channel as is used by 

## Features

* packet parsing & analysis
* MIC checking
* payload decryption
* handles uplink & downlink packets, network join etc
* ability to create LoRa format packet

# Example

`example goes here`


## Status:

### To do:

* packet assembly/encryption (this will be trivial given we have parsing + MIC check + decryption)
* testing with wider range of data (downlink, network join etc) 


