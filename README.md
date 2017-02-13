# lora-packet

A pure [node.js](http://nodejs.org/) library to decode and encode packets 
for LoRa/LoRaWAN<sup>TM</sup> radio communication, based on the specification 
from the [LoRa Alliance](https://www.lora-alliance.org/) (based on V1.0.1 
Draft 3), and as used by [The Things Network](https://www.thethingsnetwork.org/).  

Packet decoding is also wrapped in a simple command-line tool that accepts input in hex and base-64


## Why?

* LoRa packets are encrypted at the radio link level.  They could be 
decrypted at the radio receiver, but frequently they're transferred onwards 
as-is, because the radio doesn't have the crypto keys.  This library lets you 
handle them in your code, rather than relying on less transparent / less 
documented / less convenient libraries / modules / systems.
* as a debugging tool, to check and decrypt packets
* node.js is available both on the application server, and can also be 
available on network gateways (which are otherwise hard to write code to 
run on)- a single library can be used in both places / either place
* inverted use case:  you have a remote gateway, and you want to send gateway 
telemetry/monitoring using the same uplink channel as used by the radio, as 
LoRa packets - so you encode your gateway telemetry as LoRa packets & slip 
them into the uplink.

## Features:

* LoRa packet parsing & analysis
* MIC (Message Integrity Check) checking
* payload decryption
* decodes uplink & downlink packets, network join etc
* ability to create LoRa format packets

## Installation

    npm install lora-packet

## Usage (command-line packet decoding):

    bin/lora-packet-decode --hex 40F17DBE4900020001954378762B11FF0D
    bin/lora-packet-decode --base64 QPF9vkkAAgABlUN4disR/w0=

## Usage (packet decoding from wire):

### fromWire(buffer)

Parse & create packet structure from wire-format buffer (i.e. "radio PHYPayload")

### packet.getBuffers()

returns an object containing the decoded packet fields, named as per 
LoRa spec, e.g. *MHDR*, *MACPayload* etc

Note: *DevAddr* and *FCnt* are stored big-endian, i.e. the way round 
that you'd expect to see them, not how they're sent down the wire.  

### packet.getMType()

returns the packet *MType* as a string (e.g. "Unconfirmed Data Up")

### packet.getDir()

returns the direction (*Dir*) as a string ('up' or 'down')

### packet.getFCnt()

returns the frame count (*FCnt*) as a number

### packet.getFPort()

returns the port (*FPort*) as a number (or null if FPort is absent)

### packet.getFCtrl.ACK()

returns the flag (*ACK*) of field *FCtrl* as a boolean

### packet.getFCtrl.ADR()

returns the flag (*ADR*) of field *FCtrl* as a boolean

### packet.getFCtrl.ADRACKReq()

returns the flag (*ADRACKReq*) of field *FCtrl* as a boolean

### verifyMIC(packet, NwkSKey)

returns a boolean; true if the MIC is correct (i.e. the value at the end of 
the packet data matches the calculation over the packet contents)

### calculateMIC(packet, NwkSKey)

returns the MIC, as a buffer

### recalculateMIC(packet, NwkSKey)

calculates the MIC & updates the packet (no return value)

### decrypt(packet, AppSKey, NwkSKey)

decrypts and returns the payload (NB the relevant key is chosen depending on 
the value of *FPort*)


## Usage (packet encoding to wire):

### fromFields(data)

takes an object with properties representing fields in the packet - see example below 
- and generates a valid packet from them.   If a NwkSKey is provided then the
MIC is calculated (otherwise = "EEEEEEEE") and if the relevant encryption key
(AppSKey or NwkSKey depending on port) then the payload is encrypted.
 
The wire-format payload can be obtained by calling *getPHYPayload()* 
(or *getBuffers().PHYPayload*)
 
#### Required fields:

* *MType* - supplied as number (0-7 or constants) or string
* *DevAddr* - supplied as Buffer (4)
* *FCnt* - supplied as number or Buffer(2)

#### Optional fields:

* *FCtrl.ADR* - boolean (default = false)
* *FCtrl.ADRACKReq* - boolean (default = false)
* *FCtrl.ACK* - boolean (default = false)
* *FCtrl.FPending* - boolean (default = false)
* *FPort* - number (default = 1)





## Example:

```javascript
var lora_packet = require('lora-packet');

//-----------------
// packet decoding

// decode a packet
var packet = lora_packet.fromWire(new Buffer('40F17DBE4900020001954378762B11FF0D', 'hex'));

// debug: prints out contents
// - contents depend on packet type
// - contents are named based on LoRa spec
console.log("packet.toString()=\n" + packet);

// e.g. retrieve payload elements
console.log("packet MIC=" + packet.getBuffers().MIC.toString('hex'));
console.log("FRMPayload=" + packet.getBuffers().FRMPayload.toString('hex'));

// check MIC
var NwkSKey = new Buffer('44024241ed4ce9a68c6a8bc055233fd3', 'hex');
console.log("MIC check=" + (lora_packet.verifyMIC(packet, NwkSKey) ? "OK" : "fail"));

// calculate MIC based on contents
console.log("calculated MIC=" + lora_packet.calculateMIC(packet, NwkSKey).toString('hex'));

// decrypt payload
var AppSKey = new Buffer('ec925802ae430ca77fd3dd73cb2cc588', 'hex');
console.log("Decrypted='" + lora_packet.decrypt(packet, AppSKey, NwkSKey).toString() + "'");


//-----------------
// packet creation

// create a packet
var constructedPacket = lora_packet.fromFields({
        MType: 'Unconfirmed Data Up',   // (default)
        DevAddr: new Buffer('01020304', 'hex'), // big-endian
        FCtrl: {
            ADR: false,       // default = false
            ACK: true,        // default = false
            ADRACKReq: false, // default = false
            FPending: false   // default = false
        },
        FCnt: new Buffer('0003', 'hex'), // can supply a buffer or a number
        payload: 'test'
    }
    , new Buffer("ec925802ae430ca77fd3dd73cb2cc588", 'hex') // AppSKey
    , new Buffer("44024241ed4ce9a68c6a8bc055233fd3", 'hex') // NwkSKey
);
console.log("constructedPacket.toString()=\n" + constructedPacket);
var wireFormatPacket = constructedPacket.getPHYPayload();
console.log("wireFormatPacket.toString()=\n" + wireFormatPacket.toString('hex'));
```

## Notes:

#### Endianness

* LoRa sends data over the wire in little-endian format
(see spec #1.2 "The octet order for all multi-­octet fields is little endian")
* lora-packet attempts to hide this from you, so e.g. DevAddr & FCnt are 
presented in big-endian format.  
* For example, DevAddr=49be7df1 is sent over the wire as 0xf1, 0x7d, 0xbe, 0x49.
* Similarly, the fields in the Join Request message (AppEUI, DevEUI, DevNonce) 
are reversed on the wire


#### Can I help?

* I've done some testing, but of course I can only test using the packets 
that I can generate & receive with the radios I've got, and packets I've 
constructed myself.  If you find a packet that `lora-packet` fails to parse, 
or incorrectly decodes / decrypts etc, please let me know!

#### LoRaWAN - naming clarification

It took me longer than expected to understand the various IDs & key names. 
Different terminology is used by LoRaWAN / TTN / Multitech, & there's both 
 OTA & manual personalisation options.  This is a quick summary which I hope 
 you'll find helpful.
  
(TODO!)

(TODO: link to blog article when published)

#### Version history

* 0.6.0 when creating a packet from fields, if no FPort and no payload are specified, omit FPort
* 0.5.4 command-line behaves gracefully on no input
* 0.5.3 MIC for join messages; getter for FCtrl.ADRACKReq
* 0.5.2 fix FOpts parsing
* 0.5.0 add command-line tool
* 0.4.0 implemented creation of packet (+ MIC + encryption) from payload / fields
* 0.3.0 refactor to allow packet creation 
* 0.2.0 initial release as npm

#### TODO

* Support code for Over-the-Air Activation (OTAA), i.e. code that handles 
the *Join Request* message, negotiating the handshake & helping to genererate 
a *Join Accept* message.
 
* MAC Commands, as sent in *FOpts* (or piggybacked in *FRMPayload*)

#### Credits

* Thank you to [David Olivari](https://github.com/davidonet)
* Thank you to [Larko](https://github.com/larkolab)

