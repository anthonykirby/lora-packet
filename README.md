# lora-packet

A pure [node.js](http://nodejs.org/) library to decode and encode packets
for LoRa/LoRaWAN<sup>TM</sup> radio communication, based on the specification
from the [LoRa Alliance](https://www.lora-alliance.org/) (based on V1.0.2 final), and as used by [The Things Network](https://www.thethingsnetwork.org/).

Packet decoding is also wrapped in a simple command-line tool that accepts input in hex and base-64

## Why?

- LoRa packets are encrypted at the radio link level. They could be
  decrypted at the radio receiver, but frequently they're transferred onwards
  as-is, because the radio doesn't have the crypto keys. This library lets you
  handle them in your code, rather than relying on less transparent / less
  documented / less convenient libraries / modules / systems.
- as a debugging tool, to check and decrypt packets
- node.js is available both on the application server, and can also be
  available on network gateways (which are otherwise hard to write code to
  run on)- a single library can be used in both places / either place
- inverted use case: you have a remote gateway, and you want to send gateway
  telemetry/monitoring using the same uplink channel as used by the radio, as
  LoRa packets - so you encode your gateway telemetry as LoRa packets & slip
  them into the uplink.

## Help me to help you: Give me data!

I'm happy to fix or add functionality, but I can only do this if I have
example packets.

## Features:

- LoRa packet parsing & analysis
- MIC (Message Integrity Check) checking
- payload decryption
- decodes uplink & downlink packets, network join etc
- ability to create LoRa format packets

## Installation

(nodejs>=10)

```bash
npm install lora-packet
```

(nodejs<=9)

```bash
npm install lora-packet@~0.7.14
```

## Usage (command-line packet decoding):

```
$ lora-packet-decode --hex 40F17DBE4900020001954378762B11FF0D
```

```
$ lora-packet-decode --base64 QPF9vkkAAgABlUN4disR/w0=
```

```
$ lora-packet-decode \
        --appkey ec925802ae430ca77fd3dd73cb2cc588 \
        --nwkkey 44024241ed4ce9a68c6a8bc055233fd3 \
        --hex 40F17DBE4900020001954378762B11FF0D
```

## Usage (packet decoding from wire):

### fromWire(buffer)

Parse & create packet structure from wire-format buffer (i.e. "radio PHYPayload")

### packet.getBuffers()

returns an object containing the decoded packet fields, named as per
LoRa spec, e.g. _MHDR_, _MACPayload_ etc

Note: _DevAddr_ and _FCnt_ are stored big-endian, i.e. the way round
that you'd expect to see them, not how they're sent down the wire.

### packet.getMType()

returns the packet _MType_ as a string (e.g. "Unconfirmed Data Up")

### packet.getDir()

returns the direction (_Dir_) as a string ('up' or 'down')

### packet.getFCnt()

returns the frame count (_FCnt_) as a number

### packet.isConfirmed()

returns true if packet is confirmed, else returns false 

### packet.getFPort()

returns the port (_FPort_) as a number (or null if FPort is absent)

### packet.getFCtrlACK()

returns the flag (_ACK_) of field _FCtrl_ as a boolean

### packet.getFCtrlFPending()

returns the flag (_FPending_) of field _FCtrl_ as a boolean

### packet.getFCtrlADR()

returns the flag (_ADR_) of field _FCtrl_ as a boolean

### packet.getFCtrlADRACKReq()

returns the flag (_ADRACKReq_) of field _FCtrl_ as a boolean

### verifyMIC(packet, NwkSKey [, AppKey] [, FCntMSBytes])

returns a boolean; true if the MIC is correct (i.e. the value at the end of
the packet data matches the calculation over the packet contents)

NB AppKey is used for Join Request/Accept, otherwise NwkSkey is used

Optionally, if using 32-byt FCnts, supply the upper 2 bytes as a Buffer.

### calculateMIC(packet, NwkSKey [, AppKey] [, FCntMSBytes])

returns the MIC, as a buffer

NB AppKey is used for Join Request/Accept, otherwise NwkSkey is used

Optionally, if using 32-byt FCnts, supply the upper 2 bytes as a Buffer.

### recalculateMIC(packet, NwkSKey [, AppKey] [, FCntMSBytes])

calculates the MIC & updates the packet (no return value)

NB AppKey is used for Join Request/Accept, otherwise NwkSkey is used

Optionally, if using 32-byt FCnts, supply the upper 2 bytes as a Buffer.

### decrypt(packet, AppSKey, NwkSKey [, FCntMSBytes]

decrypts and returns the payload as a buffer:
The library cannot know whether this is an ASCII string or binary data,
so you will need to interpret it appropriately.

NB the relevant key is chosen depending on the value of _FPort_,
and NB key order is different than MIC APIs

### decryptJoinAccept(inputData, appKey)

decrypts and returns the Join Accept Message as a buffer:

```javascript
const packet = lora_packet.fromWire(inputData);
const DecryptedPacket = lora_packet.fromWire(lora_packet.decryptJoinAccept(packet, appKey));
```

## Usage (packet encoding to wire):

### fromFields(data)

takes an object with properties representing fields in the packet - see example below

- and generates a valid packet from them. If a NwkSKey is provided then the
  MIC is calculated (otherwise = "EEEEEEEE") and if the relevant encryption key
  (AppSKey or NwkSKey depending on port) then the payload is encrypted.

The wire-format payload can be obtained by calling _getPHYPayload()_
(or _getBuffers().PHYPayload_)

#### Required fields:

- _MType_ - supplied as number (0-7 or constants) or string
- _DevAddr_ - supplied as Buffer (4)
- _FCnt_ - supplied as number or Buffer(2)

#### Optional fields:

- _FCtrl.ADR_ - boolean (default = false)
- _FCtrl.ADRACKReq_ - boolean (default = false)
- _FCtrl.ACK_ - boolean (default = false)
- _FCtrl.FPending_ - boolean (default = false)
- _FPort_ - number (default = 1)

## Example:

```javascript
const lora_packet = require("lora-packet");

//-----------------
// packet decoding

// decode a packet
const packet = lora_packet.fromWire(Buffer.from("40F17DBE4900020001954378762B11FF0D", "hex"));

// debug: prints out contents
// - contents depend on packet type
// - contents are named based on LoRa spec
console.log("packet.toString()=\n" + packet);

// e.g. retrieve payload elements
console.log("packet MIC=" + packet.MIC.toString("hex"));
console.log("FRMPayload=" + packet.FRMPayload.toString("hex"));

// check MIC
const NwkSKey = Buffer.from("44024241ed4ce9a68c6a8bc055233fd3", "hex");
console.log("MIC check=" + (lora_packet.verifyMIC(packet, NwkSKey) ? "OK" : "fail"));

// calculate MIC based on contents
console.log("calculated MIC=" + lora_packet.calculateMIC(packet, NwkSKey).toString("hex"));

// decrypt payload
const AppSKey = Buffer.from("ec925802ae430ca77fd3dd73cb2cc588", "hex");
console.log("Decrypted (ASCII)='" + lora_packet.decrypt(packet, AppSKey, NwkSKey).toString() + "'");
console.log("Decrypted (hex)='0x" + lora_packet.decrypt(packet, AppSKey, NwkSKey).toString("hex") + "'");

//-----------------
// packet creation

// create a packet
const constructedPacket = lora_packet.fromFields(
  {
    MType: "Unconfirmed Data Up", // (default)
    DevAddr: Buffer.from("01020304", "hex"), // big-endian
    FCtrl: {
      ADR: false, // default = false
      ACK: true, // default = false
      ADRACKReq: false, // default = false
      FPending: false, // default = false
    },
    FCnt: Buffer.from("0003", "hex"), // can supply a buffer or a number
    payload: "test",
  },
  Buffer.from("ec925802ae430ca77fd3dd73cb2cc588", "hex"), // AppSKey
  Buffer.from("44024241ed4ce9a68c6a8bc055233fd3", "hex") // NwkSKey
);
console.log("constructedPacket.toString()=\n" + constructedPacket);
const wireFormatPacket = constructedPacket.getPHYPayload();
console.log("wireFormatPacket.toString()=\n" + wireFormatPacket.toString("hex"));
```

## Notes:

#### Endianness

- LoRa sends data over the wire in little-endian format
  (see spec #1.2 "The octet order for all multi-­octet fields is little endian")
- lora-packet attempts to hide this from you, so e.g. DevAddr & FCnt are
  presented in big-endian format.
- For example, DevAddr=49be7df1 is sent over the wire as 0xf1, 0x7d, 0xbe, 0x49.
- Similarly, the fields in the Join Request message (AppEUI, DevEUI, DevNonce)
  are reversed on the wire

#### Can I help?

- I've done some testing, but of course I can only test using the packets
  that I can generate & receive with the radios I've got, and packets I've
  constructed myself. If you find a packet that `lora-packet` fails to parse,
  or incorrectly decodes / decrypts etc, please let me know!

#### LoRaWAN - naming clarification

It took me longer than expected to understand the various IDs & key names.
Different terminology is used by LoRaWAN / TTN / Multitech, & there's both
OTA & manual personalisation options. This is a quick summary which I hope
you'll find helpful.

(TODO!)

#### Version history

- 0.8.7 fix recalculateMIC
- 0.8.6 add isConfirmed & fix initialise with Port=0
- 0.8.5 add docs + text output for FPending (data down) + ADRACKReq (data up)
- 0.8.3 default FCnt should be 0
- 0.8.2 fix decryption of Join Accept
- 0.8.1 fix shebang
- 0.8.0 upgrade to typescript & node 10.x/12.x/14.x; deprecate pre-10.x
- 0.7.14 bump mocha version
- 0.7.13 fix CFList length
- 0.7.12 fix CFList byte order
- 0.7.10 add Decrypt Join Accept
- 0.7.8 improve support for 32-bit FCnt
- 0.7.7 add command-line support for AppSKey/NwkSKey
- 0.7.4 add support for 32-bit FCnt in MIC calculation
- 0.7.2 fix Join Accept parsing
- 0.7.0 add support for join packets and OTAA handshaking
- 0.6.0 when creating a packet from fields, if no FPort and no payload are specified, omit FPort
- 0.5.4 command-line behaves gracefully on no input
- 0.5.3 MIC for join messages; getter for FCtrl.ADRACKReq
- 0.5.2 fix FOpts parsing
- 0.5.0 add command-line tool
- 0.4.0 implemented creation of packet (+ MIC + encryption) from payload / fields
- 0.3.0 refactor to allow packet creation
- 0.2.0 initial release as npm

[Travi CI builds](https://travis-ci.org/anthonykirby/lora-packet)

#### TODO

- MAC Commands, as sent in _FOpts_ (or piggybacked in _FRMPayload_)

#### Credits

- Thank you to [David Olivari](https://github.com/davidonet)
- Thank you to [Larko](https://github.com/larkolab)
- Thank you to [Tommas Bakker](https://github.com/tommas-factorylab)
- Thank you to [Rob Gillan](https://github.com/rgillan)
- Thank you to [Christopher Hunt](https://github.com/huntc)
- Thank you to [Thibault Ortiz](https://github.com/tortizactility)
- Thank you to [Flemming Madsen](https://github.com/amplexdenmark)
- Thank you to [Giorgio Pillon](https://github.com/kalik1)
- Thank you to [Nuno Cruz](https://github.com/nunomcruz)
- Thank you to [Felipe Lima](https://github.com/felipefdl) and the fine folks at [TagoIO](https://tago.io/)
- Thank you to [Nicolas Graziano](https://github.com/ngraziano)
- Thank you to [Benjamin Cabé](https://github.com/kartben)
- Thank you to [kalik1](https://github.com/kalik1)
