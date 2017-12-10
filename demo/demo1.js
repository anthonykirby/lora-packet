"use strict";
var lora_packet = require('../lib/index.js');
//var lora_packet = require('lora-packet');

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
console.log("Decrypted (ASCII)='" + lora_packet.decrypt(packet, AppSKey, NwkSKey).toString() + "'");
console.log("Decrypted (hex)='0x" + lora_packet.decrypt(packet, AppSKey, NwkSKey).toString('hex') + "'");


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
