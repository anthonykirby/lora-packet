"use strict";
var lora_packet = require('../lib/index.js');
//var lora_packet = require('lora-packet');

// decode a packet
var packet = lora_packet.fromWire(new Buffer('40F17DBE4900020001954378762B11FF0D', 'hex'));

// debug: prints out contents
// - contents depend on packet type
// - contents are named based on LoRa spec
console.log ("packet.toString()=\n"+packet);

// e.g. retrieve payload elements
console.log("packet MIC=" + packet.getBuffers().MIC.toString('hex'));
console.log("FRMPayload=" + packet.getBuffers().FRMPayload.toString('hex'));

// check MIC
var NwkSKey = new Buffer('44024241ed4ce9a68c6a8bc055233fd3', 'hex');
console.log("MIC check="+(lora_packet.verifyMIC(packet, NwkSKey) ? "OK" : "fail"));

// calculate MIC based on contents
console.log("calculated MIC=" + lora_packet.getMIC(packet, NwkSKey).toString('hex'));

// decrypt payload
var AppSKey = new Buffer('ec925802ae430ca77fd3dd73cb2cc588', 'hex');
console.log("Decrypted='"+lora_packet.decrypt(packet, AppSKey, NwkSKey).toString()+"'");
