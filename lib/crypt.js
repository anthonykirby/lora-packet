"use strict";

var util = require('./util.js')("lora-packet crypto");

var CryptoJS = require("crypto-js");
var aesCmac = require('node-aes-cmac').aesCmac;
var fromWire = require('./packet').fromWire;

var errHdr = "decrypt error: ";

// brevity
//var checkDefined = util.checkDefined;
var checkBufferLength = util.checkBufferLength;
var checkBuffer = util.checkBuffer;

// IV is always zero
var LORA_IV = CryptoJS.enc.Hex.parse('00000000000000000000000000000000');

exports.decrypt = function(packet, AppSKey, NwkSKey, fCntMSB32) {
    var pktBufs = packet.getBuffers();
    checkBuffer(pktBufs.PHYPayload, "parsed packet");

    if (!fCntMSB32) fCntMSB32 = Buffer.from([0x00, 0x00]);

    // calc number of (16-byte/128-bit) blocks
    var blocks = Math.ceil(pktBufs.FRMPayload.length / 16);

    // create what LoRaWAN calls "Sequence S"
    // TODO this should be (at least) in a Uint8Array for ease of import to cryptojs
    var plain_S = new Buffer(16 * blocks);
    for (var block = 0; block < blocks; block++) {
        var Ai = _metadataBlock_Ai(packet, block, fCntMSB32);
        Ai.copy(plain_S, block * 16);
    }

    // encrypt "Sequence S" with key to create cipherstream

    // #4.3.3  key depends on port
    var key = packet.getFPort() === 0 ? NwkSKey : AppSKey;
    checkBufferLength(key, "appropriate key", 16);

    // TODO is there a better way to get cryptojs to ingest message/key?
    var cipherstream_base64 = CryptoJS.AES.encrypt(
        CryptoJS.enc.Hex.parse(plain_S.toString('hex')),
        CryptoJS.enc.Hex.parse(key.toString('hex')), {
            mode: CryptoJS.mode.ECB,
            iv: LORA_IV,
            padding: CryptoJS.pad.NoPadding
        });
    var cipherstream = new Buffer(cipherstream_base64.toString(), 'base64');

    // create buffer for decrypted message
    var plaintextPayload = new Buffer(pktBufs.FRMPayload.length);

    // xor the cipherstream with payload to create plaintext
    for (var i = 0; i < pktBufs.FRMPayload.length; i++) {
        var Si = cipherstream.readUInt8(i);
        plaintextPayload.writeUInt8(Si ^ pktBufs.FRMPayload.readUInt8(i), i);
    }

    // TODO? provide a convenience conversion to UTF-8

    return plaintextPayload;
};

exports.decryptJoin = function(packet, AppKey) {
    var pktBufs = packet.getBuffers();
    checkBuffer(pktBufs.MACPayloadWithMIC, "parsed packet");

    checkBufferLength(AppKey, "AppKey", 16);

    // TODO is there a better way to get cryptojs to ingest message/key?
    var cipherstream = CryptoJS.AES.decrypt(
        { ciphertext: CryptoJS.enc.Hex.parse(pktBufs.MACPayloadWithMIC.toString('hex')) },
        CryptoJS.enc.Hex.parse(AppKey.toString('hex')),
        {
            mode: CryptoJS.mode.ECB,
            padding: CryptoJS.pad.NoPadding
        }
    );
    return new Buffer(CryptoJS.enc.Hex.stringify(cipherstream), 'hex');
};

exports.generateSessionKeys = function(AppKey, NetId, AppNonce, DevNonce) {
    checkBufferLength(AppKey, "AppKey", 16);
    checkBufferLength(NetId, "NetId", 3);
    checkBufferLength(AppNonce, "AppNonce", 3);
    checkBufferLength(DevNonce, "DevNonce", 2);
    var output = {};

    // NwkSKey
    var nwkSKeyNonce = Buffer.concat([new Buffer('01', 'hex'), util.reverse(AppNonce), util.reverse(NetId), util.reverse(DevNonce), new Buffer('00000000000000', 'hex')]);
    var nwkSKey_base64 = CryptoJS.AES.encrypt(
        CryptoJS.enc.Hex.parse(nwkSKeyNonce.toString('hex')),
        CryptoJS.enc.Hex.parse(AppKey.toString('hex')), {
            mode: CryptoJS.mode.ECB,
            padding: CryptoJS.pad.NoPadding
        });
    output.NwkSKey = new Buffer(nwkSKey_base64.toString(), 'base64');

    // AppSKey
    var appSKeyNonce = Buffer.concat([new Buffer('02', 'hex'), util.reverse(AppNonce), util.reverse(NetId), util.reverse(DevNonce), new Buffer('00000000000000', 'hex')]);
    var appSKey_base64 = CryptoJS.AES.encrypt(
        CryptoJS.enc.Hex.parse(appSKeyNonce.toString('hex')),
        CryptoJS.enc.Hex.parse(AppKey.toString('hex')), {
            mode: CryptoJS.mode.ECB,
            padding: CryptoJS.pad.NoPadding
        });
    output.AppSKey = new Buffer(appSKey_base64.toString(), 'base64');
    return output;
};

function encrypt(buffer, key) {
    var ciphertext = CryptoJS.AES.encrypt(
        CryptoJS.lib.WordArray.create(buffer),
        CryptoJS.lib.WordArray.create(key),
        {
            mode: CryptoJS.mode.ECB,
            iv: LORA_IV,
            padding: CryptoJS.pad.NoPadding
        }
    ).ciphertext.toString(CryptoJS.enc.Hex);
    return new Buffer(ciphertext, 'hex');
}

exports.decryptJoinAccept = function (phyPayload, appKey) {
    // ## Decrypt payload, including MIC
    //
    // The network server uses an AES decrypt operation in ECB mode to encrypt the join-accept
    // message so that the end-device can use an AES encrypt operation to decrypt the message.
    // This way an end-device only has to implement AES encrypt but not AES decrypt.
    var mhdr = phyPayload.slice(0, 1);
    var joinAccept = encrypt(phyPayload.slice(1), appKey);
    return  Buffer.concat([mhdr,joinAccept]);

}

function _metadataBlock_Ai(packet, i, fCntMSB32) {

    // TODO common code
    if (!fCntMSB32) fCntMSB32 = Buffer.from([0x00, 0x00]);


    var Dir;
    if (packet.getDir() == 'up') {
        Dir = util.bufferFromUInt8(0);
    } else if (packet.getDir() == 'down') {
        Dir = util.bufferFromUInt8(1);
    } else {
        throw new Error(errHdr + "expecting direction to be either 'up' or 'down'");
    }

    var Ai_buf = Buffer.concat([
        new Buffer("0100000000", 'hex'), // as spec
        Dir, // direction ('Dir')
        util.reverse(packet.getBuffers().DevAddr),
        util.reverse(packet.getBuffers().FCnt),
        //util.bufferFromUInt16LE(fCntMSB32), // upper 2 bytes of FCnt (zeroes)
        fCntMSB32,
        util.bufferFromUInt8(0), // 0x00
        util.bufferFromUInt8(i + 1) // block number
    ]);

    return Ai_buf;
}
