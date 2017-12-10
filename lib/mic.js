"use strict";

var packet = require('./packet.js');

/**
 * LoRa MIC calculation and checking
 *
 * See LoRa spec #4.4 "Message Integrity Code (MIC)"
 *
 *
 * MIC calculated over
 *      B0 | MHDR | FHDR | FPort | FRMPayload
 *  ( = B0 | MHDR | MACPayload )
 *
 * where B0 =
 *   0x49
 *   0x00 0x00 0x00 0x00
 *   direction-uplink/downlink [1]
 *   DevAddr [4]
 *   FCnt as 32-bit, lsb first [4]
 *   0x00
 *   message length [1]
 *
 */

var aesCmac = require('node-aes-cmac').aesCmac;

var util = require('./util.js')("lora-packet verify");
var checkDefined = util.checkDefined;
var checkBufferLength = util.checkBufferLength;
var checkBuffer = util.checkBuffer;


// calculate MIC from packet
exports.calculateMIC = function (packet, NwkSKey, AppKey, FCntMSBytes) {
    var pktBufs = packet.getBuffers();
    if(packet.isJoinRequestMessage() == true) {
        checkBuffer(pktBufs.PHYPayload, "pktBufs packet");
        checkBufferLength(AppKey, "AppKey", 16);

        checkBuffer(pktBufs.MHDR, "pktBufs packet.MHDR");
        checkBuffer(pktBufs.AppEUI, "pktBufs packet.AppEUI");
        checkBuffer(pktBufs.DevEUI, "pktBufs packet.DevEUI");
        checkBuffer(pktBufs.DevNonce, "pktBufs packet.DevNonce");

        var msglen = pktBufs.MHDR.length + pktBufs.AppEUI.length + pktBufs.DevEUI.length + pktBufs.DevNonce.length;

        // CMAC over MHDR | AppEUI | DevEUI | DevNonce
        // the seperate fields are not in little-endian format, use the concatenated field
        var cmac_input = Buffer.concat([pktBufs.MHDR, pktBufs.MACPayload]);

        // CMAC calculation (as RFC4493)
        var full_cmac = aesCmac(AppKey, cmac_input, {returnAsBuffer: true});

        // only first 4 bytes of CMAC are used as MIC
        var MIC = full_cmac.slice(0,4);

        return MIC;
    } else if(packet.isJoinAcceptMessage() == true) {
        checkBuffer(pktBufs.PHYPayload, "pktBufs packet");
        checkBufferLength(AppKey, "AppKey", 16);

        checkBuffer(pktBufs.MHDR, "pktBufs packet.MHDR");
        checkBuffer(pktBufs.AppNonce, "pktBufs packet.AppNonce");
        checkBuffer(pktBufs.NetID, "pktBufs packet.NetID");
        checkBuffer(pktBufs.DevAddr, "pktBufs packet.DevAddr");
        checkBuffer(pktBufs.DLSettings, "pktBufs packet.DLSettings");
        checkBuffer(pktBufs.RxDelay, "pktBufs packet.RxDelay");
        checkBuffer(pktBufs.CFList, "pktBufs packet.CFList");

        var msglen = pktBufs.MHDR.length + pktBufs.AppNonce.length + pktBufs.NetID.length + pktBufs.DevAddr.length + 
            pktBufs.DLSettings.length + pktBufs.RxDelay.length + pktBufs.CFList.length;

        // CMAC over MHDR | AppNonce | NetID | DevAddr | DLSettings | RxDelay | CFList
        // the seperate fields are not encrypted, use the encrypted concatenated field
        var cmac_input = Buffer.concat([pktBufs.MHDR, pktBufs.MACPayload]);

        // CMAC calculation (as RFC4493)
        var full_cmac = aesCmac(AppKey, cmac_input, {returnAsBuffer: true});

        // only first 4 bytes of CMAC are used as MIC
        var MIC = full_cmac.slice(0,4);

        return MIC;
    } else {
        checkBuffer(pktBufs.PHYPayload, "pktBufs packet");
        checkBufferLength(NwkSKey, "NwkSKey", 16);

        checkBufferLength(pktBufs.DevAddr, "pktBufs packet.DevAddr", 4);
        checkBufferLength(pktBufs.FCnt, "pktBufs packet.FCnt", 2);

        checkBuffer(pktBufs.MHDR, "pktBufs packet.MHDR");
        checkBuffer(pktBufs.MACPayload, "pktBufs packet.MACPayload");

        if (FCntMSBytes) {
            checkBufferLength(FCntMSBytes, "FCntMSBytes", 2);
        } else {
            FCntMSBytes = new Buffer('0000', 'hex');
        }

        var Dir;
        if (packet.getDir() == 'up') {
            Dir = util.bufferFromUInt8(0);
        } else if (packet.getDir() == 'down') {
            Dir = util.bufferFromUInt8(1);
        } else {
            throw new Error (errHdr + "expecting direction to be either 'up' or 'down'");
        }

        var msglen = pktBufs.MHDR.length + pktBufs.MACPayload.length;

        var B0 = Buffer.concat([
            new Buffer("4900000000", 'hex'),    // as spec
            Dir,  // direction ('Dir')
            util.reverse(pktBufs.DevAddr),
            util.reverse(pktBufs.FCnt),
            FCntMSBytes,    // upper 2 bytes of FCnt (zeroes)
            util.bufferFromUInt8(0),    // 0x00
            util.bufferFromUInt8(msglen)     // len(msg)
            ]);

        // CMAC over B0 | MHDR | MACPayload
        var cmac_input = Buffer.concat([B0, pktBufs.MHDR, pktBufs.MACPayload]);

        // CMAC calculation (as RFC4493)
        var full_cmac = aesCmac(NwkSKey, cmac_input, {returnAsBuffer: true});

        // only first 4 bytes of CMAC are used as MIC
        var MIC = full_cmac.slice(0,4);

        return MIC;
    }
};

// verify is just calculate & compare
exports.verifyMIC = function (packet, NwkSKey, AppKey, FCntMSBytes) {
    var pktBufs = packet.getBuffers();
    checkBufferLength(pktBufs.MIC, "pktBufs packet.MIC", 4);

    var calculated = exports.calculateMIC(packet, NwkSKey, AppKey, FCntMSBytes);
    return util.areBuffersEqual(pktBufs.MIC, calculated);
};

// calculate MIC & store
exports.recalculateMIC = function (packet, NwkSKey, AppKey, FCntMSBytes) {
    var calculated = exports.calculateMIC(packet, NwkSKey, AppKey, FCntMSBytes);
    var pktBufs = packet.getBuffers();
    pktBufs.MIC = calculated;
};



