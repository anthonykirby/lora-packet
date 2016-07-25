"use strict";

var util = require('./util.js')("lora-packet parser");

exports.create = function (contents) {
    return LoraPacket(contents);
};

// decoding MType description & direction
var MTYPE_JOIN_REQUEST = 0;
var MTYPE_JOIN_ACCEPT = 1;
var MTYPE_UNCONFIRMED_DATA_UP = 2;
var MTYPE_UNCONFIRMED_DATA_DOWN = 2;
var MTYPE_CONFIRMED_DATA_UP = 3;
var MTYPE_CONFIRMED_DATA_DOWN = 4;

var MTYPE_DESCRIPTIONS = [
    'Join Request',
    'Join Accept',
    'Unconfirmed Data Up',
    'Unconfirmed Data Down',
    'Confirmed Data Up',
    'Confirmed Data Down',
    'RFU',
    'Proprietary'
];
var MTYPE_DIRECTIONS = [
    null,
    null,
    'up',
    'down',
    'up',
    'down',
    null,
    null
];


function LoraPacket(contents) {
    if (!(this instanceof LoraPacket)) return new LoraPacket(contents);
    var that = this;


    this.getX = function () {
        return that._x;
    };

    this.getPacket = function () {
        return that._packet;
    };

    this._getMType = function () {
        return (that._packet.MHDR.readUInt8(0) & 0xff) >> 5;
    };

    this.isDataMessage = function () {
        switch (that._getMType()) {
            case MTYPE_UNCONFIRMED_DATA_UP:
            case MTYPE_UNCONFIRMED_DATA_DOWN:
            case MTYPE_CONFIRMED_DATA_UP:
            case MTYPE_CONFIRMED_DATA_DOWN:
                return true;
            default:
                return false;
        }
    };

    this.isJoinMessage = function () {
        return that.isJoinRequestMessage() || that.isJoinAcceptMessage();
    };
    this.isJoinRequestMessage = function () {
        return (that._getMType() == MTYPE_JOIN_REQUEST);
    };
    this.isJoinAcceptMessage = function () {
        return (that._getMType() == MTYPE_JOIN_ACCEPT);
    };


    if (contents instanceof Buffer) {
        _initialiseFromBuffer(contents);
    }
    else if (typeof contents == 'string') {
        _initialiseFromString(contents);
    } else {
        _initialiseFromEmpty();
    }

    // parse incoming packet
    function _initialiseFromBuffer(contents) {
        that._packet = {};
        var p = that._packet;

        // duplicate buffer to guard against modification
        var incoming = new Buffer(contents);

        p.PHYPayload = incoming;

        p.MHDR = incoming.slice(0, 1);

//        var type = p.MHDR._getMType;
        if (that.isJoinRequestMessage()) {
            // NB little-endian buffers!
            p.AppEUI = util.reverse(incoming.slice(1, 1 + 8));
            p.DevEUI = util.reverse(incoming.slice(9, 9 + 8));
            p.DevNonce = util.reverse(incoming.slice(17, 17 + 2));
        }
        else if (that.isJoinAcceptMessage()) {
            p.AppNonce = util.reverse(incoming.slice(1, 1 + 3));
            p.NetID = util.reverse(incoming.slice(4, 4 + 3));
            p.DevAddr = util.reverse(incoming.slice(7, 7 + 4));
            var DLSettings = incoming.readInt8(11);
            var RxDelay = incoming.readInt8(12);
        }
        else if (that.isDataMessage()) {
            p.MACPayload = incoming.slice(1, incoming.length - 4);
            p.MIC = incoming.slice(incoming.length - 4);

            p.FCtrl = p.MACPayload.slice(4, 5);
            var FCtrl = p.FCtrl.readInt8(0);
            var FOptsLen = FCtrl & 0x0f;
            p.FOpts = p.MACPayload.slice(6, 6 + FOptsLen);
            var FHDR_length = 7 + FOptsLen;
            p.FHDR = p.MACPayload.slice(0, 0 + FHDR_length);    // TODO silence linter
            p.DevAddr = util.reverse(p.FHDR.slice(0, 4)); // NB little-endian buffers!

            p.FCnt = util.reverse(p.FHDR.slice(5, 7)); // NB little-endian buffers!

            // what's left? Either FPort+FRMPayload or nothing.
            if (FHDR_length == p.MACPayload.length) {
                p.FPort = new Buffer(0);
                p.FRMPayload = new Buffer(0);
            } else {
                p.FPort = p.MACPayload.slice(FHDR_length, FHDR_length + 1);
                p.FRMPayload = p.MACPayload.slice(FHDR_length + 1);
            }
        }
    }

// TODO!
//    function _initialiseFromString(contents) {
//        that._x = contents;
//    }
//
//    function _initialiseFromEmpty() {
//        that._x = "empty";
//    }


    // provide MType as a string
    this.getMType = function () {
        return MTYPE_DESCRIPTIONS[that._getMType()];
    };

    // provide Direction as a string
    this.getDir = function () {
        return MTYPE_DIRECTIONS[that._getMType()];
    };

    // provide FPort as a number
    this.getFPort = function () {
        return that._packet.FPort.readUInt8(0);
    };

    // provide FCnt as a number
    this.getFCnt = function () {
        return that._packet.FCnt.readUInt16BE(0);
    };

    // provide FCtrl.ACK as a flag
    this.getFCtrlACK = function () {
        return !!(that._packet.FCtrl.readUInt8(0) & 0x20);  // TODO constant
    };

    // provide FCtrl.ADR as a flag
    this.getFCtrlADR = function () {
        return !!(that._packet.FCtrl.readUInt8(0) & 0x80);  // TODO constant
    };

    this.getBuffers = function () {
        return that._packet;
    };

    /*    this.setPlaintextPayload = function(payload) {
     that._plaintextPayload = payload;
     };*/

    /*    this.getPlaintextPayload = function() {
     return that._plaintextPayload;
     };*/


    this.toString = function () {
        var p = that._packet;

        var msg = "";

        if (that.isJoinRequestMessage()) { // TODO constants
            msg += "      AppEUI = " + p.AppEUI.toString('hex') + "\n";
            msg += "      DevEUI = " + p.DevEUI.toString('hex') + "\n";
            msg += "    DevNonce = " + p.DevNonce.toString('hex') + "\n";
        }
        else if (that.isJoinAcceptMessage()) { // TODO constants
            msg += "    AppNonce = " + p.AppNonce.toString('hex') + "\n";
            msg += "       NetID = " + p.NetID.toString('hex') + "\n";
            msg += "     DevAddr = " + p.DevAddr.toString('hex') + "\n";
            // TODO & the rest
        }
        else if (that.isDataMessage())  // TODO constants
        {
            msg += "  PHYPayload = " + p.PHYPayload.toString('hex') + "\n";
            msg += "\n";
            msg += "( PHYPayload = MHDR[1] | MACPayload[..] | MIC[4] )\n";
            msg += "        MHDR = " + p.MHDR.toString('hex') + "\n";
            msg += "  MACPayload = " + p.MACPayload.toString('hex') + "\n";
            msg += "         MIC = " + p.MIC.toString('hex') + "\n";
            msg += "\n";
            msg += "( MACPayload = FHDR | FPort | FRMPayload )\n";
            msg += "        FHDR = " + p.FHDR.toString('hex') + "\n";
            msg += "       FPort = " + p.FPort.toString('hex') + "\n";
            msg += "  FRMPayload = " + p.FRMPayload.toString('hex') + "\n";
            msg += "\n";
            msg += "      ( FHDR = DevAddr[4] | FCtrl[1] | FCnt[2] | FOpts[0..15] )\n";
            msg += "     DevAddr = " + p.DevAddr.toString('hex') + " (Big Endian)\n";
            msg += "       FCtrl = " + p.FCtrl.toString('hex') + "\n";//TODO as binary?
            msg += "        FCnt = " + p.FCnt.toString('hex') + " (Big Endian)\n";
            msg += "       FOpts = " + p.FOpts.toString('hex') + "\n";
            msg += "\n";
            msg += "Message Type = " + that.getMType() + "\n";
            msg += "   Direction = " + that.getDir() + "\n";
            msg += "        FCnt = " + that.getFCnt() + "\n";
            msg += "   FCtrl.ACK = " + that.getFCtrlACK() + "\n";
            msg += "   FCtrl.ADR = " + that.getFCtrlADR() + "\n";
        }
        return msg;
    };

}
