"use strict";

var util = require('./util.js')("lora-packet parser");

exports.create = function (contents) {
    return LoraPacket(contents);
};

// decoding MType description & direction
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


    if (contents instanceof Buffer) {
        _initialiseFromBuffer(contents);
    }
    else if (typeof contents == 'string') {
        _initialiseFromString(contents);
    } else {
        _initialiseFromEmpty();
    }


    this.getX = function () {
        return that._x;
    };

    this.getPacket = function () {
        return that._packet;
    };


    // parse incoming packet
    function _initialiseFromBuffer(contents) {
        that._packet = {};
        var p = that._packet;

        // duplicate buffer to guard against modification
        var incoming = new Buffer(contents);

        p.PHYPayload = incoming;

        p.MHDR = incoming.slice(0, 1);

        p.MACPayload = incoming.slice(1, incoming.length - 4);
        p.MIC = incoming.slice(incoming.length - 4);

        p.FCtrl = p.MACPayload.slice(4, 5);
        var FCtrl = p.FCtrl.readInt8(0);
        var FOptsLen = FCtrl & 0x0f;
        p.FOpts = p.MACPayload.slice(6, 6 + FOptsLen);
        var FHDR_length = 7 + FOptsLen;
        p.FHDR = p.MACPayload.slice(0, 0 + FHDR_length);    // TODO silence linter
        p.DevAddr = p.FHDR.slice(0, 4);

        p.FCnt = p.FHDR.slice(5, 7);

        // what's left? Either FPort+FRMPayload or nothing.
        if (FHDR_length == p.MACPayload.length) {
            p.FPort = new Buffer(0);
            p.FRMPayload = new Buffer(0);
        } else {
            p.FPort = p.MACPayload.slice(FHDR_length, FHDR_length + 1);
            p.FRMPayload = p.MACPayload.slice(FHDR_length + 1);
        }
    }

    function _initialiseFromString(contents) {
        that._x = contents;
    }

    function _initialiseFromEmpty() {
        that._x = "empty";
    }


    this._getMType = function () {
        return (that._packet.MHDR.readUInt8(0) & 0xff) >> 5;
    };

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
        return that._packet.FCnt.readUInt16LE(0);
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
        msg += "     DevAddr = " + p.DevAddr.toString('hex') + "\n";
        msg += "       FCtrl = " + p.FCtrl.toString('hex') + "\n";//TODO as binary?
        msg += "        FCnt = " + p.FCnt.toString('hex') + "\n";
        msg += "       FOpts = " + p.FOpts.toString('hex') + "\n";

        return msg;
    };

}
