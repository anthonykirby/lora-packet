"use strict";

var util = require('./util.js')("lora-packet parser");

exports.fromWire = function(contents) {
    var lp = new LoraPacket();
    lp._fromWire(contents);

    // return null object on failure
    if (lp._packet !== null) {
        return lp;
    } else {
        return null;
    }
};

exports.fromFields = function(userFields) {
    var lp = new LoraPacket();
    lp._fromFields(userFields);

    // return null object on failure
    if (lp._packet !== null) {
        return lp;
    } else {
        return null;
    }
};


var constants = {
    // decoding MType description & direction
    MTYPE_JOIN_REQUEST: 0,
    MTYPE_JOIN_ACCEPT: 1,
    MTYPE_UNCONFIRMED_DATA_UP: 2,
    MTYPE_UNCONFIRMED_DATA_DOWN: 3,
    MTYPE_CONFIRMED_DATA_UP: 4,
    MTYPE_CONFIRMED_DATA_DOWN: 5,

    MTYPE_DESCRIPTIONS: [
        'Join Request',
        'Join Accept',
        'Unconfirmed Data Up',
        'Unconfirmed Data Down',
        'Confirmed Data Up',
        'Confirmed Data Down',
        'RFU',
        'Proprietary'
    ],

    MTYPE_DIRECTIONS: [
        'up',
        'down',
        'up',
        'down',
        'up',
        'down',
        null,
        null
    ],

    FCTRL_ADR: 0x80,
    FCTRL_ADRACKREQ: 0x40,
    FCTRL_ACK: 0x20,
    FCTRL_FPENDING: 0x10,
    DLSETTINGS_RXONEDROFFSET_MASK: 0x70,
    DLSETTINGS_RXONEDROFFSET_POS: 4,
    DLSETTINGS_RXTWODATARATE_MASK: 0x0F,
    DLSETTINGS_RXTWODATARATE_POS: 0,
    RXDELAY_DEL_MASK: 0x0F,
    RXDELAY_DEL_POS: 0
};

exports.constants = function() {
    //  return Object.assign({}, constants);
    return constants;
};


function LoraPacket(packetContents) {
    if (!(this instanceof LoraPacket)) return new LoraPacket(packetContents);
    var that = this;


    this.getPacket = function() {
        return that._packet;
    };

    this._getMType = function() {
        return (that._packet.MHDR.readUInt8(0) & 0xff) >> 5;
    };

    this.isDataMessage = function() {
        switch (that._getMType()) {
            case constants.MTYPE_UNCONFIRMED_DATA_UP:
            case constants.MTYPE_UNCONFIRMED_DATA_DOWN:
            case constants.MTYPE_CONFIRMED_DATA_UP:
            case constants.MTYPE_CONFIRMED_DATA_DOWN:
                return true;
            default:
                return false;
        }
    };

    //    this.isJoinMessage = function () {
    //        return that.isJoinRequestMessage() || that.isJoinAcceptMessage();
    //    };
    this.isJoinRequestMessage = function() {
        return (that._getMType() == constants.MTYPE_JOIN_REQUEST);
    };
    this.isJoinAcceptMessage = function() {
        return (that._getMType() == constants.MTYPE_JOIN_ACCEPT);
    };

    this._fromWire = function(contents) {
        if (contents instanceof Buffer) {
            _initialiseFromWireformat(contents);

        }
        // TODO also allow initialisation from byte array
        else {
            that._packet = null;
        }
    };

    // parse incoming packet
    function _initialiseFromWireformat(contents) {
        that._packet = {};
        var p = that._packet;

        // duplicate buffer to guard against modification
        var incoming = new Buffer(contents);

        p.PHYPayload = incoming;

        p.MHDR = incoming.slice(0, 1);

        //        var type = p.MHDR._getMType;
        if (that.isJoinRequestMessage()) {
            // NB little-endian buffers!
            p.MACPayload = incoming.slice(1, incoming.length - 4);
            p.MACPayloadWithMIC = incoming.slice(1, incoming.length);
            p.AppEUI = util.reverse(incoming.slice(1, 1 + 8));
            p.DevEUI = util.reverse(incoming.slice(9, 9 + 8));
            p.DevNonce = util.reverse(incoming.slice(17, 17 + 2));
            p.MIC = incoming.slice(incoming.length - 4);
        } else if (that.isJoinAcceptMessage()) {
            p.MACPayload = incoming.slice(1, incoming.length - 4);
            p.MACPayloadWithMIC = incoming.slice(1, incoming.length);
            p.AppNonce = util.reverse(incoming.slice(1, 1 + 3));
            p.NetID = util.reverse(incoming.slice(4, 4 + 3));
            p.DevAddr = util.reverse(incoming.slice(7, 7 + 4));
            p.DLSettings = incoming.slice(11, 11 + 1);
            p.RxDelay = incoming.slice(12, 12 + 1);
            if (incoming.length == 13+16+4) {
                p.CFList = incoming.slice(13, 13+16)
            } else {
                p.CFList = new Buffer(0);
            }
            p.MIC = incoming.slice(incoming.length - 4);
        } else if (that.isDataMessage()) {
            p.MACPayload = incoming.slice(1, incoming.length - 4);
            p.MACPayloadWithMIC = incoming.slice(1, incoming.length);
            p.MIC = incoming.slice(incoming.length - 4);

            p.FCtrl = p.MACPayload.slice(4, 5);
            var FCtrl = p.FCtrl.readInt8(0);
            var FOptsLen = FCtrl & 0x0f;
            p.FOpts = p.MACPayload.slice(7, 7 + FOptsLen);
            var FHDR_length = 7 + FOptsLen;
            p.FHDR = p.MACPayload.slice(0, 0 + FHDR_length); // TODO silence linter
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

    this._fromFields = function(userFields) {
        if (_isPlausible(userFields)) {
            _initialiseFromFields(userFields);
        } else {
            that._packet = null;
        }
    };


    function _isPlausibleDataPacket(userFields) {
        if (
            util.isDefined(userFields.DevAddr) && util.isDefined(userFields.payload)
        ) {
            return true;
        } else {
            return false;
        }
    }

    function _isPlausibleJoinRequestPacket(userFields) {
        if (
            util.isDefined(userFields.AppEUI) && util.isDefined(userFields.DevEUI) && util.isDefined(userFields.DevNonce)
        ) {
            return true;
        } else {
            return false;
        }
    }

    function _isPlausibleJoinAcceptPacket(userFields) {
        if (
            util.isDefined(userFields.AppNonce) && util.isDefined(userFields.NetID) && util.isDefined(userFields.DevAddr)
        ) {
            return true;
        } else {
            return false;
        }
    }

    function _isPlausible(userFields) {
        if (!util.isDefined(userFields)) {
            return false;
        } else if (_isPlausibleDataPacket(userFields) === true) {
            return true
        } else if (_isPlausibleJoinRequestPacket(userFields) === true) {
            return true
        } else if (_isPlausibleJoinAcceptPacket(userFields) === true) {
            return true
        } else {
            // not enough to construct packet
            return false;
        }
    }

    function _initialiseDataPacketFromFields(userFields) {
        var p = {}; // temp packet we use during construction
        that._packet = null;

        // required fields
        if (util.isBufferLength(userFields.DevAddr, 4)) {
            p.DevAddr = new Buffer(userFields.DevAddr);
        } else {
            throw new Error("DevAddr is required in a suitable format");
        }

        // required fields
        if (util.isDefined(userFields.payload)) {
            if (util.isString(userFields.payload)) {
                // construct from string
                p.FRMPayload = new Buffer(userFields.payload);
            } else if (util.isBuffer(userFields.payload)) {
                // construct from buffer
                p.FRMPayload = new Buffer(userFields.payload);
            } else if (userFields.payload instanceof Uint8Array) {
                // TODO: construct from Uint8Array
                p.FRMPayload = new Buffer("TODO");
            } else {
                throw new Error("Payload is required in a suitable format");
            }
        } else {
            throw new Error("Payload is required (but may be empty)");
        }


        if (util.isDefined(userFields.MType)) {
            if (util.isNumber(userFields.MType)) {
                p.MHDR = new Buffer(1);
                p.MHDR.writeUInt8(userFields.MType << 5, 0);
            } else if (util.isString(userFields.MType)) {
                var mhdr_idx = constants.MTYPE_DESCRIPTIONS.indexOf(userFields.MType);
                if (mhdr_idx >= 0) {
                    p.MHDR = new Buffer(1);
                    p.MHDR.writeUInt8(mhdr_idx << 5, 0);
                } else {
                    throw new Error("MType is unknown");
                }
            } else {
                throw new Error("MType is required in a suitable format");
            }
        }

        if (util.isDefined(userFields.FCnt)) {
            if (util.isBufferLength(userFields.FCnt, 2)) {
                p.FCnt = new Buffer(userFields.FCnt);
            } else if (util.isNumber(userFields.FCnt)) {
                p.FCnt = new Buffer(2);
                p.FCnt.writeUInt16BE(userFields.FCnt, 0); // NB bigendian
            } else {
                throw new Error("FCnt is required in a suitable format");
            }
        }


        if (util.isDefined(userFields.FOpts)) {
            if (util.isString(userFields.FOpts)) {
                p.FOpts = new Buffer(userFields.FOpts, 'hex');
            } else if (util.isBuffer(userFields.FOpts)) {
                p.FOpts = new Buffer(userFields.FOpts);
            } else {
                throw new Error("FOpts is required in a suitable format");
            }
            if (15 < p.FOpts.length) {
                throw new Error("Too many options for piggybacking");
            }
        } else {
            p.FOpts = new Buffer('', 'hex');
        }

        var fctrl = 0;
        if (util.isDefined(userFields.FCtrl)) {
            if (userFields.FCtrl.ADR) {
                fctrl |= constants.FCTRL_ADR;
            }
            if (userFields.FCtrl.ADRACKReq) {
                fctrl |= constants.FCTRL_ADRACKREQ;
            }
            if (userFields.FCtrl.ACK) {
                fctrl |= constants.FCTRL_ACK;
            }
            if (userFields.FCtrl.FPending) {
                fctrl |= constants.FCTRL_FPENDING;
            }
        }
        fctrl |= (p.FOpts.length & 0x0f);
        p.FCtrl = new Buffer(1);
        p.FCtrl.writeUInt8(fctrl, 0);

        if (util.isDefined(userFields.FPort)) {
            if (util.isNumber(userFields.FPort)) {
                p.FPort = new Buffer(1);
                p.FPort.writeUInt8(userFields.FPort, 0);
            } else {
                throw new Error("FPort required in a suitable format");
            }
        }

        // defaults
        if (!util.isDefined(p.MHDR)) {
            p.MHDR = new Buffer(1);
            p.MHDR.writeUInt8(constants.MTYPE_UNCONFIRMED_DATA_UP << 5, 0);
        }

        if (!util.isDefined(p.FPort)) {
            if (p.FRMPayload.length > 0) {
                // create FPort only if payload exists
                p.FPort = new Buffer('01', 'hex');
            } else {
                p.FPort = new Buffer(0);    // empty buffer
            }
        }
        if (!util.isDefined(p.FPort)) {
            p.FPort = new Buffer('01', 'hex');
        }
        if (!util.isDefined(p.FCnt)) {
            p.FCnt = new Buffer('0001', 'hex');
        }

        // this MIC is bogus for now, but correct length
        if (!util.isDefined(p.MIC)) {
            p.MIC = new Buffer('EEEEEEEE', 'hex');
        }

        that._packet = p;
        that.mergeGroupFields();
    }

    function _initialiseJoinRequestPacketFromFields(userFields) {
        var p = {}; // temp packet we use during construction
        that._packet = null;

        // required fields
        if (util.isBufferLength(userFields.AppEUI, 8)) {
            p.AppEUI = new Buffer(userFields.AppEUI);
        } else {
            throw new Error("AppEUI is required in a suitable format");
        }

        // required fields
        if (util.isBufferLength(userFields.DevEUI, 8)) {
            p.DevEUI = new Buffer(userFields.DevEUI);
        } else {
            throw new Error("DevEUI is required in a suitable format");
        }

        // required fields
        if (util.isBufferLength(userFields.DevNonce, 2)) {
            p.DevNonce = new Buffer(userFields.DevNonce);
        } else {
            throw new Error("DevNonce is required in a suitable format");
        }


        if (util.isDefined(userFields.FCnt)) {
            if (util.isBufferLength(userFields.FCnt, 2)) {
                p.FCnt = new Buffer(userFields.FCnt);
            } else if (util.isNumber(userFields.FCnt)) {
                p.FCnt = new Buffer(2);
                p.FCnt.writeUInt16BE(userFields.FCnt, 0); // NB bigendian
            } else {
                throw new Error("FCnt is required in a suitable format");
            }
        }
        p.MHDR = new Buffer(1);
        p.MHDR.writeUInt8(constants.MTYPE_JOIN_REQUEST << 5, 0);


        // this MIC is bogus for now, but correct length
        if (!util.isDefined(p.MIC)) {
            p.MIC = new Buffer('EEEEEEEE', 'hex');
        }

        that._packet = p;
        that.mergeGroupFields();
    }

    function _initialiseJoinAcceptPacketFromFields(userFields) {
        var p = {}; // temp packet we use during construction
        that._packet = null;

        // required fields
        if (util.isBufferLength(userFields.AppNonce, 3)) {
            p.AppNonce = new Buffer(userFields.AppNonce);
        } else {
            throw new Error("AppNonce is required in a suitable format");
        }

        // required fields
        if (util.isBufferLength(userFields.NetID, 3)) {
            p.NetID = new Buffer(userFields.NetID);
        } else {
            throw new Error("NetID is required in a suitable format");
        }

        // required fields
        if (util.isBufferLength(userFields.DevAddr, 4)) {
            p.DevAddr = new Buffer(userFields.DevAddr);
        } else {
            throw new Error("DevAddr is required in a suitable format");
        }


        if (util.isDefined(userFields.DLSettings)) {
            if (util.isBufferLength(userFields.DLSettings, 1)) {
                p.DLSettings = new Buffer(userFields.DLSettings);
            } else if (util.isNumber(userFields.DLSettings)) {
                p.DLSettings = new Buffer(1);
                p.DLSettings.writeUInt8(userFields.DLSettings, 0);
            } else {
                throw new Error("DLSettings is required in a suitable format");
            }
        }

        if (util.isDefined(userFields.RxDelay)) {
            if (util.isBufferLength(userFields.RxDelay, 1)) {
                p.RxDelay = new Buffer(userFields.RxDelay);
            } else if (util.isNumber(userFields.RxDelay)) {
                p.RxDelay = new Buffer(1);
                p.RxDelay.writeUInt8(userFields.RxDelay, 0);
            } else {
                throw new Error("RxDelay is required in a suitable format");
            }
        }

        if (util.isDefined(userFields.CFList)) {
            if (util.isBufferLength(userFields.CFList, 0) || util.isBufferLength(userFields.CFList, 16)) {
                p.CFList = new Buffer(userFields.CFList);
            } else {
                throw new Error("CFList is required in a suitable format");
            }
        }


        if (!util.isDefined(p.DLSettings)) {
            p.DLSettings = new Buffer('00', 'hex');
        }
        if (!util.isDefined(p.RxDelay)) {
            p.RxDelay = new Buffer('00', 'hex');
        }
        if (!util.isDefined(p.CFList)) {
            p.CFList = new Buffer('', 'hex');
        }
        p.MHDR = new Buffer(1);
        p.MHDR.writeUInt8(constants.MTYPE_JOIN_ACCEPT << 5, 0);


        // this MIC is bogus for now, but correct length
        if (!util.isDefined(p.MIC)) {
            p.MIC = new Buffer('EEEEEEEE', 'hex');
        }

        that._packet = p;
        that.mergeGroupFields();
    }

    // populate anew from whatever the client gives us
    //  with defaults for the rest
    function _initialiseFromFields(userFields) {
        if (util.isDefined(userFields.MType)) {
            var MTypeNo;
            if (util.isNumber(userFields.MType)) {
                MTypeNo = userFields.MType;
            } else if (util.isString(userFields.MType)) {
                var mhdr_idx = constants.MTYPE_DESCRIPTIONS.indexOf(userFields.MType);
                if (mhdr_idx >= 0) {
                    MTypeNo = mhdr_idx;
                } else {
                    throw new Error("MType is unknown");
                }
            } else {
                throw new Error("MType is required in a suitable format");
            }

            if(MTypeNo == constants.MTYPE_JOIN_REQUEST) {
                _initialiseJoinRequestPacketFromFields(userFields);
            } else if(MTypeNo == constants.MTYPE_JOIN_ACCEPT) {
                _initialiseJoinAcceptPacketFromFields(userFields);
            } else {
                _initialiseDataPacketFromFields(userFields);
            }
        } else {
            if (_isPlausibleDataPacket(userFields) === true) {
                _initialiseDataPacketFromFields(userFields);
            } else if (_isPlausibleJoinRequestPacket(userFields) === true) {
                _initialiseJoinRequestPacketFromFields(userFields);
            } else if (_isPlausibleJoinAcceptPacket(userFields) === true) {
                _initialiseJoinAcceptPacketFromFields(userFields);
            } else {
                throw new Error("No plausible packet");
            }
        }
    }

    // packet creation (or re-creation)
    // - merge individual fields to create the higher-level ones
    //  (e.g PHYPayload = MHDR | MACPayload  | MIC)
    // BUT note that DevAddr & FCnt are stored big-endian
    this.mergeGroupFields = function() {
        var p = that._packet;
        if(that.isJoinRequestMessage()) {
            p.MACPayload = Buffer.concat([util.reverse(p.AppEUI), util.reverse(p.DevEUI), util.reverse(p.DevNonce)]);
            p.PHYPayload = Buffer.concat([p.MHDR, p.MACPayload, p.MIC]);
            p.MACPayloadWithMIC = p.PHYPayload.slice(p.MHDR.length, p.PHYPayload.length);
        } else if(that.isJoinAcceptMessage()) {
            p.MACPayload = Buffer.concat([util.reverse(p.AppNonce), util.reverse(p.NetID), util.reverse(p.DevAddr), p.DLSettings, p.RxDelay, p.CFList]);
            p.PHYPayload = Buffer.concat([p.MHDR, p.MACPayload, p.MIC]);
            p.MACPayloadWithMIC = p.PHYPayload.slice(p.MHDR.length, p.PHYPayload.length);
        } else {
            p.FHDR = Buffer.concat([util.reverse(p.DevAddr), p.FCtrl, util.reverse(p.FCnt), p.FOpts]);
            p.MACPayload = Buffer.concat([p.FHDR, p.FPort, p.FRMPayload]);
            p.PHYPayload = Buffer.concat([p.MHDR, p.MACPayload, p.MIC]);
            p.MACPayloadWithMIC = p.PHYPayload.slice(p.MHDR.length, p.PHYPayload.length);
        }
    };

    // provide MType as a string
    this.getMType = function() {
        return constants.MTYPE_DESCRIPTIONS[that._getMType()];
    };

    // provide Direction as a string
    this.getDir = function() {
        return constants.MTYPE_DIRECTIONS[that._getMType()];
    };

    // provide FPort as a number
    this.getFPort = function() {
        if (that._packet.FPort && that._packet.FPort.length) {
            return that._packet.FPort.readUInt8(0);
        } else {
            return null;
        }
    };

    // provide FCnt as a number
    this.getFCnt = function() {
        if (that._packet.FCnt) {
            return that._packet.FCnt.readUInt16BE(0);
        } else {
            return null;
        }
    };

    // provide FCtrl.ACK as a flag
    this.getFCtrlACK = function() {
        return !!(that._packet.FCtrl.readUInt8(0) & constants.FCTRL_ACK);
    };

    // provide FCtrl.ADR as a flag
    this.getFCtrlADR = function() {
        return !!(that._packet.FCtrl.readUInt8(0) & constants.FCTRL_ADR);
    };

    // provide FCtrl.ADRACKReq as a flag
    this.getFCtrlADRACKReq = function() {
        return !!(that._packet.FCtrl.readUInt8(0) & constants.FCTRL_ADRACKREQ);
    };

    // provide FCtrl.FPending as a flag
    this.getFCtrlFPending = function() {
        return !!(that._packet.FCtrl.readUInt8(0) & constants.FCTRL_FPENDING);
    };

    // provide DLSettings.RX1DRoffset as integer
    this.getDLSettingsRxOneDRoffset = function() {
        return (that._packet.DLSettings.readUInt8(0) & constants.DLSETTINGS_RXONEDROFFSET_MASK) >> constants.DLSETTINGS_RXONEDROFFSET_POS;
    };

    // provide DLSettings.RX2DataRate as integer
    this.getDLSettingsRxTwoDataRate = function() {
        return (that._packet.DLSettings.readUInt8(0) & constants.DLSETTINGS_RXTWODATARATE_MASK) >> constants.DLSETTINGS_RXTWODATARATE_MASK;
    };

    // provide RxDelay.Del as integer
    this.getRxDelayDel = function() {
        return (that._packet.RxDelay.readUInt8(0) & constants.RXDELAY_DEL_MASK) >> constants.RXDELAY_DEL_POS;
    };

    // provide CFList.FreqChFour as buffer
    this.getCFListFreqChFour = function() {
        if(that._packet.CFList.length === 16) {
            return that._packet.CFList.slice(0, 0 + 3);
        } else {
            return new Buffer(0);
        }
    };

    // provide CFList.FreqChFive as buffer
    this.getCFListFreqChFive = function() {
        if(that._packet.CFList.length === 16) {
            return that._packet.CFList.slice(3, 3 + 3);
        } else {
            return new Buffer(0);
        }
    };

    // provide CFList.FreqChSix as buffer
    this.getCFListFreqChSix = function() {
        if(that._packet.CFList.length === 16) {
            return that._packet.CFList.slice(6, 6 + 3);
        } else {
            return new Buffer(0);
        }
    };

    // provide CFList.FreqChSeven as buffer
    this.getCFListFreqChSeven = function() {
        if(that._packet.CFList.length === 16) {
            return that._packet.CFList.slice(9, 9 + 3);
        } else {
            return new Buffer(0);
        }
    };

    // provide CFList.FreqChEight as buffer
    this.getCFListFreqChEight = function() {
        if(that._packet.CFList.length === 16) {
            return that._packet.CFList.slice(12, 12 + 3);
        } else {
            return new Buffer(0);
        }
    };

    this.getPHYPayload = function() {
        return that._packet.PHYPayload;
    };

    this.getBuffers = function() {
        return that._packet;
    };

    /*    this.setPlaintextPayload = function(payload) {
     that._plaintextPayload = payload;
     };*/

    /*    this.getPlaintextPayload = function() {
     return that._plaintextPayload;
     };*/


    this.toString = function() {
        var p = that._packet;

        var msg = "";

        if (that.isJoinRequestMessage()) {
            msg += "          Message Type = Join Request" + "\n";
            msg += "            PHYPayload = " + asHexString(p.PHYPayload).toUpperCase() + "\n";
            msg += "\n";
            msg += "          ( PHYPayload = MHDR[1] | MACPayload[..] | MIC[4] )\n";
            msg += "                  MHDR = " + asHexString(p.MHDR) + "\n";
            msg += "            MACPayload = " + asHexString(p.MACPayload) + "\n";
            msg += "                   MIC = " + asHexString(p.MIC) + "\n";
            msg += "\n";
            msg += "          ( MACPayload = AppEUI[8] | DevEUI[8] | DevNonce[2] )\n";
            msg += "                AppEUI = " + asHexString(p.AppEUI) + "\n";
            msg += "                DevEUI = " + asHexString(p.DevEUI) + "\n";
            msg += "              DevNonce = " + asHexString(p.DevNonce) + "\n";
        } else if (that.isJoinAcceptMessage()) {
            msg += "          Message Type = Join Accept" + "\n";
            msg += "            PHYPayload = " + asHexString(p.PHYPayload).toUpperCase() + "\n";
            msg += "\n";
            msg += "          ( PHYPayload = MHDR[1] | MACPayload[..] | MIC[4] )\n";
            msg += "                  MHDR = " + asHexString(p.MHDR) + "\n";
            msg += "            MACPayload = " + asHexString(p.MACPayload) + "\n";
            msg += "                   MIC = " + asHexString(p.MIC) + "\n";
            msg += "\n";
            msg += "          ( MACPayload = AppNonce[3] | NetID[3] | DevAddr[4] | DLSettings[1] | RxDelay[1] | CFList[0|15] )\n";
            msg += "              AppNonce = " + asHexString(p.AppNonce) + "\n";
            msg += "                 NetID = " + asHexString(p.NetID) + "\n";
            msg += "               DevAddr = " + asHexString(p.DevAddr) + "\n";
            msg += "            DLSettings = " + asHexString(p.DLSettings) + "\n";
            msg += "               RxDelay = " + asHexString(p.RxDelay) + "\n";
            msg += "                CFList = " + asHexString(p.CFList) + "\n";
            msg += "\n";
            msg += "DLSettings.RX1DRoffset = " + that.getDLSettingsRxOneDRoffset() + "\n";
            msg += "DLSettings.RX2DataRate = " + that.getDLSettingsRxTwoDataRate() + "\n";
            msg += "           RxDelay.Del = " + that.getRxDelayDel() + "\n";
            msg += "\n";
            if(p.CFList.length === 15) {
                msg += "              ( CFList = FreqCh4[3] | FreqCh5[3] | FreqCh6[3] | FreqCh7[3] | FreqCh8[3] )\n";
                msg += "               FreqCh4 = " + asHexString(that.getCFListFreqChFour) + "\n";
                msg += "               FreqCh5 = " + asHexString(that.getCFListFreqChFive) + "\n";
                msg += "               FreqCh6 = " + asHexString(that.getCFListFreqChSix) + "\n";
                msg += "               FreqCh7 = " + asHexString(that.getCFListFreqChSeven) + "\n";
                msg += "               FreqCh8 = " + asHexString(that.getCFListFreqChEight) + "\n";
            }
        } else if (that.isDataMessage()) {
            msg += "Message Type = Data" + "\n";
            msg += "            PHYPayload = " + asHexString(p.PHYPayload).toUpperCase() + "\n";
            msg += "\n";
            msg += "          ( PHYPayload = MHDR[1] | MACPayload[..] | MIC[4] )\n";
            msg += "                  MHDR = " + asHexString(p.MHDR) + "\n";
            msg += "            MACPayload = " + asHexString(p.MACPayload) + "\n";
            msg += "                   MIC = " + asHexString(p.MIC) + "\n";
            msg += "\n";
            msg += "          ( MACPayload = FHDR | FPort | FRMPayload )\n";
            msg += "                  FHDR = " + asHexString(p.FHDR) + "\n";
            msg += "                 FPort = " + asHexString(p.FPort) + "\n";
            msg += "            FRMPayload = " + asHexString(p.FRMPayload) + "\n";
            msg += "\n";
            msg += "                ( FHDR = DevAddr[4] | FCtrl[1] | FCnt[2] | FOpts[0..15] )\n";
            msg += "               DevAddr = " + asHexString(p.DevAddr) + " (Big Endian)\n";
            msg += "                 FCtrl = " + asHexString(p.FCtrl) + "\n"; //TODO as binary?
            msg += "                  FCnt = " + asHexString(p.FCnt) + " (Big Endian)\n";
            msg += "                 FOpts = " + asHexString(p.FOpts) + "\n";
            msg += "\n";
            msg += "          Message Type = " + that.getMType() + "\n";
            msg += "             Direction = " + that.getDir() + "\n";
            msg += "                  FCnt = " + that.getFCnt() + "\n";
            msg += "             FCtrl.ACK = " + that.getFCtrlACK() + "\n";
            msg += "             FCtrl.ADR = " + that.getFCtrlADR() + "\n";
        }
        return msg;
    };
}

function asHexString(buf) {
    return buf.toString('hex').toUpperCase();
}

