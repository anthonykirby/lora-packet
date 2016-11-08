'use strict';

// utility functions for lora-packet

module.exports = LoraPacketUtil;

function LoraPacketUtil(context) {
    if (!(this instanceof LoraPacketUtil)) return new LoraPacketUtil(context);
    var that = this;

    // we can't enforce this so supply a fallback
    if (!context) {
        context = "<missing context>";
    }

    // context use for error header
    that.errHdr = "Error (" + context + "): ";


    // Buffer.compare only added in node.js v0.11.13
    this.areBuffersEqual = function(bufA, bufB) {
        var len = bufA.length;
        if (len !== bufB.length) {
            return false;
        }
        for (var i = 0; i < len; i++) {
            if (bufA.readUInt8(i) !== bufB.readUInt8(i)) {
                return false;
            }
        }
        return true;
    };

    this.isDefined = function(x) {
        return (typeof x !== 'undefined' && x !== null);
    };
    this.isBuffer = function(x) {
        return that.isDefined(x) && (x instanceof Buffer);
    };
    this.isString = function(x) {
        return that.isDefined(x) && (typeof x === 'string' || x instanceof String);
    };
    this.isNumber = function(x) {
        return that.isDefined(x) && (typeof x == "number" && !isNaN(x));
    };
    this.isBufferLength = function(x, expectedLength) {
        return that.isBuffer(x) && (x.length == expectedLength);
    };

    this.checkDefined = function(x, name) {
        if (!that.isDefined(x)) {
            throw new Error(that.errHdr + "expecting " + name + " to be defined");
        }
    };

    this.checkBuffer = function(x, name) {
        if (!that.isBuffer(x)) {
            throw new Error(that.errHdr + "expecting " + name + " to be a Buffer");
        }
    };

    this.checkBufferLength = function(obj, name, length) {
        if (!that.isBufferLength(obj, length)) {
            throw new Error(that.errHdr + "expecting " + name + " to be a Buffer length=" + length);
        }
    };


    this.bufferFromUInt8 = function(value) {
        var buf = new Buffer(1);
        buf.writeUInt8(value, 0);
        return buf;
    };

    this.bufferFromUInt16LE = function(value) {
        var buf = new Buffer(2);
        buf.writeUInt16LE(value, 0);
        return buf;
    };


    this.isValidUtf8 = function(buffer) {
        return that.areBuffersEqual(new Buffer(buffer.toString(), 'utf8'), buffer);
    };

    this.reverse = function(source) {
        var reversed = new Buffer(source.length);

        for (var i = 0, j = source.length - 1; i <= j; ++i, --j) {
            reversed[i] = source[j];
            reversed[j] = source[i];
        }

        return reversed;
    };
}