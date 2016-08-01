'use strict';

var lora_packet = require('..');
var expect = require("chai").expect;
var assert = require('chai').assert;

module.exports = function () {

    // TODO more variation on this

    describe('decrypt example packet', function () {

        it('should decrypt test payload', function () {
            var message_hex = "40F17DBE4900020001954378762B11FF0D";
            var packet = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            var AppSKey_hex = "ec925802ae430ca77fd3dd73cb2cc588";
            var decrypted = lora_packet.decrypt(packet, new Buffer(AppSKey_hex, 'hex'), undefined);
            expect(decrypted).to.not.be.undefined;
            expect(decrypted.toString()).to.equal('test');
        });
        it('should decrypt large payload', function () {
            var message_hex = "40f17dbe490004000155332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a20af3c5e7";
            var packet = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            var AppSKey_hex = "ec925802ae430ca77fd3dd73cb2cc588";
            var decrypted = lora_packet.decrypt(packet, new Buffer(AppSKey_hex, 'hex'), undefined);
            expect(decrypted).to.not.be.undefined;
            expect(decrypted.toString()).to.equal('The quick brown fox jumps over the lazy dog.');
        });

        it('bad key scrambles payload', function () {
            var message_hex = "40F17DBE4900020001954378762B11FF0D";
            var packet = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            var AppSKey_hex = "ec925802ae430ca77fd3dd73cb2cc580";
            var decrypted = lora_packet.decrypt(packet, new Buffer(AppSKey_hex, 'hex'), undefined);
            expect(decrypted).to.not.be.undefined;
            expect(decrypted.toString('hex')).to.equal('5999fc3f');
        });


        it('bad data lightly scrambles payload', function () {
            var message_hex = "40F17DBE4900020001954478762B11FF0D";
            var packet = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            var AppSKey_hex = "ec925802ae430ca77fd3dd73cb2cc588";
            var decrypted = lora_packet.decrypt(packet, new Buffer(AppSKey_hex, 'hex'), undefined);
            expect(decrypted).to.not.be.undefined;
            expect(decrypted.toString()).to.equal('tbst');
        });

    });
};

