'use strict';

var lora_packet = require('..');
var expect = require("chai").expect;
var assert = require('chai').assert;

module.exports = function () {

    // TODO more variation on this

    describe('MIC checks', function () {

        it('should calculate & verify correct data packet MIC', function () {
            var message_hex = "40F17DBE4900020001954378762B11FF0D";
            var packet = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            var NwkSKey_hex = "44024241ed4ce9a68c6a8bc055233fd3";
            var calculatedMIC = lora_packet.calculateMIC(packet, new Buffer(NwkSKey_hex, 'hex'));
            expect(calculatedMIC.toString('hex')).to.equal('2b11ff0d');

            expect(lora_packet.verifyMIC(packet, new Buffer(NwkSKey_hex, 'hex'))).to.equal(true);
        });

        it('should calculate & verify correct data packet MIC', function () {
            var message_hex = "40F17DBE49000300012A3518AF";
            var packet = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            var NwkSKey_hex = "44024241ed4ce9a68c6a8bc055233fd3";
            var calculatedMIC = lora_packet.calculateMIC(packet, new Buffer(NwkSKey_hex, 'hex'));
            expect(calculatedMIC.toString('hex')).to.equal('2a3518af');

            expect(lora_packet.verifyMIC(packet, new Buffer(NwkSKey_hex, 'hex'))).to.equal(true);
        });

        it('should detect incorrect data packet MIC', function () {
            // bodged MIC so it's different
            var message_hex = "40F17DBE49000300012A3518AA"; // aa not af
            var packet = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            var NwkSKey_hex = "44024241ed4ce9a68c6a8bc055233fd3";
            var calculatedMIC = lora_packet.calculateMIC(packet, new Buffer(NwkSKey_hex, 'hex'));
            expect(calculatedMIC.toString('hex')).to.equal('2a3518af');

            expect(lora_packet.verifyMIC(packet, new Buffer(NwkSKey_hex, 'hex'))).to.equal(false);
        });

        it('should calculate & verify correct data packet MIC for ACK', function () {
            var message_hex = "60f17dbe4920020001f9d65d27";
            var packet = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            var NwkSKey_hex = "44024241ed4ce9a68c6a8bc055233fd3";
            var calculatedMIC = lora_packet.calculateMIC(packet, new Buffer(NwkSKey_hex, 'hex'));
            expect(calculatedMIC.toString('hex')).to.equal('f9d65d27');

            expect(lora_packet.verifyMIC(packet, new Buffer(NwkSKey_hex, 'hex'))).to.equal(true);
        });

        it('recalculateMIC should calculate & overwrite existing data packet MIC', function () {
            var message_hex = "60f17dbe4920020001f9d65d27";
            var packet = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            // overwrite
            packet.getBuffers().MIC = new Buffer('EEEEEEEE', 'hex');
            expect(packet.getBuffers().MIC).to.deep.equal(new Buffer('EEEEEEEE', 'hex'));

            // expect failure
            var NwkSKey = new Buffer("44024241ed4ce9a68c6a8bc055233fd3", 'hex');
            expect(lora_packet.verifyMIC(packet, NwkSKey)).to.equal(false);

            // calculate again
            lora_packet.recalculateMIC(packet, NwkSKey);
            expect(lora_packet.verifyMIC(packet, NwkSKey)).to.equal(true);
            expect(packet.getBuffers().MIC).to.deep.equal(new Buffer('f9d65d27', 'hex'));
        });

        it('should calculate & verify correct join request packet MIC', function () {
            var message_hex = "0039363463336913AA05693574323831330489C65B1304";
            var packet = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            var AppKey_hex = "98929b92c49edba9676d646d3b612456";
            var calculatedMIC = lora_packet.calculateMIC(packet, null, new Buffer(AppKey_hex, 'hex'));
            expect(calculatedMIC.toString('hex')).to.equal('c65b1304');

            expect(lora_packet.verifyMIC(packet, null, new Buffer(AppKey_hex, 'hex'))).to.equal(true);
        });

        it('should detect incorrect join request packet MIC', function () {
            // bodged MIC so it's different
            var message_hex = "0039363463336913AA05693574323831330489C65B1305"; // 05 not 04
            var packet = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            var AppKey_hex = "98929b92c49edba9676d646d3b612456";
            var calculatedMIC = lora_packet.calculateMIC(packet, null, new Buffer(AppKey_hex, 'hex'));
            expect(calculatedMIC.toString('hex')).to.equal('c65b1304');

            expect(lora_packet.verifyMIC(packet, null, new Buffer(AppKey_hex, 'hex'))).to.equal(false);
        });

        it('should calculate & verify correct join accept packet MIC', function () {
            var message_hex = "20386337CCBBAAE7CD2C010000D9D0A6E7"; // not encrypted
            var packet = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            var AppKey_hex = "98929b92c49edba9676d646d3b612456";
            var calculatedMIC = lora_packet.calculateMIC(packet, null, new Buffer(AppKey_hex, 'hex'));
            expect(calculatedMIC.toString('hex')).to.equal('d9d0a6e7');

            expect(lora_packet.verifyMIC(packet, null, new Buffer(AppKey_hex, 'hex'))).to.equal(true);
        });

        it('should detect incorrect join accept packet MIC', function () {
            // bodged MIC so it's different
            var message_hex = "20386337CCBBAAE7CD2C010000D9D0A6E8"; // E8 not E7, not encrypted
            var packet = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            var AppKey_hex = "98929b92c49edba9676d646d3b612456";
            var calculatedMIC = lora_packet.calculateMIC(packet, null, new Buffer(AppKey_hex, 'hex'));
            expect(calculatedMIC.toString('hex')).to.equal('d9d0a6e7');

            expect(lora_packet.verifyMIC(packet, null, new Buffer(AppKey_hex, 'hex'))).to.equal(false);
        });

        it('should calculate & verify MIC when 32-bit FCnts are used', function () {
            var message_hex = "40F17DBE4900020001954378762B11FF0D";
            var packet = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            var NwkSKey_hex = "44024241ed4ce9a68c6a8bc055233fd3";
            var calculatedMIC = lora_packet.calculateMIC(packet, new Buffer(NwkSKey_hex, 'hex'), null, new Buffer('0000', 'hex'));
            expect(calculatedMIC.toString('hex')).to.equal('2b11ff0d');

            expect(lora_packet.verifyMIC(packet, new Buffer(NwkSKey_hex, 'hex'), null, new Buffer('0000', 'hex'))).to.equal(true);
        });



    });
};

