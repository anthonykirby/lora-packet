'use strict';

var lora_packet = require('..');
var expect = require("chai").expect;
var assert = require('chai').assert;

module.exports = function () {

    // TODO more variation on this

    describe('MIC checks', function () {

        it('should calculate & verify correct MIC', function () {
            var message_hex = "40F17DBE4900020001954378762B11FF0D";
            var packet = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            var NwkSKey_hex = "44024241ed4ce9a68c6a8bc055233fd3";
            var calculatedMIC = lora_packet.calculateMIC(packet, new Buffer(NwkSKey_hex, 'hex'));
            expect(calculatedMIC.toString('hex')).to.equal('2b11ff0d');

            expect(lora_packet.verifyMIC(packet, new Buffer(NwkSKey_hex, 'hex'))).to.equal(true);
        });

        it('should calculate & verify correct MIC', function () {
            var message_hex = "40F17DBE49000300012A3518AF";
            var packet = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            var NwkSKey_hex = "44024241ed4ce9a68c6a8bc055233fd3";
            var calculatedMIC = lora_packet.calculateMIC(packet, new Buffer(NwkSKey_hex, 'hex'));
            expect(calculatedMIC.toString('hex')).to.equal('2a3518af');

            expect(lora_packet.verifyMIC(packet, new Buffer(NwkSKey_hex, 'hex'))).to.equal(true);
        });

        it('should detect incorrect MIC', function () {
            // bodged MIC so it's different
            var message_hex = "40F17DBE49000300012A3518AA"; // aa not af
            var packet = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            var NwkSKey_hex = "44024241ed4ce9a68c6a8bc055233fd3";
            var calculatedMIC = lora_packet.calculateMIC(packet, new Buffer(NwkSKey_hex, 'hex'));
            expect(calculatedMIC.toString('hex')).to.equal('2a3518af');

            expect(lora_packet.verifyMIC(packet, new Buffer(NwkSKey_hex, 'hex'))).to.equal(false);
        });

        it('should calculate & verify correct MIC for ACK', function () {
            var message_hex = "60f17dbe4920020001f9d65d27";
            var packet = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            var NwkSKey_hex = "44024241ed4ce9a68c6a8bc055233fd3";
            var calculatedMIC = lora_packet.calculateMIC(packet, new Buffer(NwkSKey_hex, 'hex'));
            expect(calculatedMIC.toString('hex')).to.equal('f9d65d27');

            expect(lora_packet.verifyMIC(packet, new Buffer(NwkSKey_hex, 'hex'))).to.equal(true);
        });

        it('recalculateMIC should calculate & overwrite existing MIC', function () {
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

    });
};

