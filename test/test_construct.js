'use strict';

var lora_packet = require('..');
var expect = require("chai").expect;
var assert = require('chai').assert;

module.exports = function () {

    // TODO more variation on this

    describe('construct packet from fields', function () {
        it('should handle undefined input', function () {
            var packet = lora_packet.fromFields(undefined);
            expect (packet).to.be.null;
        });
        it('should handle null input', function () {
            var packet = lora_packet.fromFields(null);
            expect (packet).to.be.null;
        });
        it('should handle buffer input', function () {
            var packet = lora_packet.fromFields(new Buffer("1234"));
            expect (packet).to.be.null;
        });
        it('should handle string input', function () {
            var packet = lora_packet.fromFields(new Buffer("1234"));
            expect (packet).to.be.null;
        });
        it('should handle empty object input', function () {
            var packet = lora_packet.fromFields({wot:'foo'});
            expect (packet).to.be.null;
        });

        it('should create packet with minimal input', function () {
            var packet = lora_packet.fromFields(
                {
                    payload:'test',
                    DevAddr: new Buffer('a1b2c3d4', 'hex')
                });
            var expected_pktBufs = {
                PHYPayload: new Buffer('40d4c3b2a10001000174657374eeeeeeee', 'hex'),
                MHDR: new Buffer('40', 'hex'),
                MACPayload: new Buffer('d4c3b2a10001000174657374', 'hex'),
                MIC: new Buffer('EEEEEEEE', 'hex'),
                FOpts: new Buffer(0),
                FCtrl: new Buffer('00', 'hex'),
                FHDR: new Buffer('d4c3b2a1000100', 'hex'),
                DevAddr: new Buffer('a1b2c3d4', 'hex'),
                FCnt: new Buffer('0001', 'hex'),
                FPort: new Buffer('01', 'hex'),
                FRMPayload: new Buffer('test')
            };
            expect (packet).not.to.be.null;
            expect(packet.getBuffers()).to.not.be.undefined;
            expect(packet.getBuffers()).to.deep.equal(expected_pktBufs);
        });


        it('should calculate MIC if NwkSKey provided', function () {
            var packet = lora_packet.fromFields(
                {
                    payload: new Buffer('95437876', 'hex'),
                    DevAddr: new Buffer('49be7df1', 'hex'),
                    FCnt: new Buffer('0002', 'hex')
                }
                , null  // AppSKey
                , new Buffer("44024241ed4ce9a68c6a8bc055233fd3", 'hex')
            );
            var expected_pktBufs = {
                PHYPayload: new Buffer('40f17dbe4900020001954378762b11ff0d', 'hex'),
                MHDR: new Buffer('40', 'hex'),
                MACPayload: new Buffer('f17dbe490002000195437876', 'hex'),
                MIC: new Buffer('2b11ff0d', 'hex'),
                FOpts: new Buffer(0),
                FCtrl: new Buffer('00', 'hex'),
                FHDR: new Buffer('f17dbe49000200', 'hex'),
                DevAddr: new Buffer('49be7df1', 'hex'),
                FCnt: new Buffer('0002', 'hex'),
                FPort: new Buffer('01', 'hex'),
                FRMPayload: new Buffer('95437876', 'hex')
            };
            expect(packet).not.to.be.null;
            expect(packet.getBuffers()).to.not.be.undefined;
            expect(packet.getBuffers()).to.deep.equal(expected_pktBufs);
        });
    });
};

