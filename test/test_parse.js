'use strict';

var lora_packet = require('..');
var expect = require("chai").expect;
var assert = require('chai').assert;

module.exports = function () {

    // TODO more variation on this

    describe('parse example packet', function () {
        it('should parse packet', function () {
            var message_hex = "40F17DBE4900020001954378762B11FF0D";

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

            var parsed = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            expect(parsed).to.not.be.undefined;
            expect(parsed.getBuffers()).to.not.be.undefined;
            expect(parsed.getBuffers()).to.deep.equal(expected_pktBufs);

            // non-buffer output
            expect(parsed.getMType()).to.equal('Unconfirmed Data Up');
            expect(parsed.getDir()).to.equal('up');
            expect(parsed.getFCnt()).to.equal(2);
            expect(parsed.getFCtrlACK()).to.equal(false);
            expect(parsed.getFCtrlADR()).to.equal(false);
        });



        it('should parse packet with empty payload', function () {
            var message_hex = "40F17DBE49000300012A3518AF";

            var expected_pktBufs = {
                PHYPayload: new Buffer('40f17dbe49000300012a3518af', 'hex'),
                MHDR: new Buffer('40', 'hex'),
                MACPayload: new Buffer('f17dbe4900030001', 'hex'),
                MIC: new Buffer('2a3518af', 'hex'),
                FOpts: new Buffer(0),
                FCtrl: new Buffer('00', 'hex'),
                FHDR: new Buffer('f17dbe49000300', 'hex'),
                DevAddr: new Buffer('49be7df1', 'hex'),
                FCnt: new Buffer('0003', 'hex'),
                FPort: new Buffer('01', 'hex'),
                FRMPayload: new Buffer('', 'hex')
            };

            var parsed = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            expect(parsed).to.not.be.undefined;
            expect(parsed.getBuffers()).to.not.be.undefined;
            expect(parsed.getBuffers()).to.deep.equal(expected_pktBufs);

            // non-buffer output
            expect(parsed.getMType()).to.equal('Unconfirmed Data Up');
            expect(parsed.getDir()).to.equal('up');
            expect(parsed.getFCnt()).to.equal(3);
            expect(parsed.getFCtrlACK()).to.equal(false);
            expect(parsed.getFCtrlADR()).to.equal(false);
        });

        it('should parse large packet', function () {
            var message_hex = "40f17dbe490004000155332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a20af3c5e7";

            var expected_pktBufs = {
                PHYPayload: new Buffer('40f17dbe490004000155332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a20af3c5e7', 'hex'),
                MHDR: new Buffer('40', 'hex'),
                MACPayload: new Buffer('f17dbe490004000155332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a2', 'hex'),
                MIC: new Buffer('0af3c5e7', 'hex'),
                FOpts: new Buffer(0),
                FCtrl: new Buffer('00', 'hex'),
                FHDR: new Buffer('f17dbe49000400', 'hex'),
                DevAddr: new Buffer('49be7df1', 'hex'),
                FCnt: new Buffer('0004', 'hex'),
                FPort: new Buffer('01', 'hex'),
                FRMPayload: new Buffer('55332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a2', 'hex')
            };

            var parsed = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            expect(parsed).to.not.be.undefined;
            expect(parsed.getBuffers()).to.not.be.undefined;
            expect(parsed.getBuffers()).to.deep.equal(expected_pktBufs);

            // non-buffer output
            expect(parsed.getMType()).to.equal('Unconfirmed Data Up');
            expect(parsed.getDir()).to.equal('up');
            expect(parsed.getFCnt()).to.equal(4);
            expect(parsed.getFCtrlACK()).to.equal(false);
            expect(parsed.getFCtrlADR()).to.equal(false);
        });


        it('should parse ack', function () {
            var message_hex = "60f17dbe4920020001f9d65d27";

            var expected_pktBufs = {
                PHYPayload: new Buffer('60f17dbe4920020001f9d65d27', 'hex'),
                MHDR: new Buffer('60', 'hex'),
                MACPayload: new Buffer('f17dbe4920020001', 'hex'),
                MIC: new Buffer('f9d65d27', 'hex'),
                FOpts: new Buffer(0),
                FCtrl: new Buffer('20', 'hex'),
                FHDR: new Buffer('f17dbe49200200', 'hex'),
                DevAddr: new Buffer('49be7df1', 'hex'),
                FCnt: new Buffer('0002', 'hex'),
                FPort: new Buffer('01', 'hex'),
                FRMPayload: new Buffer('', 'hex')
            };

            var parsed = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            expect(parsed).to.not.be.undefined;
            expect(parsed.getBuffers()).to.not.be.undefined;
            expect(parsed.getBuffers()).to.deep.equal(expected_pktBufs);

            // non-buffer output
            expect(parsed.getMType()).to.equal('Unconfirmed Data Down');
            expect(parsed.getDir()).to.equal('down');
            expect(parsed.getFCnt()).to.equal(2);
            expect(parsed.getFCtrlACK()).to.equal(true);
            expect(parsed.getFCtrlADR()).to.equal(false);
        });

        it('should return null if given bogus input', function () {
            var parsed = lora_packet.fromWire("not a buffer");
            expect(parsed).to.be.null;
        });

        it('should expose constants', function () {
            var constants = lora_packet.constants();
            expect(constants.MTYPE_CONFIRMED_DATA_DOWN).to.equal(5);
        });

    });
};
