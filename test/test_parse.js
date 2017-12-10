'use strict';

var lora_packet = require('..');
var expect = require("chai").expect;
var assert = require('chai').assert;

module.exports = function () {

    // TODO more variation on this

    describe('parse example packet', function () {
        it('should parse data packet', function () {
            var message_hex = "40F17DBE4900020001954378762B11FF0D";

            var expected_pktBufs = {
                PHYPayload: new Buffer('40f17dbe4900020001954378762b11ff0d', 'hex'),
                MACPayloadWithMIC: new Buffer('f17dbe4900020001954378762b11ff0d', 'hex'),
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
            expect(parsed.getFPort()).to.equal(1);
        });

        it('should parse join request packet', function () {
            var message_hex = "0039363463336913AA05693574323831338EF1C1D5EC6C";

            var expected_pktBufs = {
                PHYPayload: new Buffer('0039363463336913aa05693574323831338ef1c1d5ec6c', 'hex'),
                MACPayloadWithMIC: new Buffer('39363463336913aa05693574323831338ef1c1d5ec6c', 'hex'),
                MHDR: new Buffer('00', 'hex'),
                MACPayload: new Buffer('39363463336913aa05693574323831338ef1', 'hex'),
                MIC: new Buffer('c1d5ec6c', 'hex'),
                AppEUI: new Buffer('aa13693363343639', 'hex'),
                DevEUI: new Buffer('3331383274356905', 'hex'),
                DevNonce: new Buffer('f18e', 'hex')
            };

            var parsed = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            expect(parsed).to.not.be.undefined;
            expect(parsed.getBuffers()).to.not.be.undefined;
            expect(parsed.getBuffers()).to.deep.equal(expected_pktBufs);

            // non-buffer output
            expect(parsed.getMType()).to.equal('Join Request');
        });

        it('should parse join accept packet', function () {
            var message_hex = "20386337CCBBAAE7CD2C010000D9D0A6E7"; // not encrypted

            var expected_pktBufs = {
                PHYPayload: new Buffer('20386337ccbbaae7cd2c010000d9d0a6e7', 'hex'),
                MACPayloadWithMIC: new Buffer('386337ccbbaae7cd2c010000d9d0a6e7', 'hex'),
                MHDR: new Buffer('20', 'hex'),
                MACPayload: new Buffer('386337ccbbaae7cd2c010000', 'hex'),
                MIC: new Buffer('d9d0a6e7', 'hex'),
                NetID: new Buffer('aabbcc', 'hex'),
                DevAddr: new Buffer('012ccde7', 'hex'),
                AppNonce: new Buffer('376338', 'hex'),
                DLSettings: new Buffer('00', 'hex'),
                RxDelay: new Buffer('00', 'hex'),
                CFList: new Buffer('', 'hex')
            };

            var parsed = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            expect(parsed).to.not.be.undefined;
            expect(parsed.getBuffers()).to.not.be.undefined;
            expect(parsed.getBuffers()).to.deep.equal(expected_pktBufs);

            // non-buffer output
            expect(parsed.getMType()).to.equal('Join Accept');
        });

        it('should parse data packet with empty payload', function () {
            var message_hex = "40F17DBE49000300012A3518AF";

            var expected_pktBufs = {
                PHYPayload: new Buffer('40f17dbe49000300012a3518af', 'hex'),
                MACPayloadWithMIC: new Buffer('f17dbe49000300012a3518af', 'hex'),
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

        it('should parse large data packet', function () {
            var message_hex = "40f17dbe490004000155332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a20af3c5e7";

            var expected_pktBufs = {
                PHYPayload: new Buffer('40f17dbe490004000155332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a20af3c5e7', 'hex'),
                MACPayloadWithMIC: new Buffer('f17dbe490004000155332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a20af3c5e7', 'hex'),
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
                MACPayloadWithMIC: new Buffer('f17dbe4920020001f9d65d27', 'hex'),
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

        it('should Join Accept', function () {
            var message_hex = "33105EAFD15E04A62872C97F821955A1B75420F0FFCC20CF999347E18AA8A235";

            var expected_pktBufs = {
                PHYPayload: new Buffer('33105EAFD15E04A62872C97F821955A1B75420F0FFCC20CF999347E18AA8A235', 'hex'),
                MACPayloadWithMIC: new Buffer('105EAFD15E04A62872C97F821955A1B75420F0FFCC20CF999347E18AA8A235', 'hex'),
                MHDR: new Buffer('33', 'hex'),
                MACPayload: new Buffer('105EAFD15E04A62872C97F821955A1B75420F0FFCC20CF999347E1', 'hex'),
                MIC: new Buffer('8AA8A235', 'hex'),
                AppNonce: new Buffer('AF5E10', 'hex'),
                NetID: new Buffer('045ED1', 'hex'),
                DevAddr: new Buffer('C97228A6', 'hex'),
                DLSettings: new Buffer('7F', 'hex'),
                RxDelay: new Buffer('82', 'hex'),
                CFList: new Buffer(''),
            };

            var parsed = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            expect(parsed).to.not.be.undefined;
            expect(parsed.getBuffers()).to.not.be.undefined;
            expect(parsed.getBuffers()).to.deep.equal(expected_pktBufs);

            // non-buffer output
            expect(parsed.getMType()).to.equal('Join Accept');
            expect(parsed.getDir()).to.equal('down');
            expect(parsed.getDLSettingsRxOneDRoffset()).to.equal(7);
            expect(parsed.getDLSettingsRxTwoDataRate()).to.equal(0);
            expect(parsed.getRxDelayDel()).to.equal(2);
            expect(parsed.getFCnt()).to.equal(null);
        });

    });
};
