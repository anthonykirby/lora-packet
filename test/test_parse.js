'use strict';

var lora_packet = require('..');
var expect = require("chai").expect;
var assert = require('chai').assert;

module.exports = function () {

    // TODO more variation on this

    describe('parse example packet', function () {
        it('should return correct results ', function () {
            var message_hex = "40F17DBE4900020001954378762B11FF0D";

            var expected_pktBufs = {
                PHYPayload: new Buffer('40f17dbe4900020001954378762b11ff0d', 'hex'),
                MHDR: new Buffer('40', 'hex'),
                MACPayload: new Buffer('f17dbe490002000195437876', 'hex'),
                MIC: new Buffer('2b11ff0d', 'hex'),
                FOpts: new Buffer(0),
                FCtrl: new Buffer('00', 'hex'),
                FHDR: new Buffer('f17dbe49000200', 'hex'),
                DevAddr: new Buffer('f17dbe49', 'hex'),
                FCnt: new Buffer('0200', 'hex'),
                FPort: new Buffer('01', 'hex'),
                FRMPayload: new Buffer('95437876', 'hex')
            };

            var parsed = lora_packet.create(new Buffer(message_hex, 'hex'));

            expect(parsed).to.not.be.undefined;
            expect(parsed.getBuffers()).to.not.be.undefined;
            expect(parsed.getBuffers()).to.deep.equal(expected_pktBufs);

            // non-buffer output
            expect(parsed.getMType()).to.equal('Unconfirmed Data Up');
            expect(parsed.getDir()).to.equal('up');
            expect(parsed.getFCnt()).to.equal(2);
        });

        it('should calculate & verify correct MIC', function () {
            var message_hex = "40F17DBE4900020001954378762B11FF0D";
            var packet = lora_packet.create(new Buffer(message_hex, 'hex'))

            var NwkSKey_hex = "44024241ed4ce9a68c6a8bc055233fd3";
            var calculatedMIC = lora_packet.getMIC(packet, new Buffer(NwkSKey_hex, 'hex'));
            expect(calculatedMIC.toString('hex')).to.equal('2b11ff0d');

            expect(lora_packet.verifyMIC(packet, new Buffer(NwkSKey_hex, 'hex'))).to.equal(true);
        });

        it('should calculate & verify correct MIC', function () {
            var message_hex = "40F17DBE49000300012A3518AF";
            var packet = lora_packet.create(new Buffer(message_hex, 'hex'))

            var NwkSKey_hex = "44024241ed4ce9a68c6a8bc055233fd3";
            var calculatedMIC = lora_packet.getMIC(packet, new Buffer(NwkSKey_hex, 'hex'));
            expect(calculatedMIC.toString('hex')).to.equal('2a3518af');

            expect(lora_packet.verifyMIC(packet, new Buffer(NwkSKey_hex, 'hex'))).to.equal(true);
        });

        it('should detect incorrect MIC', function () {
            // bodged MIC so it's different
            var message_hex = "40F17DBE49000300012A3518AA"; // aa not af
            var packet = lora_packet.create(new Buffer(message_hex, 'hex'))

            var NwkSKey_hex = "44024241ed4ce9a68c6a8bc055233fd3";
            var calculatedMIC = lora_packet.getMIC(packet, new Buffer(NwkSKey_hex, 'hex'));
            expect(calculatedMIC.toString('hex')).to.equal('2a3518af');

            expect(lora_packet.verifyMIC(packet, new Buffer(NwkSKey_hex, 'hex'))).to.equal(false);
        });


        it('should return correct results with empty payload', function () {
            var message_hex = "40F17DBE49000300012A3518AF";

            var expected_pktBufs = {
                PHYPayload: new Buffer('40f17dbe49000300012a3518af', 'hex'),
                MHDR: new Buffer('40', 'hex'),
                MACPayload: new Buffer('f17dbe4900030001', 'hex'),
                MIC: new Buffer('2a3518af', 'hex'),
                FOpts: new Buffer(0),
                FCtrl: new Buffer('00', 'hex'),
                FHDR: new Buffer('f17dbe49000300', 'hex'),
                DevAddr: new Buffer('f17dbe49', 'hex'),
                FCnt: new Buffer('0300', 'hex'),
                FPort: new Buffer('01', 'hex'),
                FRMPayload: new Buffer('', 'hex')
            };

            var parsed = lora_packet.create(new Buffer(message_hex, 'hex'));

            expect(parsed).to.not.be.undefined;
            expect(parsed.getBuffers()).to.not.be.undefined;
            expect(parsed.getBuffers()).to.deep.equal(expected_pktBufs);

            // non-buffer output
            expect(parsed.getMType()).to.equal('Unconfirmed Data Up');
            expect(parsed.getDir()).to.equal('up');
            expect(parsed.getFCnt()).to.equal(3);
        });

        it('should return correct results with large payload', function () {
            var message_hex = "40f17dbe490004000155332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a20af3c5e7";

            var expected_pktBufs = {
                PHYPayload: new Buffer('40f17dbe490004000155332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a20af3c5e7', 'hex'),
                MHDR: new Buffer('40', 'hex'),
                MACPayload: new Buffer('f17dbe490004000155332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a2', 'hex'),
                MIC: new Buffer('0af3c5e7', 'hex'),
                FOpts: new Buffer(0),
                FCtrl: new Buffer('00', 'hex'),
                FHDR: new Buffer('f17dbe49000400', 'hex'),
                DevAddr: new Buffer('f17dbe49', 'hex'),
                FCnt: new Buffer('0400', 'hex'),
                FPort: new Buffer('01', 'hex'),
                FRMPayload: new Buffer('55332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a2', 'hex')
            };

            var parsed = lora_packet.create(new Buffer(message_hex, 'hex'));

            expect(parsed).to.not.be.undefined;
            expect(parsed.getBuffers()).to.not.be.undefined;
            expect(parsed.getBuffers()).to.deep.equal(expected_pktBufs);

            // non-buffer output
            expect(parsed.getMType()).to.equal('Unconfirmed Data Up');
            expect(parsed.getDir()).to.equal('up');
            expect(parsed.getFCnt()).to.equal(4);
        });

        it('should decrypt test payload', function () {
            var message_hex = "40F17DBE4900020001954378762B11FF0D";
            var packet = lora_packet.create(new Buffer(message_hex, 'hex'));

            var AppSKey_hex = "ec925802ae430ca77fd3dd73cb2cc588";
            var decrypted = lora_packet.decrypt(packet, new Buffer(AppSKey_hex, 'hex'), undefined);
            expect(decrypted).to.not.be.undefined;
            expect(decrypted.toString()).to.equal('test');
        });
        it('should decrypt large payload', function () {
            var message_hex = "40f17dbe490004000155332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a20af3c5e7";
            var packet = lora_packet.create(new Buffer(message_hex, 'hex'));

            var AppSKey_hex = "ec925802ae430ca77fd3dd73cb2cc588";
            var decrypted = lora_packet.decrypt(packet, new Buffer(AppSKey_hex, 'hex'), undefined);
            expect(decrypted).to.not.be.undefined;
            expect(decrypted.toString()).to.equal('The quick brown fox jumps over the lazy dog.');
        });

        it('bad key scrambles payload', function () {
            var message_hex = "40F17DBE4900020001954378762B11FF0D";
            var packet = lora_packet.create(new Buffer(message_hex, 'hex'));

            var AppSKey_hex = "ec925802ae430ca77fd3dd73cb2cc580";
            var decrypted = lora_packet.decrypt(packet, new Buffer(AppSKey_hex, 'hex'), undefined);
            expect(decrypted).to.not.be.undefined;
            expect(decrypted.toString('hex')).to.equal('5999fc3f');
        });


        it('bad data lightly scrambles payload', function () {
            var message_hex = "40F17DBE4900020001954478762B11FF0D";
            var packet = lora_packet.create(new Buffer(message_hex, 'hex'));

            var AppSKey_hex = "ec925802ae430ca77fd3dd73cb2cc588";
            var decrypted = lora_packet.decrypt(packet, new Buffer(AppSKey_hex, 'hex'), undefined);
            expect(decrypted).to.not.be.undefined;
            expect(decrypted.toString()).to.equal('tbst');
        });

    });
};






function isDeepEqual(a, b) {
    try {
        assert.deepEqual(a, b);
        return true;
    } catch (e) {
        return false;
    }
}