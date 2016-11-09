'use strict';

var lora_packet = require('..');
var expect = require("chai").expect;
var assert = require('chai').assert;

module.exports = function() {

    // TODO more variation on this

    describe('construct packet from fields', function() {
        it('should handle undefined input', function() {
            var packet = lora_packet.fromFields(undefined);
            expect(packet).to.be.null;
        });
        it('should handle null input', function() {
            var packet = lora_packet.fromFields(null);
            expect(packet).to.be.null;
        });
        it('should handle buffer input', function() {
            var packet = lora_packet.fromFields(new Buffer("1234"));
            expect(packet).to.be.null;
        });
        it('should handle string input', function() {
            var packet = lora_packet.fromFields(new Buffer("1234"));
            expect(packet).to.be.null;
        });
        it('should handle empty object input', function() {
            var packet = lora_packet.fromFields({
                wot: 'foo'
            });
            expect(packet).to.be.null;
        });

        it('should create packet with minimal input', function() {
            var packet = lora_packet.fromFields({
                payload: 'test',
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
            expect(packet).not.to.be.null;
            expect(packet.getBuffers()).to.not.be.undefined;
            expect(packet.getBuffers()).to.deep.equal(expected_pktBufs);
        });


        it('should create packet with MType as integer', function() {
            var packet = lora_packet.fromFields({
                payload: 'test',
                DevAddr: new Buffer('a1b2c3d4', 'hex'),
                MType: 5
            });
            var expected_pktBufs = {
                PHYPayload: new Buffer('A0d4c3b2a10001000174657374eeeeeeee', 'hex'),
                MHDR: new Buffer('A0', 'hex'),
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
            expect(packet).not.to.be.null;
            expect(packet.getBuffers()).to.not.be.undefined;
            expect(packet.getBuffers()).to.deep.equal(expected_pktBufs);
        });

        it('should create packet with MType as string', function() {
            var packet = lora_packet.fromFields({
                payload: 'test',
                DevAddr: new Buffer('a1b2c3d4', 'hex'),
                MType: 'Confirmed Data Up'
            });
            var expected_pktBufs = {
                PHYPayload: new Buffer('80d4c3b2a10001000174657374eeeeeeee', 'hex'),
                MHDR: new Buffer('80', 'hex'),
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
            expect(packet).not.to.be.null;
            expect(packet.getBuffers()).to.not.be.undefined;
            expect(packet.getBuffers()).to.deep.equal(expected_pktBufs);
        });



        it('should create packet with FCnt as buffer', function() {
            var packet = lora_packet.fromFields({
                payload: 'test',
                DevAddr: new Buffer('a1b2c3d4', 'hex'),
                FCnt: new Buffer('1234', 'hex')
            });
            var expected_pktBufs = {
                PHYPayload: new Buffer('40d4c3b2a10034120174657374eeeeeeee', 'hex'),
                MHDR: new Buffer('40', 'hex'),
                MACPayload: new Buffer('d4c3b2a10034120174657374', 'hex'),
                MIC: new Buffer('EEEEEEEE', 'hex'),
                FOpts: new Buffer(0),
                FCtrl: new Buffer('00', 'hex'),
                FHDR: new Buffer('d4c3b2a1003412', 'hex'),
                DevAddr: new Buffer('a1b2c3d4', 'hex'),
                FCnt: new Buffer('1234', 'hex'),
                FPort: new Buffer('01', 'hex'),
                FRMPayload: new Buffer('test')
            };
            expect(packet).not.to.be.null;
            expect(packet.getBuffers()).to.not.be.undefined;
            expect(packet.getBuffers()).to.deep.equal(expected_pktBufs);
        });

        it('should create packet with FCnt as integer', function() {
            var packet = lora_packet.fromFields({
                payload: 'test',
                DevAddr: new Buffer('a1b2c3d4', 'hex'),
                FCnt: 4660
            });
            var expected_pktBufs = {
                PHYPayload: new Buffer('40d4c3b2a10034120174657374eeeeeeee', 'hex'),
                MHDR: new Buffer('40', 'hex'),
                MACPayload: new Buffer('d4c3b2a10034120174657374', 'hex'),
                MIC: new Buffer('EEEEEEEE', 'hex'),
                FOpts: new Buffer(0),
                FCtrl: new Buffer('00', 'hex'),
                FHDR: new Buffer('d4c3b2a1003412', 'hex'),
                DevAddr: new Buffer('a1b2c3d4', 'hex'),
                FCnt: new Buffer('1234', 'hex'),
                FPort: new Buffer('01', 'hex'),
                FRMPayload: new Buffer('test')
            };
            expect(packet).not.to.be.null;
            expect(packet.getBuffers()).to.not.be.undefined;
            expect(packet.getBuffers()).to.deep.equal(expected_pktBufs);
        });


        it('should create packet with FOpts as buffer', function() {
            var packet = lora_packet.fromFields({
                payload: 'test',
                DevAddr: new Buffer('a1b2c3d4', 'hex'),
                FOpts: new Buffer('03610f00', 'hex'),
                FCtrl: {
                    ACK: true
                }
            });
            expect(packet).not.to.be.null;
            expect(packet.getBuffers()).to.not.be.undefined;
            expect(packet.getBuffers().FOpts).to.deep.equal(new Buffer('03610f00', 'hex'));
            expect(packet.getBuffers().FCtrl).to.deep.equal(new Buffer('24', 'hex'));
        });

        it('should create packet with FOpts as string', function() {
            var packet = lora_packet.fromFields({
                payload: 'test',
                DevAddr: new Buffer('a1b2c3d4', 'hex'),
                FOpts: '03610f00',
                FCtrl: {
                    ADR: true
                }
            });
            expect(packet).not.to.be.null;
            expect(packet.getBuffers()).to.not.be.undefined;
            expect(packet.getBuffers().FOpts).to.deep.equal(new Buffer('03610f00', 'hex'));
            expect(packet.getBuffers().FCtrl).to.deep.equal(new Buffer('84', 'hex'));
        });

        it('should not create packet with FOpts longer than 15', function() {
            var packet = lora_packet.fromFields({
                payload: 'test',
                DevAddr: new Buffer('a1b2c3d4', 'hex'),
                FOpts: '0102030405060708090A0B0C0D0E0F10',
            });
            expect(packet).to.be.null;
        });


        it('should create packet with correct FCtrl.ACK', function() {
            var packet = lora_packet.fromFields({
                payload: 'test',
                DevAddr: new Buffer('a1b2c3d4', 'hex'),
                FCtrl: {
                    ACK: true
                }
            });
            expect(packet.getBuffers().FCtrl).to.deep.equal(new Buffer('20', 'hex'));
            expect(packet.getFCtrlACK()).to.equal(true);
            packet = lora_packet.fromFields({
                payload: 'test',
                DevAddr: new Buffer('a1b2c3d4', 'hex'),
                FCtrl: {
                    ACK: false
                }
            });
            expect(packet.getBuffers().FCtrl).to.deep.equal(new Buffer('00', 'hex'));
            expect(packet.getFCtrlACK()).to.equal(false);
        });

        it('should create packet with correct FCtrl.ADR', function() {
            var packet = lora_packet.fromFields({
                payload: 'test',
                DevAddr: new Buffer('a1b2c3d4', 'hex'),
                FCtrl: {
                    ADR: true
                }
            });
            expect(packet.getBuffers().FCtrl).to.deep.equal(new Buffer('80', 'hex'));
            expect(packet.getFCtrlADR()).to.equal(true);
            packet = lora_packet.fromFields({
                payload: 'test',
                DevAddr: new Buffer('a1b2c3d4', 'hex'),
                FCtrl: {
                    ACK: false
                }
            });
            expect(packet.getBuffers().FCtrl).to.deep.equal(new Buffer('00', 'hex'));
            expect(packet.getFCtrlADR()).to.equal(false);
        });
        it('should create packet with correct FCtrl when all flags set', function() {
            var packet = lora_packet.fromFields({
                payload: 'test',
                DevAddr: new Buffer('a1b2c3d4', 'hex'),
                FCtrl: {
                    ADR: true,
                    ACK: true,
                    ADRACKReq: true,
                    FPending: true
                }
            });
            expect(packet.getBuffers().FCtrl).to.deep.equal(new Buffer('F0', 'hex'));
            expect(packet.getFCtrlADR()).to.equal(true);
            expect(packet.getFCtrlACK()).to.equal(true);
            expect(packet.getFCtrlFPending()).to.equal(true);
        });

        it('should create packet with correct FPort', function() {
            var packet = lora_packet.fromFields({
                payload: 'test',
                DevAddr: new Buffer('a1b2c3d4', 'hex'),
                FPort: 42
            });
            expect(packet.getFPort()).to.equal(42);
        });


        it('should calculate MIC if NwkSKey provided', function() {
            var packet = lora_packet.fromFields({
                    payload: new Buffer('95437876', 'hex'),
                    DevAddr: new Buffer('49be7df1', 'hex'),
                    FCnt: new Buffer('0002', 'hex')
                }, null // AppSKey
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

        it('should encrypt if keys provided', function() {
            var packet = lora_packet.fromFields({
                    payload: 'test',
                    DevAddr: new Buffer('49be7df1', 'hex'),
                    FCnt: new Buffer('0002', 'hex')
                }, new Buffer("ec925802ae430ca77fd3dd73cb2cc588", 'hex') // AppSKey
                , new Buffer("44024241ed4ce9a68c6a8bc055233fd3", 'hex') // NwkSKey
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
            expect(packet.getPHYPayload()).to.deep.equal(expected_pktBufs.PHYPayload);
        });


    });
};