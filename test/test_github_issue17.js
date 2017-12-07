'use strict';

var lora_packet = require('..');
var expect = require("chai").expect;
var assert = require('chai').assert;

module.exports = function () {

    // TODO more variation on this

    describe('parse packets from github issue #17', function () {
        it('should parse packet #1', function () {
            var message_base64 = "MxBer9FeBKYocsl/ghlVobdUIPD/zCDPmZNH4YqoojU=";
//            console.log ("packet #1 message_hex = "+new Buffer(message_base64, 'base64').toString("hex"));

            var parsed = lora_packet.fromWire(new Buffer(message_base64, 'base64'));

            expect(parsed).to.not.be.undefined;
            expect(parsed.getBuffers()).to.not.be.undefined;
            var asString = parsed.toString();

//            console.log(asString);
        });

        it('should parse packet #2', function () {
            var message_base64 = "OzXyHlIP87QFJcUUSwJJ05OfMI16FN+11LBIFbx0i3Ml76YDsWE6EXTuVIHcZHq8W9y7YkvXIzD/UjDn90geq+cIc1ESELjmS/3PKQuz2mkh4gaIODijgYsO6y3tgS5pN8GfWnWFfaL6QnM=";
//            console.log ("packet #2 message_hex = "+new Buffer(message_base64, 'base64').toString("hex"));

            var parsed = lora_packet.fromWire(new Buffer(message_base64, 'base64'));

            expect(parsed).to.not.be.undefined;
            expect(parsed.getBuffers()).to.not.be.undefined;
            var asString = parsed.toString();

//            console.log(asString);
        });

        it('should parse packet #3', function () {
            var message_base64 = "LguOqcAjnlkI3QiAlgbBFu4jHqHM6fkVARZiMz0wkO1LxfR8xzTJ2bC6Zv9geek2gTorqOUIgSLQZKpKvuZGUc9NsbZBegjRKqmzhvS0IfkNQQ==";
//            console.log ("packet #3 message_hex = "+new Buffer(message_base64, 'base64').toString("hex"));

            var parsed = lora_packet.fromWire(new Buffer(message_base64, 'base64'));

            expect(parsed).to.not.be.undefined;
            expect(parsed.getBuffers()).to.not.be.undefined;
            var asString = parsed.toString();

//            console.log(asString);
        });

/*
 * I'm not convinced this is a valid packet
 * (if you can explain how it is, I'll gladly write code to decode it
 *
        it('should parse packet #4', function () {
            var message_base64 = "mp6cIKwk";
//            console.log ("packet #4 message_hex = "+new Buffer(message_base64, 'base64').toString("hex"));

            var parsed = lora_packet.fromWire(new Buffer(message_base64, 'base64'));

            expect(parsed).to.not.be.undefined;
            expect(parsed.getBuffers()).to.not.be.undefined;
            var asString = parsed.toString();

//            console.log(asString);
        });
 */

        it('should parse packet #5', function () {
            var message_base64 = "L6B+BD7/WzsJh+uNIHwKa3rV1/kP63fYQhYwXpAQWoDdsPu6iSOL9DPaC8HsKpMaFHc96wcLX5fh5SCd+mO5AoGdagie9Cdxz4bJo52R5hwDbWTXeOta0CXv+GM1vP5sBsD2hCF6NterPz3QeC7/8VvN7hfohVdkWneAa2r6JhXwFisPbh4V2Bfxrvn1k7Prc4BMVHdzt7WpTVVUUvckypPo52K1L5bl0pd1C5XD6ULNzmUSs9y9vdGsNow3PM8HScxLDvUgm9ENuooeTiEh9zmIxLSFp2OHIV0bf7TmCw4e8EPF/pE=";
//            console.log ("packet #5 message_hex = "+new Buffer(message_base64, 'base64').toString("hex"));

            var parsed = lora_packet.fromWire(new Buffer(message_base64, 'base64'));

            expect(parsed).to.not.be.undefined;
            expect(parsed.getBuffers()).to.not.be.undefined;
            var asString = parsed.toString();

//            console.log(asString);
        });

/*
 * I'm not convinced this is a valid packet
 * (if you can explain how it is, I'll gladly write code to decode it
 *
        it('should parse packet #6', function () {
            var message_base64 = "q5r5mNQ=";

            console.log ("packet #6 message_hex = "+new Buffer(message_base64, 'base64').toString("hex"));

            var parsed = lora_packet.fromWire(new Buffer(message_base64, 'base64'));

            expect(parsed).to.not.be.undefined;
            expect(parsed.getBuffers()).to.not.be.undefined;
            var asString = parsed.toString();

            console.log(asString);
        });
*/
    });
};
