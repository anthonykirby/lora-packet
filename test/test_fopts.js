'use strict';

var lora_packet = require('..');
var expect = require("chai").expect;
var assert = require('chai').assert;

module.exports = function () {

    // TODO more variation on this

    describe('parse packets from github issue #18', function () {
        it('should parse packet #1', function () {

            var message_hex = "4084412505A3010009110308B33750F504D4B86A";
//            console.log ("packet #1 message_hex = "+new Buffer(message_base64, 'base64').toString("hex"));

            var parsed = lora_packet.fromWire(new Buffer(message_hex, 'hex'));

            expect(parsed).to.not.be.undefined;
            expect(parsed.getBuffers()).to.not.be.undefined;
            expect(parsed.getBuffers().FOpts).to.not.be.undefined;
            expect(parsed.getBuffers().FOpts).to.deep.equal(new Buffer('091103', 'hex'));

//            var asString = parsed.toString();
//            console.log(asString);
        });


    });
};
