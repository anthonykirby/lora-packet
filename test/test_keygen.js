'use strict';

var lora_packet = require('..');
var expect = require("chai").expect;
var assert = require('chai').assert;

module.exports = function () {

    describe('generate session keys', function () {

        it('should generate valid session keys', function () {
            var AppKey_hex = "98929b92c49edba9676d646d3b612456";
            var NetID_hex = "aabbcc";
            var AppNonce_hex = "376338";
            var DevNonce_hex = "f18e";
            var sessionKeys = lora_packet.generateSessionKeys(
                new Buffer(AppKey_hex, 'hex'), new Buffer(NetID_hex, 'hex'), new Buffer(AppNonce_hex, 'hex'), new Buffer(DevNonce_hex, 'hex')
            );
            expect(sessionKeys).to.not.be.undefined;
            expect(sessionKeys.NwkSKey.toString('hex')).to.equal('4e3d6e6afbcc67af2ba3c8e8ec4acf4b');
            expect(sessionKeys.AppSKey.toString('hex')).to.equal('610897aa6f1460623443b527d3ac6a9d');
        });

    });
};

