'use strict';

var mic = require('./mic.js');
var crypt = require('./crypt.js');
var packet = require('./packet.js');
var util = require('./util.js')("");

module.exports={
    fromWire:packet.fromWire,
    fromFields:_constructPacketFromFields,

    verifyMIC:mic.verifyMIC,
    calculateMIC:mic.calculateMIC,
    recalculateMIC:mic.recalculateMIC,

    decrypt:crypt.decrypt,

    constants:packet.constants,

    // deprecated
    getMIC:mic.calculateMIC,
    create:packet.fromWire
};


// to create a packet from fields, it's necessary to pull together
//  all three modules (packet.js, mic.js, crypt.js)
function _constructPacketFromFields(userFields, AppSKey, NwkSKey) {
    // if user fails to supply keys, construct a packet anyway
    var constructed = packet.fromFields(userFields);

    if (constructed != null) {
        // to encrypt, need NwkSKey if port=0, else AppSKey
        if ((constructed.getFPort() == 0 && util.isBufferLength(NwkSKey, 16))
            || (constructed.getFPort() > 0 && util.isBufferLength(AppSKey, 16))) {

            // crypto is reversible (just XORs FRMPayload), so we can
            //  just do "decrypt" on the plaintext to get ciphertext
            var ciphertext = crypt.decrypt(constructed, AppSKey, NwkSKey);

            // overwrite payload with ciphertext
            constructed.getBuffers().FRMPayload = ciphertext;

            // recalculate buffers to be ready for MIC calc'n
            constructed.mergeGroupFields();
        }

        if (util.isBufferLength(NwkSKey, 16)) {
            mic.recalculateMIC(constructed, NwkSKey);
            constructed.mergeGroupFields();
        }
    }

    return constructed;
}
