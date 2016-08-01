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

    // deprecated
    getMIC:mic.calculateMIC,
    create:packet.fromWire
};

function _constructPacketFromFields(userFields, AppSKey, NwkSKey) {
    // if user fails to supply keys, construct a packet anyway
    var constructed = packet.fromFields(userFields);

    if (constructed != null) {
        // only require relevant keys
        if (util.isBufferLength(NwkSKey, 16) && util.isBufferLength(AppSKey, 16)) {
            // crypto is reversible (just XORs FRMPayload)
            var modified_text = crypt.decrypt(constructed, AppSKey, NwkSKey);
            constructed.getBuffers().FRMPayload =modified_text;
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
