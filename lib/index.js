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

function _constructPacketFromFields(userFields, AppSKey, NwkSkey) {
    // if user fails to supply keys, construct a packet anyway
    var constructed = packet.fromFields(userFields);

    if (constructed != null) {
        if (util.isBufferLength(NwkSkey, 16)) {
            mic.recalculateMIC(constructed, NwkSkey);
            constructed.mergeGroupFields();
        }
    }

    return constructed;
}
