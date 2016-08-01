var mic = require('./mic.js');
var crypt = require('./crypt.js');
var packet = require('./packet.js');
var util = require('./util.js')("");

module.exports={
    fromWire:packet.fromWire,
    fromFields:_constructPacketFromFields,

    verifyMIC:mic.verifyMIC,
    getMIC:mic.getMIC,
    calculateMIC:mic.calculateMIC,

    decrypt:crypt.decrypt,

    // deprecated
    create:packet.fromWire
};

function _constructPacketFromFields(userFields, AppSKey, NwkSkey) {
    // if user fails to supply keys, construct a packet anyway
    var constructed = packet.fromFields(userFields);

    if (constructed != null) {
        if (util.isBufferLength(NwkSkey, 16)) {
            mic.calculateMIC(constructed, NwkSkey);
            constructed.mergeGroupFields();
        }
    }

    return constructed;
}
