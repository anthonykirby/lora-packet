import { decrypt, decryptJoin, generateSessionKeys, decryptJoinAccept, encrypt } from "./lib/crypto";
import { calculateMIC, recalculateMIC, verifyMIC } from "./lib/mic";
import LoraPacket from "./lib/LoraPacket";

const modules = {
  fromWire: LoraPacket.fromWire,
  fromFields: LoraPacket.fromFields,
  decrypt,
  decryptJoin,
  generateSessionKeys,
  decryptJoinAccept,
  encrypt,
  calculateMIC,
  recalculateMIC,
  verifyMIC,
};

export default modules;
module.exports = modules;
