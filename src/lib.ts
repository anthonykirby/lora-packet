import {
  decrypt,
  decryptJoin,
  generateSessionKeys,
  decryptJoinAccept,
  encrypt,
  generateSessionKeys11,
  generateSessionKeys10,
  generateWORSessionKeys,
  generateWORKey,
  generateJSKeys,
} from "./lib/crypto";
import { calculateMIC, recalculateMIC, verifyMIC } from "./lib/mic";
import LoraPacket from "./lib/LoraPacket";

const modules = {
  fromWire: LoraPacket.fromWire,
  fromFields: LoraPacket.fromFields,
  decrypt,
  decryptJoin,
  generateSessionKeys,
  generateSessionKeys10,
  generateSessionKeys11,
  generateWORSessionKeys,
  generateWORKey,
  generateJSKeys,
  decryptJoinAccept,
  encrypt,
  calculateMIC,
  recalculateMIC,
  verifyMIC,
};

export default modules;
module.exports = modules;
