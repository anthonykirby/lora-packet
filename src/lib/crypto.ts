import LoraPacket from "./LoraPacket";
import { reverseBuffer } from "./util";
import CryptoJS from "crypto-js";

const LORAIV = CryptoJS.enc.Hex.parse("00000000000000000000000000000000");

function decrypt(payload: LoraPacket, AppSKey?: Buffer, NwkSKey?: Buffer, fCntMSB32?: Buffer): Buffer {
  if (!payload.PHYPayload || !payload.FRMPayload) throw new Error("Payload was not defined");

  if (!fCntMSB32) fCntMSB32 = Buffer.alloc(2, 0);

  const blocks = Math.ceil(payload.FRMPayload.length / 16);

  const sequenceS = Buffer.alloc(16 * blocks);
  for (let block = 0; block < blocks; block++) {
    const ai = _metadataBlockAi(payload, block, fCntMSB32);

    ai.copy(sequenceS, block * 16);
  }

  const key = payload.getFPort() === 0 ? NwkSKey : AppSKey;
  if (!key || key.length !== 16) throw new Error("Expected a appropriate key with length 16");

  const cipherstream_base64 = CryptoJS.AES.encrypt(
    CryptoJS.enc.Hex.parse(sequenceS.toString("hex")),
    CryptoJS.enc.Hex.parse(key.toString("hex")),
    {
      mode: CryptoJS.mode.ECB,
      iv: LORAIV,
      padding: CryptoJS.pad.NoPadding,
    }
  );

  const cipherstream = Buffer.from(cipherstream_base64.toString(), "base64");

  const plaintextPayload = Buffer.alloc(payload.FRMPayload.length);

  for (let i = 0; i < payload.FRMPayload.length; i++) {
    const Si = cipherstream.readUInt8(i);
    plaintextPayload.writeUInt8(Si ^ payload.FRMPayload.readUInt8(i), i);
  }

  return plaintextPayload;
}

// Check
function decryptJoin(payload: LoraPacket, AppKey: Buffer): Buffer {
  if (!payload?.MACPayloadWithMIC) throw new Error("Expected parsed payload to be defined");
  if (AppKey.length !== 16) throw new Error("Expected a appropriate key with length 16");

  const cipherstream = CryptoJS.AES.decrypt(
    payload.MACPayloadWithMIC.toString("base64"),
    CryptoJS.enc.Hex.parse(AppKey.toString("hex")),
    {
      mode: CryptoJS.mode.ECB,
      padding: CryptoJS.pad.NoPadding,
    }
  );
  return Buffer.from(cipherstream.toString(), "hex");
}

function generateSessionKeys(
  AppKey: Buffer,
  NetId: Buffer,
  AppNonce: Buffer,
  DevNonce: Buffer
): { AppSKey: Buffer; NwkSKey: Buffer } {
  if (AppKey.length !== 16) throw new Error("Expected a AppKey with length 16");
  if (NetId.length !== 3) throw new Error("Expected a NetId with length 3");
  if (AppNonce.length !== 3) throw new Error("Expected a AppNonce with length 3");
  if (DevNonce.length !== 2) throw new Error("Expected a DevNonce with length 2");

  const nwkSKeyNonce = Buffer.concat([
    Buffer.from("01", "hex"),
    reverseBuffer(AppNonce),
    reverseBuffer(NetId),
    reverseBuffer(DevNonce),
    Buffer.from("00000000000000", "hex"),
  ]);
  const nwkSKey_base64 = CryptoJS.AES.encrypt(
    CryptoJS.enc.Hex.parse(nwkSKeyNonce.toString("hex")),
    CryptoJS.enc.Hex.parse(AppKey.toString("hex")),
    {
      mode: CryptoJS.mode.ECB,
      padding: CryptoJS.pad.NoPadding,
    }
  );
  const NwkSKey = Buffer.from(nwkSKey_base64.toString(), "base64");

  const appSKeyNonce = Buffer.concat([
    Buffer.from("02", "hex"),
    reverseBuffer(AppNonce),
    reverseBuffer(NetId),
    reverseBuffer(DevNonce),
    Buffer.from("00000000000000", "hex"),
  ]);
  const appSKey_base64 = CryptoJS.AES.encrypt(
    CryptoJS.enc.Hex.parse(appSKeyNonce.toString("hex")),
    CryptoJS.enc.Hex.parse(AppKey.toString("hex")),
    {
      mode: CryptoJS.mode.ECB,
      padding: CryptoJS.pad.NoPadding,
    }
  );
  const AppSKey = Buffer.from(appSKey_base64.toString(), "base64");
  return { AppSKey, NwkSKey };
}
function encrypt(buffer: Buffer, key: Buffer): Buffer {
  // CHECK
  const ciphertext = CryptoJS.AES.encrypt(
    CryptoJS.enc.Hex.parse(buffer.toString("hex")),
    CryptoJS.enc.Hex.parse(key.toString("hex")),
    {
      mode: CryptoJS.mode.ECB,
      iv: LORAIV,
      padding: CryptoJS.pad.NoPadding,
    }
  ).ciphertext.toString(CryptoJS.enc.Hex);
  return Buffer.from(ciphertext, "hex");
}

function decryptJoinAccept(payload: LoraPacket, appKey: Buffer): Buffer {
  const payloadBuffer = payload.PHYPayload || Buffer.alloc(0);
  // Check
  const mhdr = payloadBuffer.slice(0, 1);
  const joinAccept = encrypt(payloadBuffer.slice(1), appKey);
  return Buffer.concat([mhdr, joinAccept]);
}

// Encrypt stream mixes in metadata blocks, as Ai =
//   0x01
//   0x00 0x00 0x00 0x00
//   direction-uplink/downlink [1]
//   DevAddr [4]
//   FCnt as 32-bit, lsb first [4]
//   0x00
//   counter = i [1]

function _metadataBlockAi(payload: LoraPacket, blockNumber: number, fCntMSB32?: Buffer): Buffer {
  if (!fCntMSB32) fCntMSB32 = Buffer.alloc(2);

  let direction;
  if (payload.getDir() == "up") {
    direction = Buffer.alloc(1, 0);
  } else if (payload.getDir() == "down") {
    direction = Buffer.alloc(1, 1);
  } else {
    throw new Error("Decrypt error: expecting direction to be either 'up' or 'down'");
  }
  if (!payload.DevAddr) throw new Error("Decrypt error: DevAddr not defined'");
  if (!payload.FCnt) throw new Error("Decrypt error: FCnt not defined'");

  const aiBuffer = Buffer.concat([
    Buffer.from("0100000000", "hex"),
    direction,
    reverseBuffer(payload.DevAddr),
    reverseBuffer(payload.FCnt),
    fCntMSB32,
    Buffer.alloc(1, 0),
    Buffer.alloc(1, blockNumber + 1),
  ]);

  return aiBuffer;
}

export { encrypt, decrypt, decryptJoin, decryptJoinAccept, generateSessionKeys };
