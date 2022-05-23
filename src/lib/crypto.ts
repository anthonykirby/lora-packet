import LoraPacket, { LorawanVersion } from "./LoraPacket";
import { reverseBuffer } from "./util";
import CryptoJS from "crypto-js";
import { Buffer } from "buffer";

const LORAIV = CryptoJS.enc.Hex.parse("00000000000000000000000000000000");

enum KeyType11 {
  FNwkSIntKey = "01",
  AppSKey = "02",
  SNwkSIntKey = "03",
  NwkSEncKey = "04",
}

enum KeyType10 {
  NwkSKey = "01",
  AppSKey = "02",
}

enum KeyTypeJS {
  JSIntKey = "06",
  JSEncKey = "05",
}

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

function decryptFOpts(payload: LoraPacket, NwkSEncKey: Buffer, fCntMSB32?: Buffer): Buffer {
  if (!fCntMSB32) fCntMSB32 = Buffer.alloc(2);

  if (!payload?.FOpts) throw new Error("Expected FOpts to be defined");
  if (!payload?.DevAddr) throw new Error("Expected DevAddr to be defined");
  if (NwkSEncKey.length !== 16) throw new Error("Expected a appropriate key with length 16");
  if (!payload.FCnt) throw new Error("Expected FCnt to be defined");

  const direction: Buffer = Buffer.alloc(1);
  let aFCntDown = false;

  if (payload.getDir() == "up") {
    direction.writeUInt8(0, 0);
  } else if (payload.getDir() == "down") {
    direction.writeUInt8(1, 0);
    if (payload.FPort != null && payload.getFPort() > 0) {
      aFCntDown = true;
    }
  } else {
    throw new Error("Decrypt error: expecting direction to be either 'up' or 'down'");
  }

  // https://lora-alliance.org/wp-content/uploads/2020/11/00001.002.00001.001.cr-fcntdwn-usage-in-fopts-encryption-v2-r1.pdf
  const aBuffer = Buffer.concat([
    Buffer.alloc(1, 1),
    Buffer.alloc(3, 0),
    Buffer.alloc(1, aFCntDown ? 2 : 1),
    direction,
    reverseBuffer(payload.DevAddr),
    reverseBuffer(payload.FCnt),
    fCntMSB32,
    Buffer.alloc(1, 0),
    Buffer.alloc(1, 1),
  ]);

  const cipherstream_base64 = CryptoJS.AES.encrypt(
    CryptoJS.enc.Hex.parse(aBuffer.toString("hex")),
    CryptoJS.enc.Hex.parse(NwkSEncKey.toString("hex")),
    {
      mode: CryptoJS.mode.ECB,
      iv: LORAIV,
      padding: CryptoJS.pad.NoPadding,
    }
  );

  const cipherstream = Buffer.from(cipherstream_base64.toString(), "base64");

  const plaintextPayload = Buffer.alloc(payload.FOpts.length);

  for (let i = 0; i < payload.FOpts.length; i++) {
    plaintextPayload[i] = cipherstream[i] ^ payload.FOpts[i];
  }

  return plaintextPayload;
}

function generateKey(
  key: Buffer,
  AppNonce: Buffer,
  NetIdOrJoinEui: Buffer,
  DevNonce: Buffer,
  keyType: KeyType11 | KeyType10 | KeyTypeJS
): Buffer {
  let keyNonceStr: string = keyType;
  keyNonceStr += reverseBuffer(AppNonce).toString("hex");
  keyNonceStr += reverseBuffer(NetIdOrJoinEui).toString("hex");
  keyNonceStr += reverseBuffer(DevNonce).toString("hex");
  keyNonceStr = keyNonceStr.padEnd(32, "0");

  const keyNonce = Buffer.from(keyNonceStr, "hex");
  const nwkSKey_base64 = CryptoJS.AES.encrypt(
    CryptoJS.enc.Hex.parse(keyNonce.toString("hex")),
    CryptoJS.enc.Hex.parse(key.toString("hex")),
    {
      mode: CryptoJS.mode.ECB,
      padding: CryptoJS.pad.NoPadding,
    }
  );
  return Buffer.from(nwkSKey_base64.toString(), "base64");
}

function generateSessionKeys(
  AppKey: Buffer,
  NetId: Buffer,
  AppNonce: Buffer,
  DevNonce: Buffer
): { AppSKey: Buffer; NwkSKey: Buffer } {
  return generateSessionKeys10(AppKey, NetId, AppNonce, DevNonce);
}

function generateSessionKeys10(
  AppKey: Buffer,
  NetId: Buffer,
  AppNonce: Buffer,
  DevNonce: Buffer
): { AppSKey: Buffer; NwkSKey: Buffer } {
  if (AppKey.length !== 16) throw new Error("Expected a AppKey with length 16");
  if (NetId.length !== 3) throw new Error("Expected a NetId with length 3");
  if (AppNonce.length !== 3) throw new Error("Expected a AppNonce with length 3");
  if (DevNonce.length !== 2) throw new Error("Expected a DevNonce with length 2");
  return {
    AppSKey: generateKey(AppKey, AppNonce, NetId, DevNonce, KeyType10.AppSKey),
    NwkSKey: generateKey(AppKey, AppNonce, NetId, DevNonce, KeyType10.NwkSKey),
  };
}

function generateSessionKeys11(
  AppKey: Buffer,
  NwkKey: Buffer,
  JoinEUI: Buffer,
  AppNonce: Buffer,
  DevNonce: Buffer
): { AppSKey: Buffer; FNwkSIntKey: Buffer; SNwkSIntKey: Buffer; NwkSEncKey: Buffer } {
  if (AppKey.length !== 16) throw new Error("Expected a AppKey with length 16");
  if (NwkKey.length !== 16) throw new Error("Expected a NwkKey with length 16");
  if (AppNonce.length !== 3) throw new Error("Expected a AppNonce with length 3");
  if (DevNonce.length !== 2) throw new Error("Expected a DevNonce with length 2");
  return {
    AppSKey: generateKey(AppKey, AppNonce, JoinEUI, DevNonce, KeyType11.AppSKey),
    FNwkSIntKey: generateKey(NwkKey, AppNonce, JoinEUI, DevNonce, KeyType11.FNwkSIntKey),
    SNwkSIntKey: generateKey(NwkKey, AppNonce, JoinEUI, DevNonce, KeyType11.SNwkSIntKey),
    NwkSEncKey: generateKey(NwkKey, AppNonce, JoinEUI, DevNonce, KeyType11.NwkSEncKey),
  };
}

function generateJSKeys(NwkKey: Buffer, DevEui: Buffer): { JSIntKey: Buffer; JSEncKey: Buffer } {
  if (DevEui.length !== 8) throw new Error("Expected a DevEui with length 16");
  if (NwkKey.length !== 16) throw new Error("Expected a NwkKey with length 16");
  return {
    JSIntKey: generateKey(NwkKey, DevEui, Buffer.alloc(0), Buffer.alloc(0), KeyTypeJS.JSIntKey),
    JSEncKey: generateKey(NwkKey, DevEui, Buffer.alloc(0), Buffer.alloc(0), KeyTypeJS.JSEncKey),
  };
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

export {
  encrypt,
  decrypt,
  decryptJoin,
  decryptFOpts,
  decryptJoinAccept,
  generateSessionKeys,
  generateSessionKeys11,
  generateSessionKeys10,
  generateJSKeys,
};
