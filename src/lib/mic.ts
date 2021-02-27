import LoraPacket from "./LoraPacket";
import { reverseBuffer } from "./util";

// @ts-ignore
import { aesCmac } from "node-aes-cmac";

// calculate MIC from payload
function calculateMIC(payload: LoraPacket, NwkSKey?: Buffer, AppKey?: Buffer, FCntMSBytes?: Buffer): Buffer {
  if (payload.isJoinRequestMessage()) {
    if (AppKey && AppKey.length !== 16) throw new Error("Expected a AppKey with length 16");
    if (!payload.MHDR) throw new Error("Expected MHDR to be defined");
    if (!payload.AppEUI) throw new Error("Expected AppEUI to be defined");
    if (!payload.DevEUI) throw new Error("Expected DevEUI to be defined");
    if (!payload.DevNonce) throw new Error("Expected DevNonce to be defined");
    if (!payload.MACPayload) throw new Error("Expected DevNonce to be defined");

    // const msgLen = payload.MHDR.length + payload.AppEUI.length + payload.DevEUI.length + payload.DevNonce.length;

    // CMAC over MHDR | AppEUI | DevEUI | DevNonce
    // the seperate fields are not in little-endian format, use the concatenated field
    const cmacInput = Buffer.concat([payload.MHDR, payload.MACPayload]);

    // CMAC calculation (as RFC4493)
    let fullCmac = aesCmac(AppKey, cmacInput, { returnAsBuffer: true });
    if (!(fullCmac instanceof Buffer)) fullCmac = Buffer.from(fullCmac);
    // only first 4 bytes of CMAC are used as MIC
    const MIC = fullCmac.slice(0, 4);

    return MIC;
  } else if (payload.isJoinAcceptMessage()) {
    if (AppKey && AppKey.length !== 16) throw new Error("Expected a AppKey with length 16");
    if (!payload.MHDR) throw new Error("Expected MHDR to be defined");
    if (!payload.AppNonce) throw new Error("Expected AppNonce to be defined");
    if (!payload.NetID) throw new Error("Expected NetID to be defined");
    if (!payload.DevAddr) throw new Error("Expected DevAddr to be defined");
    if (!payload.DLSettings) throw new Error("Expected DLSettings to be defined");
    if (!payload.RxDelay) throw new Error("Expected RxDelay to be defined");
    if (!payload.CFList) throw new Error("Expected CFList to be defined");
    if (!payload.MACPayload) throw new Error("Expected MACPayload to be defined");

    // const msgLen =
    //   payload.MHDR.length +
    //   payload.AppNonce.length +
    //   payload.NetID.length +
    //   payload.DevAddr.length +
    //   payload.DLSettings.length +
    //   payload.RxDelay.length +
    //   payload.CFList.length;

    // CMAC over MHDR | AppNonce | NetID | DevAddr | DLSettings | RxDelay | CFList
    // the seperate fields are not encrypted, use the encrypted concatenated field
    const cmacInput = Buffer.concat([payload.MHDR, payload.MACPayload]);

    // CMAC calculation (as RFC4493)
    let fullCmac = aesCmac(AppKey, cmacInput, { returnAsBuffer: true });
    if (!(fullCmac instanceof Buffer)) fullCmac = Buffer.from(fullCmac);
    // only first 4 bytes of CMAC are used as MIC
    const MIC = fullCmac.slice(0, 4);

    return MIC;
  } else {
    if (NwkSKey && NwkSKey.length !== 16) throw new Error("Expected a NwkSKey with length 16");
    if (payload.DevAddr && payload.DevAddr.length !== 4) throw new Error("Expected a payload DevAddr with length 4");
    if (payload.FCnt && payload.FCnt.length !== 2) throw new Error("Expected a payload FCnt with length 2");
    if (!payload.MHDR) throw new Error("Expected MHDR to be defined");
    if (!payload.DevAddr) throw new Error("Expected DevAddr to be defined");
    if (!payload.FCnt) throw new Error("Expected FCnt to be defined");
    if (!payload.MACPayload) throw new Error("Expected MACPayload to be defined");

    if (!FCntMSBytes) {
      FCntMSBytes = Buffer.from("0000", "hex");
    }

    let dir;
    if (payload.getDir() == "up") {
      dir = Buffer.alloc(1, 0);
    } else if (payload.getDir() == "down") {
      dir = Buffer.alloc(1, 1);
    } else {
      throw new Error("expecting direction to be either 'up' or 'down'");
    }

    const msgLen = payload.MHDR.length + payload.MACPayload.length;

    const B0 = Buffer.concat([
      Buffer.from("4900000000", "hex"), // as spec
      dir, // direction ('Dir')
      reverseBuffer(payload.DevAddr),
      reverseBuffer(payload.FCnt),
      FCntMSBytes, // upper 2 bytes of FCnt (zeroes)
      Buffer.alloc(1, 0), // 0x00
      Buffer.alloc(1, msgLen), // len(msg)
    ]);

    // CMAC over B0 | MHDR | MACPayload
    const cmacInput = Buffer.concat([B0, payload.MHDR, payload.MACPayload]);

    // CMAC calculation (as RFC4493)
    let fullCmac = aesCmac(NwkSKey, cmacInput, { returnAsBuffer: true });
    if (!(fullCmac instanceof Buffer)) fullCmac = Buffer.from(fullCmac);

    // only first 4 bytes of CMAC are used as MIC
    const MIC = fullCmac.slice(0, 4);

    return MIC;
  }
}

// verify is just calculate & compare
function verifyMIC(payload: LoraPacket, NwkSKey?: Buffer, AppKey?: Buffer, FCntMSBytes?: Buffer): boolean {
  if (payload.MIC && payload.MIC.length !== 4) throw new Error("Expected a payload payload.MIC with length 4");

  const calculated = calculateMIC(payload, NwkSKey, AppKey, FCntMSBytes);
  if (!payload.MIC) return false;
  return Buffer.compare(payload.MIC, calculated) === 0;
}

// calculate MIC & store
function recalculateMIC(payload: LoraPacket, NwkSKey?: Buffer, AppKey?: Buffer, FCntMSBytes?: Buffer): void {
  const calculated = calculateMIC(payload, NwkSKey, AppKey, FCntMSBytes);
  payload.MIC = calculated;
  if (!payload.MHDR) throw new Error("Missing MHDR");
  if (!payload.MACPayload) throw new Error("Missing MACPayload");
  if (!payload.MIC) throw new Error("Missing MIC");
  if (!payload.MHDR) throw new Error("Missing MHDR");
  payload.PHYPayload = Buffer.concat([payload.MHDR, payload.MACPayload, payload.MIC]);
  payload.MACPayloadWithMIC = payload.PHYPayload.slice(payload.MHDR.length, payload.PHYPayload.length);
}

export { calculateMIC, verifyMIC, recalculateMIC };
