import LoraPacket, { LorawanVersion } from "./LoraPacket";
import { reverseBuffer } from "./util";

import { AesCmac } from "aes-cmac";
import { Buffer } from "buffer";

// calculate MIC from payload
function calculateMIC(
  payload: LoraPacket,
  NwkSKey?: Buffer, //NwkSKey for DataUP/Down; SNwkSIntKey in data 1.1; SNwkSIntKey in Join 1.1
  AppKey?: Buffer, //AppSKey for DataUP/Down; FNwkSIntKey in data 1.1; JSIntKey in Join 1.1
  FCntMSBytes?: Buffer,
  ConfFCntDownTxDrTxCh?: Buffer
): Buffer {
  let LWVersion: LorawanVersion = LorawanVersion.V1_0;
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
    let fullCmac = new AesCmac(AppKey).calculate(cmacInput);
    if (!(fullCmac instanceof Buffer)) fullCmac = Buffer.from(fullCmac);
    // only first 4 bytes of CMAC are used as MIC
    const MIC = fullCmac.slice(0, 4);

    return MIC;
  } else if (payload.isReJoinRequestMessage()) {
    if (payload.RejoinType[0] === 1 && (!AppKey || AppKey.length !== 16))
      throw new Error("Expected a JSIntKey with length 16");
    if ((payload.RejoinType[0] === 0 || payload.RejoinType[0] === 2) && (!NwkSKey || NwkSKey.length !== 16))
      throw new Error("Expected a SNwkSIntKey with length 16");
    if (AppKey && AppKey.length !== 16) throw new Error("Expected a AppKey with length 16");
    if (!payload.MHDR) throw new Error("Expected MHDR to be defined");
    if (!payload.RejoinType) throw new Error("Expected RejoinType to be defined");
    if (!payload.NetID && !payload.AppEUI) throw new Error("Expected NetID or JoinEUI to be defined");
    if (!payload.DevEUI) throw new Error("Expected DevEUI to be defined");
    if (!payload.RJCount0 && !payload.RJCount1) throw new Error("Expected RJCount0 or RJCount1 to be defined");
    // const msgLen = payload.MHDR.length + payload.AppEUI.length + payload.DevEUI.length + payload.DevNonce.length;

    // CMAC over MHDR | AppEUI | DevEUI | DevNonce
    // the seperate fields are not in little-endian format, use the concatenated field
    const cmacInput = Buffer.concat([payload.MHDR, payload.MACPayload]);

    // CMAC calculation (as RFC4493)
    const calcKey = payload.RejoinType[0] === 1 ? AppKey : NwkSKey;
    let fullCmac = new AesCmac(calcKey).calculate(cmacInput);
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
    if (payload.getDLSettingsOptNeg()) LWVersion = LorawanVersion.V1_1;

    let cmacInput: Buffer = Buffer.alloc(0);

    let cmacKey: Buffer = AppKey;
    if (LWVersion === LorawanVersion.V1_0) {
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

      cmacInput = Buffer.concat([payload.MHDR, payload.MACPayload]);
    } else if (LWVersion === LorawanVersion.V1_1) {
      if (!payload.JoinReqType) throw new Error("Expected JoinReqType to be defined");
      if (!payload.JoinEUI) throw new Error("Expected JoinEUI to be defined");
      if (!payload.DevNonce) throw new Error("Expected DevNonce to be defined");
      if (!NwkSKey || NwkSKey.length !== 16) throw new Error("Expected a NwkSKey with length 16");
      cmacKey = NwkSKey;
      cmacInput = Buffer.concat([
        payload.JoinReqType,
        reverseBuffer(payload.JoinEUI),
        reverseBuffer(payload.DevNonce),
        payload.MHDR,
        payload.MACPayload,
      ]);
    }

    // CMAC calculation (as RFC4493)
    let fullCmac = new AesCmac(cmacKey).calculate(cmacInput);
    if (!(fullCmac instanceof Buffer)) fullCmac = Buffer.from(fullCmac);
    // only first 4 bytes of CMAC are used as MIC
    const MIC = fullCmac.slice(0, 4);

    return MIC;
  } else {
    // ConfFCntDownTxDrTxCh = ConfFCntDownTxDrTxCh || Buffer.alloc(2, 0);
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

    if (ConfFCntDownTxDrTxCh) {
      if (!AppKey || AppKey?.length !== 16) throw new Error("Expected a FNwkSIntKey with length 16");
      LWVersion = LorawanVersion.V1_1;
    }

    // if (NwkSKey && AppKey) {
    //   LWVersion = LorawanVersion.V1_1;
    // }

    let dir;
    const isUplinkAndIs1_1 = payload.getDir() === "up" && LWVersion === LorawanVersion.V1_1;
    const isDownlinkAndIs1_1 = payload.getDir() === "down" && LWVersion === LorawanVersion.V1_1;

    if (payload.getDir() == "up") {
      dir = Buffer.alloc(1, 0);
    } else if (payload.getDir() == "down") {
      dir = Buffer.alloc(1, 1);
      if (!ConfFCntDownTxDrTxCh) {
        ConfFCntDownTxDrTxCh = Buffer.alloc(4, 0);
      } else if (ConfFCntDownTxDrTxCh && ConfFCntDownTxDrTxCh?.length !== 2) {
        throw new Error("Expected a ConfFCntDown with length 2");
      } else {
        ConfFCntDownTxDrTxCh = Buffer.concat([ConfFCntDownTxDrTxCh, Buffer.alloc(2, 0)]);
      }
    } else {
      throw new Error("expecting direction to be either 'up' or 'down'");
    }

    if (isUplinkAndIs1_1) {
      if (!ConfFCntDownTxDrTxCh || ConfFCntDownTxDrTxCh?.length !== 4) {
        throw new Error("Expected a ConfFCntDownTxDrTxCh with length 4 Expected ( ConfFCnt | TxDr | TxCh)");
      }

      if (payload.getFCtrlACK() || (isUplinkAndIs1_1 && payload.getFPort() === 0)) {
        ConfFCntDownTxDrTxCh.writeUInt16BE(ConfFCntDownTxDrTxCh.readUInt16LE(0));
      } else {
        ConfFCntDownTxDrTxCh.writeUInt16BE(0);
      }
    }

    const msgLen = payload.MHDR.length + payload.MACPayload.length;

    const B0 = Buffer.concat([
      Buffer.from([0x49]), // as spec
      isDownlinkAndIs1_1 ? ConfFCntDownTxDrTxCh : Buffer.alloc(4, 0), // LoraWan Spec 1.1, pag. 27
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
    let key = NwkSKey;
    if (isDownlinkAndIs1_1) key = AppKey;
    let fullCmac = new AesCmac(key).calculate(cmacInput);
    if (!(fullCmac instanceof Buffer)) fullCmac = Buffer.from(fullCmac);

    // only first 4 bytes of CMAC are used as MIC
    const MIC = fullCmac.slice(0, 4);

    if (isUplinkAndIs1_1) {
      const B1 = Buffer.concat([
        Buffer.from([0x49]), // as spec
        ConfFCntDownTxDrTxCh, // LoraWan Spec 1.1, pag. 27
        dir, // direction ('Dir')
        reverseBuffer(payload.DevAddr),
        reverseBuffer(payload.FCnt),
        FCntMSBytes, // upper 2 bytes of FCnt (zeroes)
        Buffer.alloc(1, 0), // 0x00
        Buffer.alloc(1, msgLen), // len(msg)
      ]);

      const cmacSInput = Buffer.concat([B1, payload.MHDR, payload.MACPayload]);
      let fullCmacS = new AesCmac(AppKey).calculate(cmacSInput);
      if (!(fullCmacS instanceof Buffer)) fullCmacS = Buffer.from(fullCmacS);

      // only first 2 bytes of CMAC and CMACS are used as MIC
      const MICS = fullCmacS.slice(0, 4);

      return Buffer.concat([MICS.slice(0, 2), MIC.slice(0, 2)]);
    }

    return MIC;
  }
}

// verify is just calculate & compare
function verifyMIC(
  payload: LoraPacket,
  NwkSKey?: Buffer,
  AppKey?: Buffer,
  FCntMSBytes?: Buffer,
  ConfFCntDownTxDrTxCh?: Buffer
): boolean {
  if (payload.MIC && payload.MIC.length !== 4) throw new Error("Expected a payload payload.MIC with length 4");

  const calculated = calculateMIC(payload, NwkSKey, AppKey, FCntMSBytes, ConfFCntDownTxDrTxCh);
  if (!payload.MIC) return false;
  return Buffer.compare(payload.MIC, calculated) === 0;
}

// calculate MIC & store
function recalculateMIC(
  payload: LoraPacket,
  NwkSKey?: Buffer,
  AppKey?: Buffer,
  FCntMSBytes?: Buffer,
  ConfFCntDownTxDrTxCh?: Buffer
): void {
  const calculated = calculateMIC(payload, NwkSKey, AppKey, FCntMSBytes, ConfFCntDownTxDrTxCh);
  payload.MIC = calculated;
  if (!payload.MHDR) throw new Error("Missing MHDR");
  if (!payload.MACPayload) throw new Error("Missing MACPayload");
  if (!payload.MIC) throw new Error("Missing MIC");
  if (!payload.MHDR) throw new Error("Missing MHDR");
  payload.PHYPayload = Buffer.concat([payload.MHDR, payload.MACPayload, payload.MIC]);
  payload.MACPayloadWithMIC = payload.PHYPayload.slice(payload.MHDR.length, payload.PHYPayload.length);
}

export { calculateMIC, verifyMIC, recalculateMIC };
