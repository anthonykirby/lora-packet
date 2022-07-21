import { reverseBuffer, asHexString } from "./util";
import { decrypt, decryptJoin, decryptFOpts } from "./crypto";
import { recalculateMIC } from "./mic";
import { Buffer } from "buffer";

enum MType {
  JOIN_REQUEST,
  JOIN_ACCEPT,
  UNCONFIRMED_DATA_UP,
  UNCONFIRMED_DATA_DOWN,
  CONFIRMED_DATA_UP,
  CONFIRMED_DATA_DOWN,
  REJOIN_REQUEST,
}

enum LorawanVersion {
  V1_0 = "1.0",
  V1_1 = "1.1",
}
enum Constants {
  FCTRL_ADR = 0x80,
  FCTRL_ADRACKREQ = 0x40,
  FCTRL_ACK = 0x20,
  FCTRL_FPENDING = 0x10,
  DLSETTINGS_RXONEDROFFSET_MASK = 0x70,
  DLSETTINGS_RXONEDROFFSET_POS = 4,
  DLSETTINGS_RXTWODATARATE_MASK = 0x0f,
  DLSETTINGS_RXTWODATARATE_POS = 0,
  DLSETTINGS_OPTNEG_MASK = 0x80,
  DLSETTINGS_OPTNEG_POS = 7,
  RXDELAY_DEL_MASK = 0x0f,
  RXDELAY_DEL_POS = 0,
}

const MTYPE_DESCRIPTIONS = [
  "Join Request",
  "Join Accept",
  "Unconfirmed Data Up",
  "Unconfirmed Data Down",
  "Confirmed Data Up",
  "Confirmed Data Down",
  "Rejoin Request",
  "Proprietary",
];

export interface IUserFields {
  CFList?: Buffer;
  RxDelay?: Buffer | number;
  DLSettings?: Buffer | number;
  NetID?: Buffer;
  AppNonce?: Buffer;
  DevNonce?: Buffer;
  DevEUI?: Buffer;
  AppEUI?: Buffer;
  FPort?: number;
  FOpts?: string | Buffer;
  FCnt?: number | Buffer;
  MType?: string | number;
  DevAddr?: Buffer;
  payload?: string | Buffer;
  FCtrl?: {
    ADR?: boolean;
    ADRACKReq?: boolean;
    ACK?: boolean;
    FPending?: boolean;
  };
  JoinReqType?: Buffer | number;
}

class LoraPacket {
  static fromWire(buffer: Buffer): LoraPacket {
    const payload = new LoraPacket();
    payload._initfromWire(buffer);
    return payload;
  }

  static fromFields(
    fields: IUserFields,
    AppSKey?: Buffer,
    NwkSKey?: Buffer,
    AppKey?: Buffer,
    FCntMSBytes?: Buffer,
    ConfFCntDownTxDrTxCh?: Buffer
  ): LoraPacket {
    if (!FCntMSBytes) FCntMSBytes = Buffer.alloc(2, 0);
    const payload = new LoraPacket();

    payload._initFromFields(fields);
    if (payload.isDataMessage()) {
      // to encrypt, need NwkSKey if port=0, else AppSKey

      const port = payload.getFPort();

      if (port != null && ((port === 0 && NwkSKey?.length === 16) || (port > 0 && AppSKey?.length === 16))) {
        // crypto is reversible (just XORs FRMPayload), so we can
        //  just do "decrypt" on the plaintext to get ciphertext

        let ciphertext: Buffer;
        if (port === 0 && NwkSKey?.length === 16 && AppSKey?.length === 16 && AppKey?.length === 16) {
          ciphertext = decrypt(payload, undefined, AppSKey, FCntMSBytes);
        } else {
          ciphertext = decrypt(payload, AppSKey, NwkSKey, FCntMSBytes);
        }

        // overwrite payload with ciphertext
        payload.FRMPayload = ciphertext;
        // recalculate buffers to be ready for MIC calc'n
        payload._mergeGroupFields();
        if (NwkSKey?.length === 16) {
          recalculateMIC(payload, NwkSKey, AppKey, FCntMSBytes, ConfFCntDownTxDrTxCh);
          payload._mergeGroupFields();
        }
      }
    } else if (payload._getMType() === MType.JOIN_REQUEST) {
      if (AppKey?.length === 16) {
        recalculateMIC(payload, NwkSKey, AppKey, FCntMSBytes);
        payload._mergeGroupFields();
      }
    } else if (payload._getMType() === MType.JOIN_ACCEPT) {
      if (AppKey?.length === 16) {
        recalculateMIC(payload, NwkSKey, AppKey, FCntMSBytes);
        payload._mergeGroupFields();
        const ciphertext = decryptJoin(payload, AppKey);
        // overwrite payload with ciphertext
        if (payload.MACPayloadWithMIC) ciphertext.copy(payload.MACPayloadWithMIC);
      }
    }

    return payload;
  }

  private _initfromWire(contents: Buffer): void {
    const incoming = Buffer.from(contents);

    this.PHYPayload = incoming;

    this.MHDR = incoming.slice(0, 1);
    this.MACPayload = incoming.slice(1, incoming.length - 4);
    this.MACPayloadWithMIC = incoming.slice(1, incoming.length);
    this.MIC = incoming.slice(incoming.length - 4);

    const mtype = this._getMType();

    if (mtype == MType.JOIN_REQUEST) {
      this.AppEUI = reverseBuffer(incoming.slice(1, 1 + 8));
      this.DevEUI = reverseBuffer(incoming.slice(9, 9 + 8));
      this.DevNonce = reverseBuffer(incoming.slice(17, 17 + 2));
    } else if (mtype == MType.JOIN_ACCEPT) {
      this.AppNonce = reverseBuffer(incoming.slice(1, 1 + 3));
      this.NetID = reverseBuffer(incoming.slice(4, 4 + 3));
      this.DevAddr = reverseBuffer(incoming.slice(7, 7 + 4));
      this.DLSettings = incoming.slice(11, 11 + 1);
      this.RxDelay = incoming.slice(12, 12 + 1);
      this.JoinReqType = Buffer.from([0xff]);

      if (incoming.length == 13 + 16 + 4) {
        this.CFList = incoming.slice(13, 13 + 16);
      } else {
        this.CFList = Buffer.alloc(0);
      }
    } else if (mtype == MType.REJOIN_REQUEST) {
      this.RejoinType = incoming.slice(1, 1 + 1);
      if (this.RejoinType[0] === 0 || this.RejoinType[0] === 2) {
        this.NetID = reverseBuffer(incoming.slice(2, 2 + 3));
        this.DevEUI = reverseBuffer(incoming.slice(5, 5 + 8));
        this.RJCount0 = reverseBuffer(incoming.slice(13, 13 + 2));
      } else if (this.RejoinType[0] === 1) {
        this.JoinEUI = reverseBuffer(incoming.slice(2, 2 + 8));
        this.DevEUI = reverseBuffer(incoming.slice(10, 10 + 8));
        this.RJCount1 = reverseBuffer(incoming.slice(13, 13 + 2));
      }
    } else if (this.isDataMessage()) {
      this.FCtrl = this.MACPayload.slice(4, 5);
      const FCtrl = this.FCtrl.readInt8(0);
      const FOptsLen = FCtrl & 0x0f;
      this.FOpts = this.MACPayload.slice(7, 7 + FOptsLen);
      const FHDR_length = 7 + FOptsLen;
      this.FHDR = this.MACPayload.slice(0, 0 + FHDR_length);
      this.DevAddr = reverseBuffer(this.FHDR.slice(0, 4));

      this.FCnt = reverseBuffer(this.FHDR.slice(5, 7));

      if (FHDR_length == this.MACPayload.length) {
        this.FPort = Buffer.alloc(0);
        this.FRMPayload = Buffer.alloc(0);
      } else {
        this.FPort = this.MACPayload.slice(FHDR_length, FHDR_length + 1);
        this.FRMPayload = this.MACPayload.slice(FHDR_length + 1);
      }
    }
  }

  private _initFromFields(userFields: IUserFields): void {
    if (typeof userFields.MType !== "undefined") {
      let MTypeNo;
      if (typeof userFields.MType === "number") {
        MTypeNo = userFields.MType;
      } else if (typeof userFields.MType == "string") {
        const mhdr_idx = MTYPE_DESCRIPTIONS.indexOf(userFields.MType);
        if (mhdr_idx >= 0) {
          MTypeNo = mhdr_idx;
        } else {
          throw new Error("MType is unknown");
        }
      } else {
        throw new Error("MType is required in a suitable format");
      }

      if (MTypeNo == MType.JOIN_REQUEST) {
        this._initialiseJoinRequestPacketFromFields(userFields);
      } else if (MTypeNo == MType.JOIN_ACCEPT) {
        this._initialiseJoinAcceptPacketFromFields(userFields);
      } else {
        this._initialiseDataPacketFromFields(userFields);
      }
    } else {
      if (userFields.DevAddr && typeof userFields.payload !== "undefined") {
        this._initialiseDataPacketFromFields(userFields);
      } else if (userFields.AppEUI && userFields.DevEUI && userFields.DevNonce) {
        this._initialiseJoinRequestPacketFromFields(userFields);
      } else if (userFields.AppNonce && userFields.NetID && userFields.DevAddr) {
        this._initialiseJoinAcceptPacketFromFields(userFields);
      } else {
        throw new Error("No plausible packet");
      }
    }
  }

  private _mergeGroupFields(): void {
    if (this.MHDR && this.MIC) {
      if (this._getMType() === MType.JOIN_REQUEST && this.AppEUI && this.DevEUI && this.DevNonce) {
        this.MACPayload = Buffer.concat([
          reverseBuffer(this.AppEUI),
          reverseBuffer(this.DevEUI),
          reverseBuffer(this.DevNonce),
        ]);
        this.PHYPayload = Buffer.concat([this.MHDR, this.MACPayload, this.MIC]);
        this.MACPayloadWithMIC = this.PHYPayload.slice(this.MHDR.length, this.PHYPayload.length);
      } else if (
        this._getMType() === MType.JOIN_ACCEPT &&
        this.AppNonce &&
        this.NetID &&
        this.DevAddr &&
        this.DLSettings &&
        this.RxDelay &&
        this.CFList
      ) {
        this.MACPayload = Buffer.concat([
          reverseBuffer(this.AppNonce),
          reverseBuffer(this.NetID),
          reverseBuffer(this.DevAddr),
          this.DLSettings,
          this.RxDelay,
          this.CFList,
        ]);
        this.PHYPayload = Buffer.concat([this.MHDR, this.MACPayload, this.MIC]);
        this.MACPayloadWithMIC = this.PHYPayload.slice(this.MHDR.length, this.PHYPayload.length);
      } else if (this.FCtrl && this.DevAddr && this.FPort && this.FCnt && this.FRMPayload && this.FOpts) {
        this.FHDR = Buffer.concat([reverseBuffer(this.DevAddr), this.FCtrl, reverseBuffer(this.FCnt), this.FOpts]);
        this.MACPayload = Buffer.concat([this.FHDR, this.FPort, this.FRMPayload]);
        this.PHYPayload = Buffer.concat([this.MHDR, this.MACPayload, this.MIC]);
        this.MACPayloadWithMIC = this.PHYPayload.slice(this.MHDR.length, this.PHYPayload.length);
      }
    }
  }

  private _initialiseDataPacketFromFields(userFields: IUserFields): void {
    if (userFields.DevAddr && userFields.DevAddr.length == 4) {
      this.DevAddr = Buffer.from(userFields.DevAddr);
    } else {
      throw new Error("DevAddr is required in a suitable format");
    }

    if (typeof userFields.payload === "string") {
      this.FRMPayload = Buffer.from(userFields.payload);
    } else if (userFields.payload instanceof Buffer) {
      this.FRMPayload = Buffer.from(userFields.payload);
    }

    if (typeof userFields.MType !== "undefined") {
      if (typeof userFields.MType === "number") {
        this.MHDR = Buffer.alloc(1);
        this.MHDR.writeUInt8(userFields.MType << 5, 0);
      } else if (typeof userFields.MType === "string") {
        const mhdr_idx = MTYPE_DESCRIPTIONS.indexOf(userFields.MType);
        if (mhdr_idx >= 0) {
          this.MHDR = Buffer.alloc(1);
          this.MHDR.writeUInt8(mhdr_idx << 5, 0);
        } else {
          throw new Error("MType is unknown");
        }
      } else {
        throw new Error("MType is required in a suitable format");
      }
    }

    if (userFields.FCnt) {
      if (userFields.FCnt instanceof Buffer && userFields.FCnt.length == 2) {
        this.FCnt = Buffer.from(userFields.FCnt);
      } else if (typeof userFields.FCnt === "number") {
        this.FCnt = Buffer.alloc(2);
        this.FCnt.writeUInt16BE(userFields.FCnt, 0);
      } else {
        throw new Error("FCnt is required in a suitable format");
      }
    }

    if (typeof userFields.FOpts !== "undefined") {
      if (typeof userFields.FOpts === "string") {
        this.FOpts = Buffer.from(userFields.FOpts, "hex");
      } else if (userFields.FOpts instanceof Buffer) {
        this.FOpts = Buffer.from(userFields.FOpts);
      } else {
        throw new Error("FOpts is required in a suitable format");
      }
      if (15 < this.FOpts.length) {
        throw new Error("Too many options for piggybacking");
      }
    } else {
      this.FOpts = Buffer.from("", "hex");
    }

    let fctrl = 0;
    if (userFields.FCtrl?.ADR) {
      fctrl |= Constants.FCTRL_ADR;
    }
    if (userFields.FCtrl?.ADRACKReq) {
      fctrl |= Constants.FCTRL_ADRACKREQ;
    }
    if (userFields.FCtrl?.ACK) {
      fctrl |= Constants.FCTRL_ACK;
    }
    if (userFields.FCtrl?.FPending) {
      fctrl |= Constants.FCTRL_FPENDING;
    }

    fctrl |= this.FOpts.length & 0x0f;
    this.FCtrl = Buffer.alloc(1);
    this.FCtrl.writeUInt8(fctrl, 0);

    if (!isNaN(userFields.FPort) && userFields.FPort >= 0 && userFields.FPort <= 255) {
      this.FPort = Buffer.alloc(1);
      this.FPort.writeUInt8(userFields.FPort, 0);
    }

    if (!this?.MHDR) {
      this.MHDR = Buffer.alloc(1);
      this.MHDR.writeUInt8(MType.UNCONFIRMED_DATA_UP << 5, 0);
    }

    if (this?.FPort == null) {
      if (this?.FRMPayload && this.FRMPayload.length > 0) {
        this.FPort = Buffer.from("01", "hex");
      } else {
        this.FPort = Buffer.alloc(0);
      }
    }

    if (!this?.FPort == null) {
      this.FPort = Buffer.from("01", "hex");
    }

    if (!this.FCnt) {
      this.FCnt = Buffer.from("0000", "hex");
    }

    if (!this.MIC) {
      this.MIC = Buffer.from("EEEEEEEE", "hex");
    }

    this._mergeGroupFields();
  }

  private _initialiseJoinRequestPacketFromFields(userFields: IUserFields): void {
    if (userFields.AppEUI && userFields.AppEUI.length == 8) {
      this.AppEUI = Buffer.from(userFields.AppEUI);
    } else {
      throw new Error("AppEUI is required in a suitable format");
    }

    if (userFields.DevEUI && userFields.DevEUI.length == 8) {
      this.DevEUI = Buffer.from(userFields.DevEUI);
    } else {
      throw new Error("DevEUI is required in a suitable format");
    }

    if (userFields.DevNonce && userFields.DevNonce.length == 2) {
      this.DevNonce = Buffer.from(userFields.DevNonce);
    } else {
      throw new Error("DevNonce is required in a suitable format");
    }

    if (userFields.FCnt) {
      if (userFields.FCnt instanceof Buffer && userFields.FCnt.length == 2) {
        this.FCnt = Buffer.from(userFields.FCnt);
      } else if (typeof userFields.FCnt === "number") {
        this.FCnt = Buffer.alloc(2);
        this.FCnt.writeUInt16BE(userFields.FCnt, 0);
      } else {
        throw new Error("FCnt is required in a suitable format");
      }
    }
    this.MHDR = Buffer.alloc(1);
    this.MHDR.writeUInt8(MType.JOIN_REQUEST << 5, 0);

    if (!this.MIC) {
      this.MIC = Buffer.from("EEEEEEEE", "hex");
    }

    this._mergeGroupFields();
  }

  private _initialiseJoinAcceptPacketFromFields(userFields: IUserFields): void {
    if (userFields.AppNonce && userFields.AppNonce.length == 3) {
      this.AppNonce = Buffer.from(userFields.AppNonce);
    } else {
      throw new Error("AppNonce is required in a suitable format");
    }

    if (userFields.NetID && userFields.NetID.length == 3) {
      this.NetID = Buffer.from(userFields.NetID);
    } else {
      throw new Error("NetID is required in a suitable format");
    }

    if (userFields.DevAddr && userFields.DevAddr.length == 4) {
      this.DevAddr = Buffer.from(userFields.DevAddr);
    } else {
      throw new Error("DevAddr is required in a suitable format");
    }

    if (userFields.DLSettings) {
      if (userFields.DLSettings instanceof Buffer && userFields.DLSettings.length == 1) {
        this.DLSettings = Buffer.from(userFields.DLSettings);
      } else if (typeof userFields.DLSettings === "number") {
        this.DLSettings = Buffer.alloc(1);
        this.DLSettings.writeUInt8(userFields.DLSettings, 0);
      } else {
        throw new Error("DLSettings is required in a suitable format");
      }
    }

    if (userFields.RxDelay) {
      if (userFields.RxDelay instanceof Buffer && userFields.RxDelay.length == 1) {
        this.RxDelay = Buffer.from(userFields.RxDelay);
      } else if (typeof userFields.RxDelay == "number") {
        this.RxDelay = Buffer.alloc(1);
        this.RxDelay.writeUInt8(userFields.RxDelay, 0);
      } else {
        throw new Error("RxDelay is required in a suitable format");
      }
    }

    if (userFields.CFList) {
      if (userFields.CFList instanceof Buffer && (userFields.CFList.length == 0 || userFields.CFList.length == 16)) {
        this.CFList = Buffer.from(userFields.CFList);
      } else {
        throw new Error("CFList is required in a suitable format");
      }
    }

    if (!userFields.JoinReqType) {
      this.JoinReqType = Buffer.from("ff", "hex");
    } else {
      if (userFields.JoinReqType instanceof Buffer && userFields.JoinReqType.length == 1) {
        this.JoinReqType = Buffer.from(userFields.JoinReqType);
      } else if (typeof userFields.JoinReqType === "number") {
        this.JoinReqType = Buffer.alloc(1);
        this.JoinReqType.writeUInt8(userFields.JoinReqType, 0);
      } else {
        throw new Error("JoinReqType is required in a suitable format");
      }
    }

    if (userFields.AppEUI && userFields.AppEUI.length == 8) {
      this.AppEUI = Buffer.from(userFields.AppEUI);
    } else if (this.getDLSettingsOptNeg()) {
      throw new Error("AppEUI/JoinEUI is required in a suitable format");
    }

    if (userFields.DevNonce && userFields.DevNonce.length == 2) {
      this.DevNonce = Buffer.from(userFields.DevNonce);
    } else if (this.getDLSettingsOptNeg()) {
      throw new Error("DevNonce is required in a suitable format");
    }

    if (!this.DLSettings) {
      this.DLSettings = Buffer.from("00", "hex");
    }
    if (!this.RxDelay) {
      this.RxDelay = Buffer.from("00", "hex");
    }
    if (!this.CFList) {
      this.CFList = Buffer.from("", "hex");
    }
    this.MHDR = Buffer.alloc(1);
    this.MHDR.writeUInt8(MType.JOIN_ACCEPT << 5, 0);

    if (!this.MIC) {
      this.MIC = Buffer.from("EEEEEEEE", "hex");
    }

    this._mergeGroupFields();
  }

  private _getMType(): number {
    if (this.MHDR) return (this.MHDR.readUInt8(0) & 0xff) >> 5;
    return -1;
  }

  public isDataMessage(): boolean {
    const mtype = this._getMType();
    if (mtype >= MType.UNCONFIRMED_DATA_UP && mtype <= MType.CONFIRMED_DATA_DOWN) return true;
    return false;
  }

  public isConfirmed(): boolean {
    const mtype = this._getMType();
    if (mtype === MType.CONFIRMED_DATA_DOWN || mtype === MType.CONFIRMED_DATA_UP) return true;
    return false;
  }

  /**
   * Provide MType as a string
   */
  public getMType(): string {
    return MTYPE_DESCRIPTIONS[this._getMType()];
  }

  /**
   * Provide Direction as a string
   */
  public getDir(): string | null {
    const mType = this._getMType();
    if (mType > 5) return null;
    if (mType % 2 == 0) return "up";
    return "down";
  }

  /**
   * Provide FPort as a number
   */
  public getFPort(): number | null {
    if (this.FPort && this.FPort.length) return this.FPort.readUInt8(0);
    return null;
  }

  /**
   * Provide FCnt as a number
   */
  public getFCnt(): number | null {
    if (this.FCnt) return this.FCnt.readUInt16BE(0);
    return null;
  }

  /**
   * Provide FCtrl.ACK as a flag
   */
  public getFCtrlACK(): boolean | null {
    if (!this.FCtrl) return null;
    return !!(this.FCtrl.readUInt8(0) & Constants.FCTRL_ACK);
  }

  /**
   * Provide FCtrl.ADR as a flag
   */
  public getFCtrlADR(): boolean | null {
    if (!this.FCtrl) return null;
    return !!(this.FCtrl.readUInt8(0) & Constants.FCTRL_ADR);
  }

  /**
   * Provide FCtrl.ADRACKReq as a flag
   */
  public getFCtrlADRACKReq(): boolean | null {
    if (!this.FCtrl) return null;
    return !!(this.FCtrl.readUInt8(0) & Constants.FCTRL_ADRACKREQ);
  }

  /**
   * Provide FCtrl.FPending as a flag
   */
  public getFCtrlFPending(): boolean | null {
    if (!this.FCtrl) return null;
    return !!(this.FCtrl.readUInt8(0) & Constants.FCTRL_FPENDING);
  }

  /**
   * Provide DLSettings.RX1DRoffset as integer
   */
  public getDLSettingsRxOneDRoffset(): number | null {
    if (!this.DLSettings) return null;
    return (
      (this.DLSettings.readUInt8(0) & Constants.DLSETTINGS_RXONEDROFFSET_MASK) >> Constants.DLSETTINGS_RXONEDROFFSET_POS
    );
  }

  /**
   * Provide DLSettings.RX2DataRate as integer
   */
  public getDLSettingsRxTwoDataRate(): number | null {
    if (!this.DLSettings) return null;
    return (
      (this.DLSettings.readUInt8(0) & Constants.DLSETTINGS_RXTWODATARATE_MASK) >> Constants.DLSETTINGS_RXTWODATARATE_POS
    );
  }

  /**
   * Provide DLSettings.OptNeg as boolean
   */
  public getDLSettingsOptNeg(): boolean | null {
    if (!this.DLSettings) return null;
    return (this.DLSettings.readUInt8(0) & Constants.DLSETTINGS_OPTNEG_MASK) >> Constants.DLSETTINGS_OPTNEG_POS === 1;
  }

  /**
   * Provide RxDelay.Del as integer
   */
  public getRxDelayDel(): number | null {
    if (!this.RxDelay) return null;
    return (this.RxDelay.readUInt8(0) & Constants.RXDELAY_DEL_MASK) >> Constants.RXDELAY_DEL_POS;
  }

  /**
   * Provide CFList.FreqChFour as buffer
   */
  public getCFListFreqChFour(): Buffer {
    if (this.CFList && this.CFList.length === 16) {
      return reverseBuffer(this.CFList.slice(0, 0 + 3));
    } else {
      return Buffer.alloc(0);
    }
  }

  /**
   * Provide CFList.FreqChFive as buffer
   */
  public getCFListFreqChFive(): Buffer {
    if (this.CFList && this.CFList.length === 16) {
      return reverseBuffer(this.CFList.slice(3, 3 + 3));
    } else {
      return Buffer.alloc(0);
    }
  }

  /**
   * Provide CFList.FreqChSix as buffer
   */
  public getCFListFreqChSix(): Buffer {
    if (this.CFList && this.CFList.length === 16) {
      return reverseBuffer(this.CFList.slice(6, 6 + 3));
    } else {
      return Buffer.alloc(0);
    }
  }

  /**
   * Provide CFList.FreqChSeven as buffer
   */
  public getCFListFreqChSeven(): Buffer {
    if (this.CFList && this.CFList.length === 16) {
      return reverseBuffer(this.CFList.slice(9, 9 + 3));
    } else {
      return Buffer.alloc(0);
    }
  }

  /**
   * Provide CFList.FreqChEight as buffer
   */
  public getCFListFreqChEight(): Buffer {
    if (this.CFList && this.CFList.length === 16) {
      return reverseBuffer(this.CFList.slice(12, 12 + 3));
    } else {
      return Buffer.alloc(0);
    }
  }

  public getBuffers() {
    return this;
  }

  public decryptFOpts(
    NwkSEncKey: Buffer,
    NwkSKey?: Buffer,
    FCntMSBytes?: Buffer,
    ConfFCntDownTxDrTxCh?: Buffer
  ): Buffer {
    return this.encryptFOpts(NwkSEncKey, NwkSKey, FCntMSBytes, ConfFCntDownTxDrTxCh);
  }
  public encryptFOpts(
    NwkSEncKey: Buffer,
    SNwkSIntKey?: Buffer,
    FCntMSBytes?: Buffer,
    ConfFCntDownTxDrTxCh?: Buffer
  ): Buffer {
    if (!this.FOpts) return Buffer.alloc(0);
    if (!NwkSEncKey || NwkSEncKey?.length !== 16) throw new Error("NwkSEncKey must be 16 bytes");
    this.FOpts = decryptFOpts(this, NwkSEncKey, FCntMSBytes);
    this._mergeGroupFields();
    if (SNwkSIntKey?.length === 16) {
      recalculateMIC(this, SNwkSIntKey, undefined, FCntMSBytes, ConfFCntDownTxDrTxCh);
      this._mergeGroupFields();
    }
    return this.FOpts;
  }

  public getPHYPayload(): Buffer | void {
    return this.PHYPayload;
  }

  public isJoinRequestMessage() {
    return this._getMType() == MType.JOIN_REQUEST;
  }

  public isReJoinRequestMessage() {
    return this._getMType() == MType.REJOIN_REQUEST;
  }

  public isJoinAcceptMessage() {
    return this._getMType() == MType.JOIN_ACCEPT;
  }

  public toString(): string {
    let msg = "";

    if (this.isJoinRequestMessage()) {
      msg += "          Message Type = Join Request" + "\n";
      msg += "            PHYPayload = " + asHexString(this.PHYPayload).toUpperCase() + "\n";
      msg += "\n";
      msg += "          ( PHYPayload = MHDR[1] | MACPayload[..] | MIC[4] )\n";
      msg += "                  MHDR = " + asHexString(this.MHDR) + "\n";
      msg += "            MACPayload = " + asHexString(this.MACPayload) + "\n";
      msg += "                   MIC = " + asHexString(this.MIC) + "\n";
      msg += "\n";
      msg += "          ( MACPayload = AppEUI[8] | DevEUI[8] | DevNonce[2] )\n";
      msg += "                AppEUI = " + asHexString(this.AppEUI) + "\n";
      msg += "                DevEUI = " + asHexString(this.DevEUI) + "\n";
      msg += "              DevNonce = " + asHexString(this.DevNonce) + "\n";
    } else if (this.isJoinAcceptMessage()) {
      msg += "          Message Type = Join Accept" + "\n";
      msg += "            PHYPayload = " + asHexString(this.PHYPayload).toUpperCase() + "\n";
      msg += "\n";
      msg += "          ( PHYPayload = MHDR[1] | MACPayload[..] | MIC[4] )\n";
      msg += "                  MHDR = " + asHexString(this.MHDR) + "\n";
      msg += "            MACPayload = " + asHexString(this.MACPayload) + "\n";
      msg += "                   MIC = " + asHexString(this.MIC) + "\n";
      msg += "\n";
      msg +=
        "          ( MACPayload = AppNonce[3] | NetID[3] | DevAddr[4] | DLSettings[1] | RxDelay[1] | CFList[0|15] )\n";
      msg += "              AppNonce = " + asHexString(this.AppNonce) + "\n";
      msg += "                 NetID = " + asHexString(this.NetID) + "\n";
      msg += "               DevAddr = " + asHexString(this.DevAddr) + "\n";
      msg += "            DLSettings = " + asHexString(this.DLSettings) + "\n";
      msg += "               RxDelay = " + asHexString(this.RxDelay) + "\n";
      msg += "                CFList = " + asHexString(this.CFList) + "\n";
      msg += "\n";
      msg += "DLSettings.RX1DRoffset = " + this.getDLSettingsRxOneDRoffset() + "\n";
      msg += "DLSettings.RX2DataRate = " + this.getDLSettingsRxTwoDataRate() + "\n";
      msg += "           RxDelay.Del = " + this.getRxDelayDel() + "\n";
      msg += "\n";
      if (this.CFList.length === 16) {
        msg += "              ( CFList = FreqCh4[3] | FreqCh5[3] | FreqCh6[3] | FreqCh7[3] | FreqCh8[3] )\n";
        msg += "               FreqCh4 = " + asHexString(this.getCFListFreqChFour()) + "\n";
        msg += "               FreqCh5 = " + asHexString(this.getCFListFreqChFive()) + "\n";
        msg += "               FreqCh6 = " + asHexString(this.getCFListFreqChSix()) + "\n";
        msg += "               FreqCh7 = " + asHexString(this.getCFListFreqChSeven()) + "\n";
        msg += "               FreqCh8 = " + asHexString(this.getCFListFreqChEight()) + "\n";
      }
    } else if (this.isDataMessage()) {
      msg += "Message Type = Data" + "\n";
      msg += "            PHYPayload = " + asHexString(this.PHYPayload).toUpperCase() + "\n";
      msg += "\n";
      msg += "          ( PHYPayload = MHDR[1] | MACPayload[..] | MIC[4] )\n";
      msg += "                  MHDR = " + asHexString(this.MHDR) + "\n";
      msg += "            MACPayload = " + asHexString(this.MACPayload) + "\n";
      msg += "                   MIC = " + asHexString(this.MIC) + "\n";
      msg += "\n";
      msg += "          ( MACPayload = FHDR | FPort | FRMPayload )\n";
      msg += "                  FHDR = " + asHexString(this.FHDR) + "\n";
      msg += "                 FPort = " + asHexString(this.FPort) + "\n";
      msg += "            FRMPayload = " + asHexString(this.FRMPayload) + "\n";
      msg += "\n";
      msg += "                ( FHDR = DevAddr[4] | FCtrl[1] | FCnt[2] | FOpts[0..15] )\n";
      msg += "               DevAddr = " + asHexString(this.DevAddr) + " (Big Endian)\n";
      msg += "                 FCtrl = " + asHexString(this.FCtrl) + "\n"; //TODO as binary?
      msg += "                  FCnt = " + asHexString(this.FCnt) + " (Big Endian)\n";
      msg += "                 FOpts = " + asHexString(this.FOpts) + "\n";
      msg += "\n";
      msg += "          Message Type = " + this.getMType() + "\n";
      msg += "             Direction = " + this.getDir() + "\n";
      msg += "                  FCnt = " + this.getFCnt() + "\n";
      msg += "             FCtrl.ACK = " + this.getFCtrlACK() + "\n";
      msg += "             FCtrl.ADR = " + this.getFCtrlADR() + "\n";
      if (this._getMType() == MType.CONFIRMED_DATA_DOWN || this._getMType() == MType.UNCONFIRMED_DATA_DOWN) {
        msg += "        FCtrl.FPending = " + this.getFCtrlFPending() + "\n";
      } else {
        msg += "       FCtrl.ADRACKReq = " + this.getFCtrlADRACKReq() + "\n";
      }
    }
    return msg;
  }

  get JoinEUI(): Buffer {
    return this.AppEUI;
  }

  set JoinEUI(v: Buffer) {
    this.AppEUI = v;
  }

  get JoinNonce(): Buffer {
    return this.AppNonce;
  }

  set JoinNonce(v: Buffer) {
    this.AppNonce = v;
  }

  PHYPayload?: Buffer;
  MHDR?: Buffer;
  MACPayload?: Buffer;
  MACPayloadWithMIC?: Buffer;
  AppEUI?: Buffer;
  DevEUI?: Buffer;
  DevNonce?: Buffer;
  MIC?: Buffer;
  AppNonce?: Buffer;
  NetID?: Buffer;
  DevAddr?: Buffer;
  DLSettings?: Buffer;
  RxDelay?: Buffer;
  CFList?: Buffer;
  FCtrl?: Buffer;
  FOpts?: Buffer;
  FCnt?: Buffer;
  FHDR?: Buffer;
  FPort?: Buffer;
  FRMPayload?: Buffer;
  JoinReqType?: Buffer;
  RejoinType?: Buffer;
  RJCount0?: Buffer;
  RJCount1?: Buffer;
}

export default LoraPacket;
export { LorawanVersion };
