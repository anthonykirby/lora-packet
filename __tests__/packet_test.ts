import LoraPayload from "../src/lib/LoraPacket";
import { decrypt, decryptFOpts } from "../src/lib/crypto";
import { recalculateMIC } from "../src/lib/mic";

describe("construct packet from fields", () => {
  it("should create packet with minimal input", () => {
    const packet = LoraPayload.fromFields({
      payload: "test",
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
    });

    const expectedPayload = {
      PHYPayload: Buffer.from("40d4c3b2a10000000174657374eeeeeeee", "hex"),
      MACPayloadWithMIC: Buffer.from("d4c3b2a10000000174657374eeeeeeee", "hex"),
      MHDR: Buffer.from("40", "hex"),
      MACPayload: Buffer.from("d4c3b2a10000000174657374", "hex"),
      MIC: Buffer.from("EEEEEEEE", "hex"),
      FOpts: Buffer.alloc(0),
      FCtrl: Buffer.from("00", "hex"),
      FHDR: Buffer.from("d4c3b2a1000000", "hex"),
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      FCnt: Buffer.from("0000", "hex"),
      FPort: Buffer.from("01", "hex"),
      FRMPayload: Buffer.from("test"),
    };
    expect(packet).not.toBeNull();
    expect(packet).not.toBeUndefined();
    expect(packet).toMatchObject(expectedPayload);

    const parsed = LoraPayload.fromWire(expectedPayload.PHYPayload);
    expect(parsed).toMatchObject(expectedPayload);
  });

  it("should omit FPort if no FRMPayload & no FPort supplied", () => {
    const packet = LoraPayload.fromFields({
      payload: "",
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      FCnt: 1,
    });

    const expectedPayload = {
      PHYPayload: Buffer.from("40d4c3b2a1000100eeeeeeee", "hex"),
      MACPayloadWithMIC: Buffer.from("d4c3b2a1000100eeeeeeee", "hex"),
      MHDR: Buffer.from("40", "hex"),
      MACPayload: Buffer.from("d4c3b2a1000100", "hex"),
      MIC: Buffer.from("EEEEEEEE", "hex"),
      FOpts: Buffer.alloc(0),
      FCtrl: Buffer.from("00", "hex"),
      FHDR: Buffer.from("d4c3b2a1000100", "hex"),
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      FCnt: Buffer.from("0001", "hex"),
      FPort: Buffer.alloc(0),
      FRMPayload: Buffer.from(""),
    };
    expect(packet).not.toBeNull;
    expect(packet).toMatchObject(expectedPayload);

    const parsed = LoraPayload.fromWire(expectedPayload.PHYPayload);
    expect(parsed).toMatchObject(expectedPayload);
  });

  it("should create packet with MType as integer", () => {
    const packet = LoraPayload.fromFields({
      payload: "test",
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      MType: 5,
      FCnt: 1,
    });
    const expectedPayload = {
      PHYPayload: Buffer.from("A0d4c3b2a10001000174657374eeeeeeee", "hex"),
      MACPayloadWithMIC: Buffer.from("d4c3b2a10001000174657374eeeeeeee", "hex"),
      MHDR: Buffer.from("A0", "hex"),
      MACPayload: Buffer.from("d4c3b2a10001000174657374", "hex"),
      MIC: Buffer.from("EEEEEEEE", "hex"),
      FOpts: Buffer.alloc(0),
      FCtrl: Buffer.from("00", "hex"),
      FHDR: Buffer.from("d4c3b2a1000100", "hex"),
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      FCnt: Buffer.from("0001", "hex"),
      FPort: Buffer.from("01", "hex"),
      FRMPayload: Buffer.from("test"),
    };
    expect(packet).not.toBeUndefined();
    expect(packet).toMatchObject(expectedPayload);

    const parsed = LoraPayload.fromWire(expectedPayload.PHYPayload);
    expect(parsed).toMatchObject(expectedPayload);
  });

  it("should create packet with MType as string", () => {
    const packet = LoraPayload.fromFields({
      payload: "test",
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      MType: "Confirmed Data Up",
      FCnt: 1,
    });
    const expectedPayload = {
      PHYPayload: Buffer.from("80d4c3b2a10001000174657374eeeeeeee", "hex"),
      MACPayloadWithMIC: Buffer.from("d4c3b2a10001000174657374eeeeeeee", "hex"),
      MHDR: Buffer.from("80", "hex"),
      MACPayload: Buffer.from("d4c3b2a10001000174657374", "hex"),
      MIC: Buffer.from("EEEEEEEE", "hex"),
      FOpts: Buffer.alloc(0),
      FCtrl: Buffer.from("00", "hex"),
      FHDR: Buffer.from("d4c3b2a1000100", "hex"),
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      FCnt: Buffer.from("0001", "hex"),
      FPort: Buffer.from("01", "hex"),
      FRMPayload: Buffer.from("test"),
    };
    expect(packet).not.toBeUndefined;
    expect(packet).toMatchObject(expectedPayload);
    const parsed = LoraPayload.fromWire(expectedPayload.PHYPayload);
    expect(parsed).toMatchObject(expectedPayload);
  });

  it("should verify MType confirmed", () => {
    const packet = LoraPayload.fromFields({
      payload: "test",
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      MType: "Confirmed Data Up",
      FCnt: 1,
    });

    expect(packet.isConfirmed()).toBe(true);
  });

  it("should verify MType unconfirmed", () => {
    const packet = LoraPayload.fromFields({
      payload: "test",
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      MType: "Unconfirmed Data Up",
      FCnt: 1,
    });

    expect(packet.isConfirmed()).toBe(false);
  });

  it("should create packet with FCnt as buffer", () => {
    const packet = LoraPayload.fromFields({
      payload: "test",
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      FCnt: Buffer.from("1234", "hex"),
    });
    const expectedPayload = {
      PHYPayload: Buffer.from("40d4c3b2a10034120174657374eeeeeeee", "hex"),
      MACPayloadWithMIC: Buffer.from("d4c3b2a10034120174657374eeeeeeee", "hex"),
      MHDR: Buffer.from("40", "hex"),
      MACPayload: Buffer.from("d4c3b2a10034120174657374", "hex"),
      MIC: Buffer.from("EEEEEEEE", "hex"),
      FOpts: Buffer.alloc(0),
      FCtrl: Buffer.from("00", "hex"),
      FHDR: Buffer.from("d4c3b2a1003412", "hex"),
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      FCnt: Buffer.from("1234", "hex"),
      FPort: Buffer.from("01", "hex"),
      FRMPayload: Buffer.from("test"),
    };

    expect(packet).not.toBeUndefined();
    expect(packet).toMatchObject(expectedPayload);

    const parsed = LoraPayload.fromWire(expectedPayload.PHYPayload);
    expect(parsed).toMatchObject(expectedPayload);
  });

  it("should create packet with FCnt as number", () => {
    const packet = LoraPayload.fromFields({
      payload: "test",
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      FCnt: 4660,
    });
    const expectedPayload = {
      PHYPayload: Buffer.from("40d4c3b2a10034120174657374eeeeeeee", "hex"),
      MACPayloadWithMIC: Buffer.from("d4c3b2a10034120174657374eeeeeeee", "hex"),
      MHDR: Buffer.from("40", "hex"),
      MACPayload: Buffer.from("d4c3b2a10034120174657374", "hex"),
      MIC: Buffer.from("EEEEEEEE", "hex"),
      FOpts: Buffer.alloc(0),
      FCtrl: Buffer.from("00", "hex"),
      FHDR: Buffer.from("d4c3b2a1003412", "hex"),
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      FCnt: Buffer.from("1234", "hex"),
      FPort: Buffer.from("01", "hex"),
      FRMPayload: Buffer.from("test"),
    };

    expect(packet).not.toBeUndefined();
    expect(packet).toMatchObject(expectedPayload);

    const parsed = LoraPayload.fromWire(expectedPayload.PHYPayload);
    expect(parsed).toMatchObject(expectedPayload);
  });

  it("should create packet with FOpts", () => {
    const packet = LoraPayload.fromFields({
      payload: "test",
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      FOpts: Buffer.from("F0F1F2F3", "hex"),
      FCnt: 1,
    });
    const expectedPayload = {
      PHYPayload: Buffer.from("40d4c3b2a1040100F0F1F2F30174657374eeeeeeee", "hex"),
      MACPayloadWithMIC: Buffer.from("d4c3b2a1040100F0F1F2F30174657374eeeeeeee", "hex"),
      MHDR: Buffer.from("40", "hex"),
      MACPayload: Buffer.from("d4c3b2a1040100F0F1F2F30174657374", "hex"),
      MIC: Buffer.from("EEEEEEEE", "hex"),
      FOpts: Buffer.from("F0F1F2F3", "hex"),
      FCtrl: Buffer.from("04", "hex"),
      FHDR: Buffer.from("d4c3b2a1040100F0F1F2F3", "hex"),
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      FCnt: Buffer.from("0001", "hex"),
      FPort: Buffer.from("01", "hex"),
      FRMPayload: Buffer.from("test"),
    };

    expect(packet).not.toBeUndefined();
    expect(packet).toMatchObject(expectedPayload);

    const parsed = LoraPayload.fromWire(expectedPayload.PHYPayload);
    expect(parsed).toMatchObject(expectedPayload);
  });

  it("should create packet with correct FCtrl.ACK", () => {
    let packet = LoraPayload.fromFields({
      payload: "test",
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      FCtrl: { ACK: true },
    });
    expect(packet.FCtrl).toMatchObject(Buffer.from("20", "hex"));
    expect(packet.getFCtrlACK()).toBe(true);
    packet = LoraPayload.fromFields({
      payload: "test",
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      FCtrl: { ACK: false },
    });
    expect(packet.FCtrl).toMatchObject(Buffer.from("00", "hex"));
    expect(packet.getFCtrlACK()).toBe(false);
  });

  it("should create packet with correct FCtrl.ADR", () => {
    let packet = LoraPayload.fromFields({
      payload: "test",
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      FCtrl: { ADR: true },
    });
    expect(packet.FCtrl).toMatchObject(Buffer.from("80", "hex"));
    expect(packet.getFCtrlADR()).toBe(true);
    packet = LoraPayload.fromFields({
      payload: "test",
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      FCtrl: { ACK: false },
    });
    expect(packet.FCtrl).toMatchObject(Buffer.from("00", "hex"));
    expect(packet.getFCtrlADR()).toBe(false);
  });
  it("should create packet with correct FCtrl when all flags set", () => {
    const packet = LoraPayload.fromFields({
      payload: "test",
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      FCtrl: { ADR: true, ACK: true, ADRACKReq: true, FPending: true },
    });
    expect(packet.FCtrl).toMatchObject(Buffer.from("F0", "hex"));
    expect(packet.getFCtrlADR()).toBe(true);
    expect(packet.getFCtrlADRACKReq()).toBe(true);
    expect(packet.getFCtrlACK()).toBe(true);
    expect(packet.getFCtrlFPending()).toBe(true);
  });

  it("should create join request packet", () => {
    const packet = LoraPayload.fromFields({
      AppEUI: Buffer.from("AABBCCDDAABBCCDD", "hex"),
      DevEUI: Buffer.from("AABBCCDDAABBCCDD", "hex"),
      DevNonce: Buffer.from("AABB", "hex"),
    });
    const expectedPayload = {
      PHYPayload: Buffer.from("00DDCCBBAADDCCBBAADDCCBBAADDCCBBAABBAAeeeeeeee", "hex"),
      MACPayloadWithMIC: Buffer.from("DDCCBBAADDCCBBAADDCCBBAADDCCBBAABBAAeeeeeeee", "hex"),
      MHDR: Buffer.from("00", "hex"),
      MACPayload: Buffer.from("DDCCBBAADDCCBBAADDCCBBAADDCCBBAABBAA", "hex"),
      MIC: Buffer.from("EEEEEEEE", "hex"),
      AppEUI: Buffer.from("AABBCCDDAABBCCDD", "hex"),
      DevEUI: Buffer.from("AABBCCDDAABBCCDD", "hex"),
      DevNonce: Buffer.from("AABB", "hex"),
    };

    expect(packet).not.toBeUndefined();
    expect(packet).toMatchObject(expectedPayload);

    const parsed = LoraPayload.fromWire(expectedPayload.PHYPayload);
    expect(parsed).toMatchObject(expectedPayload);
  });

  it("should create join accept packet with minimal input", () => {
    const packet = LoraPayload.fromFields({
      AppNonce: Buffer.from("AABBCC", "hex"),
      NetID: Buffer.from("AABBCC", "hex"),
      DevAddr: Buffer.from("AABBCCDD", "hex"),
    });
    const expectedPayload = {
      PHYPayload: Buffer.from("20CCBBAACCBBAADDCCBBAA0000eeeeeeee", "hex"),
      MACPayloadWithMIC: Buffer.from("CCBBAACCBBAADDCCBBAA0000eeeeeeee", "hex"),
      MHDR: Buffer.from("20", "hex"),
      MACPayload: Buffer.from("CCBBAACCBBAADDCCBBAA0000", "hex"),
      MIC: Buffer.from("EEEEEEEE", "hex"),
      AppNonce: Buffer.from("AABBCC", "hex"),
      NetID: Buffer.from("AABBCC", "hex"),
      DevAddr: Buffer.from("AABBCCDD", "hex"),
      DLSettings: Buffer.from("00", "hex"),
      RxDelay: Buffer.from("00", "hex"),
      CFList: Buffer.alloc(0),
    };

    expect(packet).not.toBeUndefined();
    expect(packet).toMatchObject(expectedPayload);

    const parsed = LoraPayload.fromWire(expectedPayload.PHYPayload);
    expect(parsed).toMatchObject(expectedPayload);
  });

  it("should create join accept packet", () => {
    const packet = LoraPayload.fromFields({
      AppNonce: Buffer.from("AABBCC", "hex"),
      NetID: Buffer.from("AABBCC", "hex"),
      DevAddr: Buffer.from("AABBCCDD", "hex"),
      DLSettings: Buffer.from("12", "hex"),
      RxDelay: Buffer.from("0F", "hex"),
    });
    const expectedPayload = {
      PHYPayload: Buffer.from("20CCBBAACCBBAADDCCBBAA120Feeeeeeee", "hex"),
      MACPayloadWithMIC: Buffer.from("CCBBAACCBBAADDCCBBAA120Feeeeeeee", "hex"),
      MHDR: Buffer.from("20", "hex"),
      MACPayload: Buffer.from("CCBBAACCBBAADDCCBBAA120F", "hex"),
      MIC: Buffer.from("EEEEEEEE", "hex"),
      AppNonce: Buffer.from("AABBCC", "hex"),
      NetID: Buffer.from("AABBCC", "hex"),
      DevAddr: Buffer.from("AABBCCDD", "hex"),
      DLSettings: Buffer.from("12", "hex"),
      RxDelay: Buffer.from("0F", "hex"),
      CFList: Buffer.alloc(0),
    };

    expect(packet).not.toBeUndefined();
    expect(packet).toMatchObject(expectedPayload);

    const parsed = LoraPayload.fromWire(expectedPayload.PHYPayload);
    expect(parsed).toMatchObject(expectedPayload);
  });

  it("should create join accept packet with CFList", () => {
    const packet = LoraPayload.fromFields({
      AppNonce: Buffer.from("AABBCC", "hex"),
      NetID: Buffer.from("AABBCC", "hex"),
      DevAddr: Buffer.from("AABBCCDD", "hex"),
      DLSettings: Buffer.from("12", "hex"),
      RxDelay: Buffer.from("0F", "hex"),
      CFList: Buffer.from("11223311223311223311223311223300", "hex"),
    });
    const expectedPayload = {
      PHYPayload: Buffer.from("20CCBBAACCBBAADDCCBBAA120F11223311223311223311223311223300eeeeeeee", "hex"),
      MACPayloadWithMIC: Buffer.from("CCBBAACCBBAADDCCBBAA120F11223311223311223311223311223300eeeeeeee", "hex"),
      MHDR: Buffer.from("20", "hex"),
      MACPayload: Buffer.from("CCBBAACCBBAADDCCBBAA120F11223311223311223311223311223300", "hex"),
      MIC: Buffer.from("EEEEEEEE", "hex"),
      AppNonce: Buffer.from("AABBCC", "hex"),
      NetID: Buffer.from("AABBCC", "hex"),
      DevAddr: Buffer.from("AABBCCDD", "hex"),
      DLSettings: Buffer.from("12", "hex"),
      RxDelay: Buffer.from("0F", "hex"),
      CFList: Buffer.from("11223311223311223311223311223300", "hex"),
    };

    expect(packet).not.toBeUndefined();
    expect(packet).toMatchObject(expectedPayload);

    const parsed = LoraPayload.fromWire(expectedPayload.PHYPayload);
    expect(parsed).toMatchObject(expectedPayload);
  });

  it("should create packet with correct FPort", () => {
    const packet = LoraPayload.fromFields({
      payload: "test",
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      FPort: 42,
    });
    expect(packet.getFPort()).toBe(42);
  });

  it("should calculate MIC if keys provided", () => {
    // @ts-ignore
    const packet = LoraPayload.fromFields(
      {
        payload: "test",
        DevAddr: Buffer.from("49be7df1", "hex"),
        FCnt: Buffer.from("0002", "hex"),
      },
      Buffer.from("ec925802ae430ca77fd3dd73cb2cc588", "hex"), // AppSKey
      Buffer.from("44024241ed4ce9a68c6a8bc055233fd3", "hex") // NwkSKey
    );
    const expectedPayload = {
      PHYPayload: Buffer.from("40f17dbe4900020001954378762b11ff0d", "hex"),
      MACPayloadWithMIC: Buffer.from("f17dbe4900020001954378762b11ff0d", "hex"),
      MHDR: Buffer.from("40", "hex"),
      MACPayload: Buffer.from("f17dbe490002000195437876", "hex"),
      MIC: Buffer.from("2b11ff0d", "hex"),
      FOpts: Buffer.alloc(0),
      FCtrl: Buffer.from("00", "hex"),
      FHDR: Buffer.from("f17dbe49000200", "hex"),
      DevAddr: Buffer.from("49be7df1", "hex"),
      FCnt: Buffer.from("0002", "hex"),
      FPort: Buffer.from("01", "hex"),
      FRMPayload: Buffer.from("95437876", "hex"),
    };

    expect(packet).not.toBeUndefined();
    expect(packet).toMatchObject(expectedPayload);

    const parsed = LoraPayload.fromWire(expectedPayload.PHYPayload);
    expect(parsed).toMatchObject(expectedPayload);
  });

  it("should encrypt if keys provided", () => {
    const packet = LoraPayload.fromFields(
      {
        payload: "test",
        DevAddr: Buffer.from("49be7df1", "hex"),
        FCnt: Buffer.from("0002", "hex"),
      },
      Buffer.from("ec925802ae430ca77fd3dd73cb2cc588", "hex"), // AppSKey
      Buffer.from("44024241ed4ce9a68c6a8bc055233fd3", "hex") // NwkSKey
    );
    const expectedPayload = {
      PHYPayload: Buffer.from("40f17dbe4900020001954378762b11ff0d", "hex"),
      MACPayloadWithMIC: Buffer.from("f17dbe4900020001954378762b11ff0d", "hex"),
      MHDR: Buffer.from("40", "hex"),
      MACPayload: Buffer.from("f17dbe490002000195437876", "hex"),
      MIC: Buffer.from("2b11ff0d", "hex"),
      FOpts: Buffer.alloc(0),
      FCtrl: Buffer.from("00", "hex"),
      FHDR: Buffer.from("f17dbe49000200", "hex"),
      DevAddr: Buffer.from("49be7df1", "hex"),
      FCnt: Buffer.from("0002", "hex"),
      FPort: Buffer.from("01", "hex"),
      FRMPayload: Buffer.from("95437876", "hex"),
    };

    expect(packet).not.toBeUndefined();
    expect(packet).toMatchObject(expectedPayload);
    expect(packet.PHYPayload).toMatchObject(expectedPayload.PHYPayload);

    const parsed = LoraPayload.fromWire(expectedPayload.PHYPayload);
    expect(parsed).toMatchObject(expectedPayload);
  });

  it("should parse packet #1", function () {
    const message_hex = "4084412505A3010009110308B33750F504D4B86A";

    const parsed = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    expect(parsed).not.toBeUndefined();
    expect(parsed.FOpts).not.toBeUndefined();
    expect(parsed.FOpts).toMatchObject(Buffer.from("091103", "hex"));
  });

  it("should create packet with port 0 ", () => {
    const NwkSKey_hex = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
    const NwkSKey = Buffer.from(NwkSKey_hex, "hex");

    const packet = LoraPayload.fromFields(
      {
        payload: Buffer.from("02", "hex"),
        DevAddr: Buffer.from("a1b2c3d4", "hex"),
        MType: "Unconfirmed Data Up",
        FPort: 0,
        FCnt: 16,
      },
      undefined,
      NwkSKey
    );

    const expectedPayload = {
      MHDR: Buffer.from("40", "hex"),
      MACPayload: Buffer.from("D4C3B2A10010000027", "hex"),
      FCtrl: Buffer.from("00", "hex"),
      DevAddr: Buffer.from("a1b2c3d4", "hex"),
      FCnt: Buffer.from("0010", "hex"),
      FPort: Buffer.from("00", "hex"),
      FRMPayload: Buffer.from("27", "hex"),
      PHYPayload: Buffer.from("40D4C3B2A1001000002712A3F9C9", "hex"),
      MACPayloadWithMIC: Buffer.from("D4C3B2A1001000002712A3F9C9", "hex"),
      MIC: Buffer.from("12A3F9C9", "hex"),
      FOpts: Buffer.alloc(0),
      FHDR: Buffer.from("D4C3B2A1001000", "hex"),
    };

    expect(packet).toMatchObject(expectedPayload);
  });

  //https://pkg.go.dev/github.com/brocaar/lorawan#example-PHYPayload-Lorawan11JoinAcceptSend
  it("should create packet with OptNeg", () => {
    const NwkKey = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    const joinEUI = Buffer.from([8, 7, 6, 5, 4, 3, 2, 1]);
    const devNonce = Buffer.from([1, 2]);

    const packet = LoraPayload.fromFields(
      {
        MType: "Join Accept",
        AppNonce: Buffer.from("010101", "hex"),
        NetID: Buffer.from("020202", "hex"),
        DevAddr: Buffer.from("01020304", "hex"),
        AppEUI: joinEUI,
        DevNonce: devNonce,
        DLSettings: Buffer.from([0b10000000]), //OptNeg=1,RX2DR=0,RX1DROffset=1
        RxDelay: Buffer.from("00", "hex"),
      },
      undefined,
      NwkKey,
      NwkKey
    );

    const expectedPayload = {
      AppNonce: Buffer.from("010101", "hex"),
      NetID: Buffer.from("020202", "hex"),
      DevAddr: Buffer.from("01020304", "hex"),
      DLSettings: Buffer.from("80", "hex"),
      RxDelay: Buffer.from("00", "hex"),
      JoinReqType: Buffer.from("ff", "hex"),
      AppEUI: Buffer.from("0807060504030201", "hex"),
      DevNonce: Buffer.from("0102", "hex"),
      CFList: Buffer.from("", "hex"),
      MHDR: Buffer.from("20", "hex"),
      MIC: Buffer.from("93ff9a3a", "hex"),
      MACPayload: Buffer.from("010101020202040302018000", "hex"),
      PHYPayload: Buffer.from("207abeea06b02920f11c02d0348fcf1815", "hex"),
      MACPayloadWithMIC: Buffer.from("7abeea06b02920f11c02d0348fcf1815", "hex"),
    };

    expect(packet).toMatchObject(expectedPayload);
  });

  //FROM https://pkg.go.dev/github.com/brocaar/lorawan
  it("should encode packet with Lorawan10 ", () => {
    const nwkSKey = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    const appSKey = Buffer.from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]);
    const fport1 = 10;

    const packet = LoraPayload.fromFields(
      {
        MType: "Confirmed Data Up",
        DevAddr: Buffer.from("01020304", "hex"),
        FPort: fport1,
        FOpts: Buffer.from([0x06, 0x73, 0x07]),
        payload: Buffer.from("01020304", "hex"),
      },
      appSKey,
      nwkSKey
    );

    expect(packet.PHYPayload.toString("hex")).toStrictEqual("80040302010300000673070ae264d4f7e117d2c0");
  });

  //FROM https://github.com/brocaar/lorawan/blob/master/phypayload_test.go

  it("should encode packet with Lorawan11 (1. FRMPayload data)", () => {
    const expectedPacket = Buffer.from([64, 4, 3, 2, 1, 128, 1, 0, 1, 166, 148, 100, 38, 21, 118, 18, 54, 106]);

    const SNwkSIntKey = Buffer.from([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]);
    const FNwkSIntKey = Buffer.from([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3]);
    const NwkSEncKey = Buffer.from([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4]);
    const AppSKey = Buffer.from([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
    const fport1 = 1;
    const confFCnt = Buffer.from([0x00, 0x01]);
    const txDR = Buffer.from([0x02]);
    const txCh = Buffer.from([0x03]);

    const packet = LoraPayload.fromFields(
      {
        MType: "Unconfirmed Data Up",
        DevAddr: Buffer.from("01020304", "hex"),
        FPort: fport1,
        FCnt: 1,
        payload: "hello",
        FCtrl: {
          ADR: true,
        },
      },
      AppSKey,
      FNwkSIntKey,
      SNwkSIntKey,
      undefined,
      Buffer.concat([confFCnt, txDR, txCh])
      //Buffer.alloc(4,0)
    );
    expect(packet.PHYPayload.toString("hex")).toStrictEqual(expectedPacket.toString("hex"));
  });

  it("should encode packet with Lorawan11 (2. FRMPayload data with ACK (in this case the confirmed fCnt is used in the mic))", () => {
    const expectedPacket = Buffer.from([64, 4, 3, 2, 1, 160, 1, 0, 1, 166, 148, 100, 38, 21, 248, 66, 196, 185]);

    const SNwkSIntKey = Buffer.from([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]);
    const FNwkSIntKey = Buffer.from([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3]);
    const NwkSEncKey = Buffer.from([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4]);
    const AppSKey = Buffer.from([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
    const fport1 = 1;
    const confFCnt = Buffer.from([0x00, 0x01]);
    const txDR = Buffer.from([0x02]);
    const txCh = Buffer.from([0x03]);

    const packet = LoraPayload.fromFields(
      {
        MType: "Unconfirmed Data Up",
        DevAddr: Buffer.from("01020304", "hex"),
        FPort: fport1,
        FCnt: 1,
        payload: "hello",
        FCtrl: {
          ADR: true,
          ACK: true,
        },
      },
      AppSKey,
      FNwkSIntKey,
      SNwkSIntKey,
      undefined,
      Buffer.concat([confFCnt, txDR, txCh])
      //Buffer.alloc(4,0)
    );
    expect(packet.PHYPayload.toString("hex")).toStrictEqual(expectedPacket.toString("hex"));
  });

  it("should encode packet with Lorawan11 (3. Mac-commands in FOpts (encrypted, using NFCntDown))", () => {
    const expectedPacket = Buffer.from([96, 4, 3, 2, 1, 3, 0, 0, 223, 180, 241, 226, 79, 31, 159]);

    const SNwkSIntKey = Buffer.from([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]);
    const FNwkSIntKey = Buffer.from([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3]);
    const NwkSEncKey = Buffer.from([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4]);
    const AppSKey = Buffer.from([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);

    const packet = LoraPayload.fromFields(
      {
        MType: "Unconfirmed Data Down",
        DevAddr: Buffer.from("01020304", "hex"),
        FCnt: 0,
        FOpts: Buffer.from([0x02, 0x07, 0x01]),
        payload: Buffer.alloc(0),
      },
      AppSKey,
      SNwkSIntKey,
      FNwkSIntKey,
      undefined,
      undefined
    );

    packet.encryptFOpts(NwkSEncKey, SNwkSIntKey);

    expect(packet.PHYPayload.toString("hex")).toStrictEqual(expectedPacket.toString("hex"));
  });

  it("should encode packet with Lorawan11 (4. Mac-commands in FOpts (encrypted, using AFCntDown encryption flag))", () => {
    const expectedPacket = Buffer.from([96, 4, 3, 2, 1, 3, 0, 0, 2, 7, 1, 1, 119, 112, 30, 163]);

    const SNwkSIntKey = Buffer.from([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]);
    const FNwkSIntKey = Buffer.from([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3]);
    const NwkSEncKey = Buffer.from([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4]);
    const AppSKey = Buffer.from([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);

    const confFCnt = Buffer.from([0x00, 0x00]);
    const fport1 = 1;
    const packet = LoraPayload.fromFields(
      {
        MType: "Unconfirmed Data Down",
        DevAddr: Buffer.from("01020304", "hex"),
        FCnt: 0,
        FPort: fport1,
        FOpts: Buffer.from([0x02, 0x07, 0x01]),
        payload: Buffer.alloc(0),
      },
      AppSKey,
      FNwkSIntKey,
      SNwkSIntKey,
      undefined,
      confFCnt
    );

    expect(packet.PHYPayload.toString("hex")).toStrictEqual(expectedPacket.toString("hex"));
  });

  // https://github.com/brocaar/lorawan/issues/64
  it("should encode packet with Lorawan11 (5. Mac-commands in FRMPayload)", () => {
    const expectedPacket = Buffer.from("400403020100000000f7ded3cc995ea7", "hex");

    const SNwkSIntKey = Buffer.from([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]);
    const FNwkSIntKey = Buffer.from([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3]);
    const NwkSEncKey = Buffer.from([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4]);

    const confFCnt = Buffer.from([0x00, 0x00]);
    const txDR = Buffer.from([0x02]);
    const txCh = Buffer.from([0x03]);

    const macCommands = Buffer.from([0x2, 0x03, 0x5]);

    const fport0 = 0;
    const packet = LoraPayload.fromFields(
      {
        MType: "Unconfirmed Data Up",
        DevAddr: Buffer.from("01020304", "hex"),
        FPort: fport0,
        payload: macCommands,
      },
      NwkSEncKey,
      FNwkSIntKey,
      SNwkSIntKey,
      undefined,
      Buffer.concat([confFCnt, txDR, txCh])
    );

    expect(packet.PHYPayload.toString("hex")).toStrictEqual(expectedPacket.toString("hex"));
    expect(decrypt(packet, null, NwkSEncKey).toString("hex")).toStrictEqual(macCommands.toString("hex"));
  });
});
