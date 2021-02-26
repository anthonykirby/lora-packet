import LoraPayload from "../src/lib/LoraPacket";

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
});
