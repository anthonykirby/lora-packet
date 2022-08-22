import LoraPayload from "../src/lib/LoraPacket";
import { calculateMIC, verifyMIC, recalculateMIC } from "../src/lib/mic";
import loraPacket from "../src/lib/LoraPacket";

describe("MIC checks", () => {
  it("should calculate & verify correct data packet MIC", () => {
    const message_hex = "40F17DBE4900020001954378762B11FF0D";
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    const NwkSKey_hex = "44024241ed4ce9a68c6a8bc055233fd3";
    const calculatedMIC = calculateMIC(packet, Buffer.from(NwkSKey_hex, "hex"));
    expect(calculatedMIC.toString("hex")).toBe("2b11ff0d");

    expect(verifyMIC(packet, Buffer.from(NwkSKey_hex, "hex"))).toBe(true);
  });

  it("should calculate & verify correct data packet MIC", () => {
    const message_hex = "40F17DBE49000300012A3518AF";
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    const NwkSKey_hex = "44024241ed4ce9a68c6a8bc055233fd3";
    const calculatedMIC = calculateMIC(packet, Buffer.from(NwkSKey_hex, "hex"));
    expect(calculatedMIC.toString("hex")).toBe("2a3518af");

    expect(verifyMIC(packet, Buffer.from(NwkSKey_hex, "hex"))).toBe(true);
  });

  it("should detect incorrect data packet MIC", () => {
    // bodged MIC so it's different
    const message_hex = "40F17DBE49000300012A3518AA"; // aa not af
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    const NwkSKey_hex = "44024241ed4ce9a68c6a8bc055233fd3";
    const calculatedMIC = calculateMIC(packet, Buffer.from(NwkSKey_hex, "hex"));
    expect(calculatedMIC.toString("hex")).toBe("2a3518af");

    expect(verifyMIC(packet, Buffer.from(NwkSKey_hex, "hex"))).toBe(false);
  });

  it("should calculate & verify correct data packet MIC for ACK", () => {
    const message_hex = "60f17dbe4920020001f9d65d27";
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    const NwkSKey_hex = "44024241ed4ce9a68c6a8bc055233fd3";
    const calculatedMIC = calculateMIC(packet, Buffer.from(NwkSKey_hex, "hex"));
    expect(calculatedMIC.toString("hex")).toBe("f9d65d27");

    expect(verifyMIC(packet, Buffer.from(NwkSKey_hex, "hex"))).toBe(true);
  });

  it("recalculateMIC should calculate & overwrite existing data packet MIC", () => {
    const message_hex = "60f17dbe4920020001f9d65d27";
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    // overwrite
    packet.MIC = Buffer.from("EEEEEEEE", "hex");
    expect(packet.MIC).toMatchObject(Buffer.from("EEEEEEEE", "hex"));

    // expect failure
    const NwkSKey = Buffer.from("44024241ed4ce9a68c6a8bc055233fd3", "hex");
    expect(verifyMIC(packet, NwkSKey)).toBe(false);

    // calculate again
    recalculateMIC(packet, NwkSKey);
    expect(verifyMIC(packet, NwkSKey)).toBe(true);
    expect(packet.MIC).toMatchObject(Buffer.from("f9d65d27", "hex"));
  });

  it("recalculateMIC should calculate & overwrite existing data packet MIC and Update PHYpayload & MACPayloadWithMIC", () => {
    const message_hex = "40f17dbe490002000195437876eeeeeeee";
    const exprected_PHYPayload = "40f17dbe4900020001954378762b11ff0d";
    const expected_MACPayloadWithMIC = "f17dbe4900020001954378762b11ff0d";
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    expect(packet.MIC).toMatchObject(Buffer.from("EEEEEEEE", "hex"));

    // expect failure
    const NwkSKey = Buffer.from("44024241ed4ce9a68c6a8bc055233fd3", "hex");
    expect(verifyMIC(packet, NwkSKey)).toBe(false);

    // calculate again
    recalculateMIC(packet, NwkSKey);
    expect(verifyMIC(packet, NwkSKey)).toBe(true);
    expect(packet.MIC).toMatchObject(Buffer.from("2b11ff0d", "hex"));
    expect(packet.PHYPayload).toMatchObject(Buffer.from(exprected_PHYPayload, "hex"));
    expect(packet.MACPayloadWithMIC).toMatchObject(Buffer.from(expected_MACPayloadWithMIC, "hex"));
  });

  it("should calculate & verify correct join request packet MIC", () => {
    const message_hex = "0039363463336913AA05693574323831330489C65B1304";
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    const AppKey_hex = "98929b92c49edba9676d646d3b612456";
    const calculatedMIC = calculateMIC(packet, undefined, Buffer.from(AppKey_hex, "hex"));
    expect(calculatedMIC.toString("hex")).toBe("c65b1304");

    expect(verifyMIC(packet, undefined, Buffer.from(AppKey_hex, "hex"))).toBe(true);
  });

  it("should detect incorrect join request packet MIC", () => {
    // bodged MIC so it's different
    const message_hex = "0039363463336913AA05693574323831330489C65B1305"; // 05 not 04
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    const AppKey_hex = "98929b92c49edba9676d646d3b612456";
    const calculatedMIC = calculateMIC(packet, undefined, Buffer.from(AppKey_hex, "hex"));
    expect(calculatedMIC.toString("hex")).toBe("c65b1304");

    expect(verifyMIC(packet, undefined, Buffer.from(AppKey_hex, "hex"))).toBe(false);
  });

  it("should calculate & verify correct join accept packet MIC", () => {
    const message_hex = "20386337CCBBAAE7CD2C010000D9D0A6E7"; // not encrypted
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    const AppKey_hex = "98929b92c49edba9676d646d3b612456";
    const calculatedMIC = calculateMIC(packet, undefined, Buffer.from(AppKey_hex, "hex"));
    expect(calculatedMIC.toString("hex")).toBe("d9d0a6e7");

    expect(verifyMIC(packet, undefined, Buffer.from(AppKey_hex, "hex"))).toBe(true);
  });

  it("should detect incorrect join accept packet MIC", () => {
    // bodged MIC so it's different
    const message_hex = "20386337CCBBAAE7CD2C010000D9D0A6E8"; // E8 not E7, not encrypted
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    const AppKey_hex = "98929b92c49edba9676d646d3b612456";
    const calculatedMIC = calculateMIC(packet, undefined, Buffer.from(AppKey_hex, "hex"));
    expect(calculatedMIC.toString("hex")).toBe("d9d0a6e7");

    expect(verifyMIC(packet, undefined, Buffer.from(AppKey_hex, "hex"))).toBe(false);
  });

  it("should calculate & verify MIC when 32-bit FCnts are used", () => {
    const message_hex = "40F17DBE4900020001954378762B11FF0D";
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    const NwkSKey_hex = "44024241ed4ce9a68c6a8bc055233fd3";
    const calculatedMIC = calculateMIC(packet, Buffer.from(NwkSKey_hex, "hex"), undefined, Buffer.from("0000", "hex"));
    expect(calculatedMIC.toString("hex")).toBe("2b11ff0d");

    expect(verifyMIC(packet, Buffer.from(NwkSKey_hex, "hex"), undefined, Buffer.from("0000", "hex"))).toBe(true);
  });

  it("should calculate & verify MIC in port 0", () => {
    const message_hex = "4006DC00FCC07400000244925050";
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    const NwkSKey_hex = "581c4d08ef04cda30b1fef7a8b2c74b8";
    const calculatedMIC = calculateMIC(packet, Buffer.from(NwkSKey_hex, "hex"), undefined, Buffer.from("0000", "hex"));
    expect(calculatedMIC.toString("hex")).toBe("44925050");

    expect(verifyMIC(packet, Buffer.from(NwkSKey_hex, "hex"), undefined, Buffer.from("0000", "hex"))).toBe(true);
  });

  it("should calculate & verify MIC when 1.0 are used (Matteo Packets)", () => {
    const message_hex = "40F7EC10E081000002015A171220B0C6D6470FC3";
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    const NwkSKey = "17da125f3d55b28cc16a8111bd1d6c0b";
    const AppKey = "29b27ce00db3957660e7a2f5f47c016f";

    const calculatedMIC = calculateMIC(
      packet,
      Buffer.from(NwkSKey, "hex"),
      Buffer.from(AppKey, "hex"),
      Buffer.from("0000", "hex")
    );

    expect(calculatedMIC.toString("hex")).toBe("D6470FC3".toLowerCase());
    // }

    // const calculatedMIC = calculateMIC(packet, Buffer.from(SNwkSIntKey_hex, "hex"), Buffer.from(FNwkSIntKey_hex, "hex"), Buffer.from("0000", "hex"), ConfFCntDownTxDrTxCh);
    // expect(calculatedMIC.toString("hex")).toBe("67349eae");

    //expect(verifyMIC(packet, Buffer.from(SNwkSIntKey_hex, "hex"), Buffer.from(FNwkSIntKey_hex, "hex"), Buffer.from("0000", "hex"))).toBe(true);
  });

  it("should calculate & verify correct join request packet MIC in 1.1", () => {
    const message_hex = "00010000000000000001000000000000000ce83685eb17";
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    const nwkKey_hex = "01010101010101010101010101010101";
    const calculatedMIC = calculateMIC(packet, undefined, Buffer.from(nwkKey_hex, "hex"));
    expect(calculatedMIC.toString("hex")).toBe("3685eb17");
    expect(verifyMIC(packet, undefined, Buffer.from(nwkKey_hex, "hex"))).toBe(true);
  });

  it("should calculate & verify incorrect join request packet MIC in 1.1", () => {
    const message_hex = "00010000000000000001000000000000000ce83685eb17";
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    const appKey_hex = "02020202020202020202020202020202";
    const calculatedMIC = calculateMIC(packet, undefined, Buffer.from(appKey_hex, "hex"));
    expect(calculatedMIC.toString("hex")).not.toBe("3685eb17");
    expect(verifyMIC(packet, undefined, Buffer.from(appKey_hex, "hex"))).not.toBe(true);
  });

  it("should calculate & verify correct unconfirmed data up packet MIC 1.1", () => {
    const message_hex = "40736310e080000000c86c36165131";
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    const FNwkSIntKey_hex = Buffer.from("e163635133105cc690cb2d57ba9c31b9", "hex");
    const SNwkSIntKey_hex = Buffer.from("05ec7c795b2f0b5bcdfa710db52b9d8f", "hex");

    const calculatedMIC = calculateMIC(
      packet,
      FNwkSIntKey_hex,
      SNwkSIntKey_hex,
      Buffer.from("0000", "hex"),
      Buffer.from("00000001", "hex")
    );
    expect(calculatedMIC.toString("hex")).toBe("36165131");

    expect(
      verifyMIC(packet, FNwkSIntKey_hex, SNwkSIntKey_hex, Buffer.from("0000", "hex"), Buffer.from("00000001", "hex"))
    ).toBe(true);
  });
});
