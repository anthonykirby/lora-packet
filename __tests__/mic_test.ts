import LoraPayload from "../src/lib/LoraPacket";
import { calculateMIC, verifyMIC, recalculateMIC } from "../src/lib/mic";

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
});
