import { generateJSKeys, generateSessionKeys, generateSessionKeys11 } from "../src/lib/crypto";

describe("generate session keys", () => {
  it("should generate valid session keys 1.0", () => {
    const AppKey_hex = "98929b92c49edba9676d646d3b612456";
    const NetID_hex = "aabbcc";
    const AppNonce_hex = "376338";
    const DevNonce_hex = "f18e";
    const sessionKeys = generateSessionKeys(
      Buffer.from(AppKey_hex, "hex"),
      Buffer.from(NetID_hex, "hex"),
      Buffer.from(AppNonce_hex, "hex"),
      Buffer.from(DevNonce_hex, "hex")
    );
    expect(sessionKeys).not.toBeUndefined();
    expect(sessionKeys.NwkSKey.toString("hex")).toBe("4e3d6e6afbcc67af2ba3c8e8ec4acf4b");
    expect(sessionKeys.AppSKey.toString("hex")).toBe("610897aa6f1460623443b527d3ac6a9d");
  });

  it("should generate valid session keys 1.1", () => {
    const AppKey_hex = "98929b92c49edba9676d646d3b612456";
    const NwkKey_hex = "089234b089c2d8490edf8c9f9b8e8f9c";
    const NetID_hex = "aabbcc";
    const AppNonce_hex = "376338";
    const DevNonce_hex = "f18e";
    const sessionKeys = generateSessionKeys11(
      Buffer.from(AppKey_hex, "hex"),
      Buffer.from(NwkKey_hex, "hex"),
      Buffer.from(NetID_hex, "hex"),
      Buffer.from(AppNonce_hex, "hex"),
      Buffer.from(DevNonce_hex, "hex")
    );
    expect(sessionKeys).not.toBeUndefined();
    expect(sessionKeys.FNwkSIntKey.toString("hex")).toBe("71674d0578777d66ecf8218a55ee9dd8");
    expect(sessionKeys.SNwkSIntKey.toString("hex")).toBe("6c8aef5cc7fab065711b96f573664349");
    expect(sessionKeys.NwkSEncKey.toString("hex")).toBe("e0a1bab82aa3874a3489d3a31436c5c5");
    expect(sessionKeys.AppSKey.toString("hex")).toBe("610897aa6f1460623443b527d3ac6a9d");
  });

  it("should generate JS keys", () => {
    const NwkKey_hex = "089234b089c2d8490edf8c9f9b8e8f9c";
    const DevEui_hex = "0123456789abcdef";
    const sessionKeys = generateJSKeys(Buffer.from(NwkKey_hex, "hex"), Buffer.from(DevEui_hex, "hex"));
    expect(sessionKeys).not.toBeUndefined();
    expect(sessionKeys.JSIntKey.toString("hex")).toBe("bd147194430d6fec1351a327ee40e264");
    expect(sessionKeys.JSEncKey.toString("hex")).toBe("8c61658dc01ee8add0c0becf90d2dc50");
  });

  it("should generate valid session keys 1.1 with optNeg Unset", () => {
    const AppKey_hex = "02020202020202020202020202020202";
    const NwkKey_hex = "01010101010101010101010101010101";
    const netId_hex = "600008";
    const AppNonce_hex = "000058";
    const DevNonce_hex = "e8b8";
    const sessionKeys = generateSessionKeys11(
      Buffer.from(AppKey_hex, "hex"),
      Buffer.from(NwkKey_hex, "hex"),
      Buffer.from(netId_hex, "hex"),
      Buffer.from(AppNonce_hex, "hex"),
      Buffer.from(DevNonce_hex, "hex")
    );
    expect(sessionKeys).not.toBeUndefined();
    expect(sessionKeys.FNwkSIntKey.toString("hex")).toBe("f8153baa6d263662a65df022e00c8641");
    expect(sessionKeys.SNwkSIntKey.toString("hex")).toBe("36976db6f2c27cbc308afac29266ff3f");
    expect(sessionKeys.NwkSEncKey.toString("hex")).toBe("f1b65319dc2ee0c923321f5b135b1a33");
    expect(sessionKeys.AppSKey.toString("hex")).toBe("ed98df8fa357f5ac02c2afb6c22f4218");
  });

  it("should generate valid session keys 1.1 Broccar parameters with OptNeg Set", () => {
    const AppKey_hex = "01000000000000000000000000000001";
    const NwkKey_hex = "00000000000000000000000000000001";
    const joinEui_hex = "0000000000000001";
    const AppNonce_hex = "000003";
    const DevNonce_hex = "E8C2";
    const sessionKeys = generateSessionKeys11(
      Buffer.from(AppKey_hex, "hex"),
      Buffer.from(NwkKey_hex, "hex"),
      Buffer.from(joinEui_hex, "hex"),
      Buffer.from(AppNonce_hex, "hex"),
      Buffer.from(DevNonce_hex, "hex")
    );
    expect(sessionKeys).not.toBeUndefined();
    expect(sessionKeys.FNwkSIntKey.toString("hex")).toBe("BBD966509BE6435F4BCB63ACC310466A".toLowerCase());
    expect(sessionKeys.SNwkSIntKey.toString("hex")).toBe("DEA9E621C747AF79A65F82DCAED92A99".toLowerCase());
    expect(sessionKeys.NwkSEncKey.toString("hex")).toBe("C8EEFDA7400395C94AB072E9C353B29D".toLowerCase());
    expect(sessionKeys.AppSKey.toString("hex")).toBe("EB45A0A167B6F1CCCB9A678D761C0B03".toLowerCase());
  });

  it("should generate JS keys in 1.1", () => {
    const NwkKey_hex = "01010101010101010101010101010101";
    const DevEui_hex = "0000000000000001";
    const sessionKeys = generateJSKeys(Buffer.from(NwkKey_hex, "hex"), Buffer.from(DevEui_hex, "hex"));
    expect(sessionKeys).not.toBeUndefined();
    expect(sessionKeys.JSIntKey.toString("hex")).toBe("6b9cc9b000daebb610f1e39758cf69df");
    expect(sessionKeys.JSEncKey.toString("hex")).toBe("c31fa11abb646ee1c21d5835815528ea");
  });
});
