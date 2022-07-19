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
});
