import { generateSessionKeys } from "../src/lib/crypto";

describe("generate session keys", () => {
  it("should generate valid session keys", () => {
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
});
