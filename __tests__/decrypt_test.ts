import LoraPayload from "../src/lib/LoraPacket";
import { decrypt } from "../src/lib/crypto";

describe("decrypt example packet", () => {
  it("should decrypt test payload", () => {
    const message_hex = "40F17DBE4900020001954378762B11FF0D";
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    const AppSKey_hex = "ec925802ae430ca77fd3dd73cb2cc588";
    const decrypted = decrypt(packet, Buffer.from(AppSKey_hex, "hex"));
    expect(decrypted).not.toBeUndefined();
    expect(decrypted.toString()).toBe("test");
  });
  it("should decrypt large payload", () => {
    const message_hex =
      "40f17dbe490004000155332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a20af3c5e7";
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    const AppSKey_hex = "ec925802ae430ca77fd3dd73cb2cc588";
    const decrypted = decrypt(packet, Buffer.from(AppSKey_hex, "hex"));
    expect(decrypted).not.toBeUndefined();
    expect(decrypted.toString()).toBe("The quick brown fox jumps over the lazy dog.");
  });

  it("bad key scrambles payload", () => {
    const message_hex = "40F17DBE4900020001954378762B11FF0D";
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    const AppSKey_hex = "ec925802ae430ca77fd3dd73cb2cc580";
    const decrypted = decrypt(packet, Buffer.from(AppSKey_hex, "hex"));
    expect(decrypted).not.toBeUndefined();
    expect(decrypted.toString("hex")).toBe("5999fc3f");
  });

  it("bad data lightly scrambles payload", () => {
    const message_hex = "40F17DBE4900020001954478762B11FF0D";
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    const AppSKey_hex = "ec925802ae430ca77fd3dd73cb2cc588";
    const decrypted = decrypt(packet, Buffer.from(AppSKey_hex, "hex"));
    expect(decrypted).not.toBeUndefined();
    expect(decrypted.toString()).toBe("tbst");
  });

  it("Should Decode Port 0 ", () => {
    const NwkSKey_hex = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
    const NwkSKey = Buffer.from(NwkSKey_hex, "hex");

    const packet = LoraPayload.fromFields(
      {
        payload: Buffer.from("02", "hex"),
        DevAddr: Buffer.from("a1b2c3d4", "hex"),
        MType: "Unconfirmed Data Up",
        FPort: 0,
        FCnt: 10,
      },
      undefined,
      NwkSKey
    );

    const decrypted = decrypt(packet, undefined, NwkSKey);
    expect(decrypted.toString("hex")).toBe("02");
  });
});
