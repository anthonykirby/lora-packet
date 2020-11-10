import { decryptJoinAccept } from "../src/lib/crypto";
import LoraPayload from "../src/lib/LoraPacket";

describe("construct join accept from fields and encrypt", () => {
  it("should create join accept packet with zero value", () => {
    const appKey = Buffer.from("00000000000000000000000000000000", "hex");
    const packet = LoraPayload.fromFields(
      {
        AppNonce: Buffer.from("000000", "hex"),
        NetID: Buffer.from("000000", "hex"),
        DevAddr: Buffer.from("00000000", "hex"),
      },
      null,
      null,
      appKey
    );

    const expectedPayloadDecrypted = {
      PHYPayload: Buffer.from("20000000000000000000000000f86f0a91", "hex"),
      MACPayloadWithMIC: Buffer.from("000000000000000000000000f86f0a91", "hex"),
      MHDR: Buffer.from("20", "hex"),
      MACPayload: Buffer.from("000000000000000000000000", "hex"),
      MIC: Buffer.from("f86f0a91", "hex"),
      AppNonce: Buffer.from("000000", "hex"),
      NetID: Buffer.from("000000", "hex"),
      DevAddr: Buffer.from("00000000", "hex"),
      DLSettings: Buffer.from("00", "hex"),
      RxDelay: Buffer.from("00", "hex"),
      CFList: Buffer.alloc(0),
    };

    const expectedPayload = {
      // decrypt("000000000000000000000000f86f0a91")
      PHYPayload: Buffer.from("20e3de108795f776b8037610ef7869b5b3", "hex"),
      MACPayloadWithMIC: Buffer.from("e3de108795f776b8037610ef7869b5b3", "hex"),
      MHDR: Buffer.from("20", "hex"),
      MACPayload: Buffer.from("000000000000000000000000", "hex"),
      // CMAC (20000000000000000000000000)
      MIC: Buffer.from("f86f0a91", "hex"),
      AppNonce: Buffer.from("000000", "hex"),
      NetID: Buffer.from("000000", "hex"),
      DevAddr: Buffer.from("00000000", "hex"),
      DLSettings: Buffer.from("00", "hex"),
      RxDelay: Buffer.from("00", "hex"),
      CFList: Buffer.alloc(0),
    };

    expect(packet).not.toBeUndefined();
    expect(packet).toMatchObject(expectedPayload);

    const parsedEncrypted = LoraPayload.fromWire(expectedPayload.PHYPayload);
    const PHYPayloadDecrypted = decryptJoinAccept(parsedEncrypted, appKey);
    expect(PHYPayloadDecrypted).toMatchObject(expectedPayloadDecrypted.PHYPayload);

    const parsed = LoraPayload.fromWire(PHYPayloadDecrypted);
    expect(parsed).toMatchObject(expectedPayloadDecrypted);
  });
});
