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

  // https://github.com/brocaar/lorawan/blob/master/phypayload_test.go
  it("should create join accept as in brocaar/lorawan 1.1", () => {
    const appKey = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    const JoinEUI = Buffer.from([8, 7, 6, 5, 4, 3, 2, 1]);

    const packet = LoraPayload.fromFields(
      {
        MType: "Join Accept",
        AppNonce: Buffer.from("010101", "hex"),
        DevNonce: Buffer.from("0102", "hex"),
        AppEUI: JoinEUI,
        NetID: Buffer.from("020202", "hex"),
        DevAddr: Buffer.from("01020304", "hex"),
        DLSettings: Buffer.from([0b10000000]),
        RxDelay: 0,
      },
      null,
      appKey,
      appKey
    );

    expect(packet.PHYPayload.toString("hex")).toStrictEqual(
      Buffer.from("IHq+6gawKSDxHALQNI/PGBU=", "base64").toString("hex")
    );
  });
});
