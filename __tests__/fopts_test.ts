import loraPacket from "../src/lib";
import LoraPayload from "../src/lib/LoraPacket";
import { calculateMIC } from "../src/lib/mic";
import { decrypt, decryptFOpts } from "../src/lib/crypto";

describe("parse packets from github issue #18", () => {
  it("should parse packet #1", () => {
    const message_hex = "4084412505A3010009110308B33750F504D4B86A";

    const parsed = loraPacket.fromWire(Buffer.from(message_hex, "hex"));

    expect(parsed).not.toBeUndefined();
    expect(parsed).not.toBeUndefined();
    expect(parsed.FOpts).not.toBeUndefined();
    expect(parsed.FOpts).toMatchObject(Buffer.from("091103", "hex"));
  });

  //FROM https://pkg.go.dev/github.com/brocaar/lorawan
  it("should encode packet with Lorawan11 Encrypted Fopts", () => {
    const sNwkSIntKey = Buffer.from([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0]);
    const nwkSEncKey = Buffer.from([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 0]);
    const appSKey = Buffer.from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]);
    const fport1 = 1;

    const packet = LoraPayload.fromFields(
      {
        MType: "Unconfirmed Data Down",
        DevAddr: Buffer.from("01020304", "hex"),
        FPort: fport1,
        FOpts: Buffer.from([0x02, 0x07, 0x01]),
        payload: Buffer.from("01020304", "hex"),
      },
      appSKey,
      sNwkSIntKey,
      undefined
    );

    packet.encryptFOpts(nwkSEncKey, sNwkSIntKey);

    const expectedPayload = {
      DevAddr: Buffer.from("01020304", "hex"),
      FRMPayload: Buffer.from("f0b468dd", "hex"),
      MHDR: Buffer.from("60", "hex"),
      FOpts: Buffer.from("22ac0a", "hex"),
      FCtrl: Buffer.from("03", "hex"),
      FPort: Buffer.from("01", "hex"),
      FCnt: Buffer.from("0000", "hex"),
      MIC: Buffer.from("aa5ed13a", "hex"),
      FHDR: Buffer.from("0403020103000022ac0a", "hex"),
      MACPayload: Buffer.from("0403020103000022ac0a01f0b468dd", "hex"),
      PHYPayload: Buffer.from("600403020103000022ac0a01f0b468ddaa5ed13a", "hex"),
      MACPayloadWithMIC: Buffer.from("0403020103000022ac0a01f0b468ddaa5ed13a", "hex"),
    };

    expect(packet).toMatchObject(expectedPayload);
  });

  //FROM https://pkg.go.dev/github.com/brocaar/lorawan
  it("should decode packet with Lorawan1.0 Encrypted Fopts", () => {
    const sNwkSIntKey = Buffer.from([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0]);
    const nwkSEncKey = Buffer.from([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 0]);
    const appSKey = Buffer.from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]);

    const packet = LoraPayload.fromWire(Buffer.from("YAQDAgEDAAAirAoB8LRo3ape0To=", "base64"));

    expect(calculateMIC(packet, sNwkSIntKey).toString("hex")).toStrictEqual("aa5ed13a");
    expect(decryptFOpts(packet, nwkSEncKey).toString("hex")).toStrictEqual("020701");
    expect(decrypt(packet, appSKey, sNwkSIntKey).toString("hex")).toStrictEqual("01020304");
  });

  it("should decode rekeyind packet with Lorawan11 Encrypted", () => {
    const message_hex = "40679810e080000000c2c5248de748";
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));
    const FNwkSIntKey_hex = Buffer.from("07c105892e1bbb7f7101d13a5f78249b", "hex");
    const SNwkSIntKey_hex = Buffer.from("f9162a2fcf6e70867cee523249282844", "hex");
    const NwkSEncKey_hex = Buffer.from("a5406d11c50850c965c2545ad81980a7", "hex");
    const appSKey = Buffer.from("38034b6efc87cf9c40ac0b45b460d395", "hex");

    expect(
      calculateMIC(
        packet,
        FNwkSIntKey_hex,
        SNwkSIntKey_hex,
        Buffer.from("0000", "hex"),
        Buffer.from("00000001", "hex")
      ).toString("hex")
    ).toStrictEqual("248de748");
    expect(decrypt(packet, appSKey, NwkSEncKey_hex).toString("hex").toUpperCase()).toStrictEqual("0B01");
  });

  it("should encrypt rekeyconf packet with Lorawan11 Encrypted", () => {
    const message_hex = "40679810e080000000c2c5248de748";
    const packet = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));
    const FNwkSIntKey_hex = Buffer.from("07c105892e1bbb7f7101d13a5f78249b", "hex");
    const SNwkSIntKey_hex = Buffer.from("f9162a2fcf6e70867cee523249282844", "hex");
    const NwkSEncKey_hex = Buffer.from("a5406d11c50850c965c2545ad81980a7", "hex");
    const appSKey = Buffer.from("38034b6efc87cf9c40ac0b45b460d395", "hex");

    expect(
      calculateMIC(
        packet,
        FNwkSIntKey_hex,
        SNwkSIntKey_hex,
        Buffer.from("0000", "hex"),
        Buffer.from("00000001", "hex")
      ).toString("hex")
    ).toStrictEqual("248de748");
    expect(decrypt(packet, appSKey, NwkSEncKey_hex).toString("hex").toUpperCase()).toStrictEqual("0B01");
  });
});
