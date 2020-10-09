import loraPacket from "../src/lib";

describe("parse packets from github issue #18", () => {
  it("should parse packet #1", () => {
    const message_hex = "4084412505A3010009110308B33750F504D4B86A";

    const parsed = loraPacket.fromWire(Buffer.from(message_hex, "hex"));

    expect(parsed).not.toBeUndefined();
    expect(parsed).not.toBeUndefined();
    expect(parsed.FOpts).not.toBeUndefined();
    expect(parsed.FOpts).toMatchObject(Buffer.from("091103", "hex"));
  });
});
