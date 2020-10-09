import LoraPayload from "../src/lib/LoraPacket";

describe("parse example payload", () => {
  it("should parse data payload", () => {
    const message_hex = "40F17DBE4900020001954378762B11FF0D";

    const expectedPayload = {
      PHYPayload: Buffer.from("40f17dbe4900020001954378762b11ff0d", "hex"),
      MACPayloadWithMIC: Buffer.from("f17dbe4900020001954378762b11ff0d", "hex"),
      MHDR: Buffer.from("40", "hex"),
      MACPayload: Buffer.from("f17dbe490002000195437876", "hex"),
      MIC: Buffer.from("2b11ff0d", "hex"),
      FOpts: Buffer.alloc(0),
      FCtrl: Buffer.from("00", "hex"),
      FHDR: Buffer.from("f17dbe49000200", "hex"),
      DevAddr: Buffer.from("49be7df1", "hex"),
      FCnt: Buffer.from("0002", "hex"),
      FPort: Buffer.from("01", "hex"),
      FRMPayload: Buffer.from("95437876", "hex"),
    };

    const parsed = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    expect(parsed).not.toBeUndefined();
    expect(parsed).not.toBeUndefined();
    expect(parsed).toMatchObject(expectedPayload);

    // non-buffer output
    expect(parsed.getMType()).toBe("Unconfirmed Data Up");
    expect(parsed.getDir()).toBe("up");
    expect(parsed.getFCnt()).toBe(2);
    expect(parsed.getFCtrlACK()).toBe(false);
    expect(parsed.getFCtrlADR()).toBe(false);
    expect(parsed.getFPort()).toBe(1);
  });

  it("should parse join request payload", () => {
    const message_hex = "0039363463336913AA05693574323831338EF1C1D5EC6C";

    const expectedPayload = {
      PHYPayload: Buffer.from("0039363463336913aa05693574323831338ef1c1d5ec6c", "hex"),
      MACPayloadWithMIC: Buffer.from("39363463336913aa05693574323831338ef1c1d5ec6c", "hex"),
      MHDR: Buffer.from("00", "hex"),
      MACPayload: Buffer.from("39363463336913aa05693574323831338ef1", "hex"),
      MIC: Buffer.from("c1d5ec6c", "hex"),
      AppEUI: Buffer.from("aa13693363343639", "hex"),
      DevEUI: Buffer.from("3331383274356905", "hex"),
      DevNonce: Buffer.from("f18e", "hex"),
    };

    const parsed = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    expect(parsed).not.toBeUndefined();
    expect(parsed).not.toBeUndefined();
    expect(parsed).toMatchObject(expectedPayload);

    // non-buffer output
    expect(parsed.getMType()).toBe("Join Request");
  });

  it("should parse join accept payload", () => {
    const message_hex = "20386337CCBBAAE7CD2C010000D9D0A6E7"; // not encrypted

    const expectedPayload = {
      PHYPayload: Buffer.from("20386337ccbbaae7cd2c010000d9d0a6e7", "hex"),
      MACPayloadWithMIC: Buffer.from("386337ccbbaae7cd2c010000d9d0a6e7", "hex"),
      MHDR: Buffer.from("20", "hex"),
      MACPayload: Buffer.from("386337ccbbaae7cd2c010000", "hex"),
      MIC: Buffer.from("d9d0a6e7", "hex"),
      NetID: Buffer.from("aabbcc", "hex"),
      DevAddr: Buffer.from("012ccde7", "hex"),
      AppNonce: Buffer.from("376338", "hex"),
      DLSettings: Buffer.from("00", "hex"),
      RxDelay: Buffer.from("00", "hex"),
      CFList: Buffer.from("", "hex"),
    };

    const parsed = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    expect(parsed).not.toBeUndefined();
    expect(parsed).not.toBeUndefined();
    expect(parsed).toMatchObject(expectedPayload);

    // non-buffer output
    expect(parsed.getMType()).toBe("Join Accept");
  });

  it("should parse data payload with empty payload", () => {
    const message_hex = "40F17DBE49000300012A3518AF";

    const expectedPayload = {
      PHYPayload: Buffer.from("40f17dbe49000300012a3518af", "hex"),
      MACPayloadWithMIC: Buffer.from("f17dbe49000300012a3518af", "hex"),
      MHDR: Buffer.from("40", "hex"),
      MACPayload: Buffer.from("f17dbe4900030001", "hex"),
      MIC: Buffer.from("2a3518af", "hex"),
      FOpts: Buffer.alloc(0),
      FCtrl: Buffer.from("00", "hex"),
      FHDR: Buffer.from("f17dbe49000300", "hex"),
      DevAddr: Buffer.from("49be7df1", "hex"),
      FCnt: Buffer.from("0003", "hex"),
      FPort: Buffer.from("01", "hex"),
      FRMPayload: Buffer.from("", "hex"),
    };

    const parsed = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    expect(parsed).not.toBeUndefined();
    expect(parsed).not.toBeUndefined();
    expect(parsed).toMatchObject(expectedPayload);

    // non-buffer output
    expect(parsed.getMType()).toBe("Unconfirmed Data Up");
    expect(parsed.getDir()).toBe("up");
    expect(parsed.getFCnt()).toBe(3);
    expect(parsed.getFCtrlACK()).toBe(false);
    expect(parsed.getFCtrlADR()).toBe(false);
  });

  it("should parse large data payload", () => {
    const message_hex =
      "40f17dbe490004000155332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a20af3c5e7";

    const expectedPayload = {
      PHYPayload: Buffer.from(
        "40f17dbe490004000155332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a20af3c5e7",
        "hex"
      ),
      MACPayloadWithMIC: Buffer.from(
        "f17dbe490004000155332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a20af3c5e7",
        "hex"
      ),
      MHDR: Buffer.from("40", "hex"),
      MACPayload: Buffer.from(
        "f17dbe490004000155332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a2",
        "hex"
      ),
      MIC: Buffer.from("0af3c5e7", "hex"),
      FOpts: Buffer.alloc(0),
      FCtrl: Buffer.from("00", "hex"),
      FHDR: Buffer.from("f17dbe49000400", "hex"),
      DevAddr: Buffer.from("49be7df1", "hex"),
      FCnt: Buffer.from("0004", "hex"),
      FPort: Buffer.from("01", "hex"),
      FRMPayload: Buffer.from(
        "55332de41a11adc072553544429ce7787707d1c316e027e7e5e334263376affb8aa17ad30075293f28dea8a2",
        "hex"
      ),
    };

    const parsed = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    expect(parsed).not.toBeUndefined();
    expect(parsed).not.toBeUndefined();
    expect(parsed).toMatchObject(expectedPayload);

    // non-buffer output
    expect(parsed.getMType()).toBe("Unconfirmed Data Up");
    expect(parsed.getDir()).toBe("up");
    expect(parsed.getFCnt()).toBe(4);
    expect(parsed.getFCtrlACK()).toBe(false);
    expect(parsed.getFCtrlADR()).toBe(false);
  });

  it("should parse ack", () => {
    const message_hex = "60f17dbe4920020001f9d65d27";

    const expectedPayload = {
      PHYPayload: Buffer.from("60f17dbe4920020001f9d65d27", "hex"),
      MACPayloadWithMIC: Buffer.from("f17dbe4920020001f9d65d27", "hex"),
      MHDR: Buffer.from("60", "hex"),
      MACPayload: Buffer.from("f17dbe4920020001", "hex"),
      MIC: Buffer.from("f9d65d27", "hex"),
      FOpts: Buffer.alloc(0),
      FCtrl: Buffer.from("20", "hex"),
      FHDR: Buffer.from("f17dbe49200200", "hex"),
      DevAddr: Buffer.from("49be7df1", "hex"),
      FCnt: Buffer.from("0002", "hex"),
      FPort: Buffer.from("01", "hex"),
      FRMPayload: Buffer.from("", "hex"),
    };

    const parsed = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    expect(parsed).not.toBeUndefined();
    expect(parsed).not.toBeUndefined();
    expect(parsed).toMatchObject(expectedPayload);

    // non-buffer output
    expect(parsed.getMType()).toBe("Unconfirmed Data Down");
    expect(parsed.getDir()).toBe("down");
    expect(parsed.getFCnt()).toBe(2);
    expect(parsed.getFCtrlACK()).toBe(true);
    expect(parsed.getFCtrlADR()).toBe(false);
  });

  it("should Join Accept", () => {
    const message_hex = "33105EAFD15E04A62872C97F821955A1B75420F0FFCC20CF999347E18AA8A235";

    const expectedPayload = {
      PHYPayload: Buffer.from("33105EAFD15E04A62872C97F821955A1B75420F0FFCC20CF999347E18AA8A235", "hex"),
      MACPayloadWithMIC: Buffer.from("105EAFD15E04A62872C97F821955A1B75420F0FFCC20CF999347E18AA8A235", "hex"),
      MHDR: Buffer.from("33", "hex"),
      MACPayload: Buffer.from("105EAFD15E04A62872C97F821955A1B75420F0FFCC20CF999347E1", "hex"),
      MIC: Buffer.from("8AA8A235", "hex"),
      AppNonce: Buffer.from("AF5E10", "hex"),
      NetID: Buffer.from("045ED1", "hex"),
      DevAddr: Buffer.from("C97228A6", "hex"),
      DLSettings: Buffer.from("7F", "hex"),
      RxDelay: Buffer.from("82", "hex"),
      CFList: Buffer.from(""),
    };

    const parsed = LoraPayload.fromWire(Buffer.from(message_hex, "hex"));

    expect(parsed).not.toBeUndefined();
    expect(parsed).not.toBeUndefined();
    expect(parsed).toMatchObject(expectedPayload);

    // non-buffer output
    expect(parsed.getMType()).toBe("Join Accept");
    expect(parsed.getDir()).toBe("down");
    expect(parsed.getDLSettingsRxOneDRoffset()).toBe(7);
    expect(parsed.getDLSettingsRxTwoDataRate()).toBe(15);
    expect(parsed.getRxDelayDel()).toBe(2);
    expect(parsed.getFCnt()).toBe(null);
  });
});
