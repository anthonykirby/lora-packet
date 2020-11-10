#!/usr/bin/env node

import loraPacket from "./lib";

const cmdlineArgs = process.argv;

const hexOption = cmdlineArgs.indexOf("--hex");
const b64Option = cmdlineArgs.indexOf("--base64");

const nwkOption = cmdlineArgs.indexOf("--nwkkey");
const appOption = cmdlineArgs.indexOf("--appkey");

const fCntMSBOption = cmdlineArgs.indexOf("--cntmsb");

function printUsageAndExit(): void {
  console.log("Usage:");
  console.log("\tlora-packet-decode [--nwkkey <NwkSKey> --appkey <AppSKey> --cntmsb <fCntMSB>] --{hex|base64} <data>");
  process.exit(1);
}

// need both keys (or neither)
if ((nwkOption >= 0 && !(appOption >= 0)) || (!(nwkOption >= 0) && appOption >= 0)) {
  printUsageAndExit();
}

let inputData: Buffer;
if (hexOption != -1 && hexOption + 1 < cmdlineArgs.length) {
  const arg = cmdlineArgs[hexOption + 1];
  console.log("decoding from Hex: ", arg);
  inputData = Buffer.from(arg, "hex");
} else if (b64Option != -1 && b64Option + 1 < cmdlineArgs.length) {
  const arg = cmdlineArgs[b64Option + 1];
  console.log("decoding from Base64: ", arg);
  inputData = Buffer.from(arg, "base64");
} else {
  printUsageAndExit();
}

const packet = loraPacket.fromWire(inputData);
console.log("Decoded packet");
console.log("--------------");
let response: string = packet.toString();
if (nwkOption >= 0 && appOption >= 0) {
  const fCntMSBBytes =
    fCntMSBOption >= 0
      ? [parseInt(cmdlineArgs[fCntMSBOption + 1]) & 0xff, parseInt(cmdlineArgs[fCntMSBOption + 1]) & 0xff00]
      : null; //[0x00, 0x00];
  let fCntMSB: Buffer;
  if (fCntMSBBytes) fCntMSB = Buffer.from(fCntMSBBytes);

  const nwkKey = Buffer.from(cmdlineArgs[nwkOption + 1], "hex");
  const appKey = Buffer.from(cmdlineArgs[appOption + 1], "hex");
  const micOk = loraPacket.verifyMIC(packet, nwkKey, appKey, fCntMSB)
    ? " (OK)"
    : " (BAD != " + asHexString(loraPacket.calculateMIC(packet, nwkKey, appKey, fCntMSB)) + ")";
  const plaintext = asHexString(loraPacket.decrypt(packet, appKey, nwkKey, fCntMSB));
  response = response.replace(/  MIC = [0-9a-fA-F]+/, "$&" + micOk);
  response = response.replace(
    /  FRMPayload = [0-9a-fA-F]+/,
    "$&\n" + "             Plaintext = " + plaintext + " ('" + asAscii(plaintext) + "')"
  );
}
console.log(response);

function asHexString(buffer: Buffer): string {
  return buffer.toString("hex").toUpperCase();
}

function asAscii(hex: string): string {
  return hex.replace(/../g, function (x) {
    const code = parseInt(x, 16);
    return code >= 32 && code < 127 ? String.fromCharCode(code) : ".";
  });
}
