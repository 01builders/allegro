import { createHash } from "crypto";
import { readFileSync } from "fs";
import { join } from "path";

type Expiry = { kind: "max_block_height" | "unix_millis"; value: number };

type Vectors = {
  chain_id: number;
  domain_tag: string;
  protocol_version: number;
  epoch: number;
  tempo_tx_hex: string;
  nonce_key_hex: string;
  nonce_seq: number;
  expiry: Expiry;
  parent_qc_hash_hex: string | null;
  sender_hex: string;
  recipient_hex: string;
  amount: number;
  asset_hex: string;
  expected: {
    tx_hash_hex: string;
    effects_hash_hex: string;
    cert_preimage_hex: string;
    cert_digest_hex: string;
    qc_hash_hex: string;
  };
};

const file = join(__dirname, "hash_vectors.json");
const vectors = JSON.parse(readFileSync(file, "utf8")) as Vectors;

const TX_HASH_TAG = Buffer.from("tempo.fastpay.tx.v1");
const EFFECTS_HASH_TAG = Buffer.from("tempo.fastpay.effects.v1");
const QC_HASH_TAG = Buffer.from("tempo.fastpay.qc.v1");
const CERT_PREIMAGE_TAG = Buffer.from("tempo.fastpay.cert.preimage.v1");

const pushU8 = (out: number[], v: number) => out.push(v & 0xff);
const pushU16 = (out: number[], v: number) => out.push((v >>> 8) & 0xff, v & 0xff);
const pushU32 = (out: number[], v: number) =>
  out.push((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
const pushU64 = (out: number[], v: number) => {
  const b = Buffer.allocUnsafe(8);
  b.writeBigUInt64BE(BigInt(v));
  out.push(...b);
};
const pushBytes = (out: number[], b: Buffer) => {
  pushU32(out, b.length);
  out.push(...b);
};

const sha256 = (buf: Buffer) => createHash("sha256").update(buf).digest();

const txEnc: number[] = [...TX_HASH_TAG];
pushU64(txEnc, vectors.chain_id);
pushBytes(txEnc, Buffer.from(vectors.tempo_tx_hex, "hex"));
txEnc.push(...Buffer.from(vectors.nonce_key_hex, "hex"));
pushU64(txEnc, vectors.nonce_seq);
if (vectors.expiry.kind === "max_block_height") {
  pushU8(txEnc, 0);
  pushU64(txEnc, vectors.expiry.value);
} else {
  pushU8(txEnc, 1);
  pushU64(txEnc, vectors.expiry.value);
}
if (vectors.parent_qc_hash_hex) {
  pushU8(txEnc, 1);
  txEnc.push(...Buffer.from(vectors.parent_qc_hash_hex, "hex"));
} else {
  pushU8(txEnc, 0);
}
const txHash = sha256(Buffer.from(txEnc));

const effectsEnc: number[] = [...EFFECTS_HASH_TAG];
effectsEnc.push(...Buffer.from(vectors.sender_hex, "hex"));
effectsEnc.push(...Buffer.from(vectors.recipient_hex, "hex"));
pushU64(effectsEnc, vectors.amount);
effectsEnc.push(...Buffer.from(vectors.asset_hex, "hex"));
effectsEnc.push(...Buffer.from(vectors.nonce_key_hex, "hex"));
pushU64(effectsEnc, vectors.nonce_seq);
const effectsHash = sha256(Buffer.from(effectsEnc));

const preimageEnc: number[] = [...CERT_PREIMAGE_TAG];
pushBytes(preimageEnc, Buffer.from(vectors.domain_tag, "utf8"));
pushU16(preimageEnc, vectors.protocol_version);
pushU64(preimageEnc, vectors.chain_id);
pushU64(preimageEnc, vectors.epoch);
preimageEnc.push(...txHash);
preimageEnc.push(...effectsHash);
const preimage = Buffer.from(preimageEnc);
const digest = sha256(preimage);

const certs = [
  { signerHex: "0b".repeat(32), signatureHex: "bb".repeat(64), createdAt: 1001 },
  { signerHex: "0a".repeat(32), signatureHex: "aa".repeat(64), createdAt: 1000 }
].sort((a, b) => Buffer.compare(Buffer.from(a.signerHex, "hex"), Buffer.from(b.signerHex, "hex")));

const qcEnc: number[] = [...QC_HASH_TAG];
qcEnc.push(...txHash);
qcEnc.push(...effectsHash);
pushU32(qcEnc, 2);
pushU32(qcEnc, certs.length);
for (const cert of certs) {
  const signer = Buffer.from(cert.signerHex, "hex");
  const sig = Buffer.from(cert.signatureHex, "hex");
  qcEnc.push(...signer);
  pushBytes(qcEnc, sig);
  pushU64(qcEnc, cert.createdAt);
}
const qcHash = sha256(Buffer.from(qcEnc));

const assertEq = (actual: Buffer, expectedHex: string, label: string) => {
  const actualHex = actual.toString("hex");
  if (actualHex !== expectedHex) {
    throw new Error(`${label} mismatch\nexpected: ${expectedHex}\nactual:   ${actualHex}`);
  }
};

assertEq(txHash, vectors.expected.tx_hash_hex, "tx_hash");
assertEq(effectsHash, vectors.expected.effects_hash_hex, "effects_hash");
assertEq(preimage, vectors.expected.cert_preimage_hex, "cert_preimage");
assertEq(digest, vectors.expected.cert_digest_hex, "cert_digest");
assertEq(qcHash, vectors.expected.qc_hash_hex, "qc_hash");

console.log("Hash vectors verified.");
