import { generateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { pbkdf2 as noblePbkdf2 } from "@noble/hashes/pbkdf2";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2";
import { sha512 as nobleSha512 } from "@noble/hashes/sha2";

export const PASSPHRASE_REGEX =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_\-+=\[\]{}|\\;:'",.<>/?]).{12,}$/;

export const MNEMONIC_REGEX = /^([a-z]+ ){11}[a-z]+$/;

// Utility: detect Node vs Browser
const isNode = typeof process !== "undefined" && process.versions?.node;

// Helper to convert string to Uint8Array
const encodeUTF8 = (str: string) =>
  isNode ? Buffer.from(str, "utf-8") : new TextEncoder().encode(str);

// PBKDF2 wrapper
const pbkdf2Derive = async (
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  keyLen: number,
  hash: "sha256" | "sha512"
): Promise<Uint8Array> => {
  // 1) Node path
  if (isNode) {
    const { pbkdf2 } = await import("crypto");
    return new Promise((resolve, reject) => {
      pbkdf2(password, salt, iterations, keyLen, hash, (err, out) => {
        if (err) reject(err);
        else resolve(new Uint8Array(out));
      });
    });
  }

  // 2) Browser with WebCrypto PBKDF2
  const subtle = (globalThis as any)?.crypto?.subtle;
  if (subtle) {
    const hashName = hash === "sha256" ? "SHA-256" : "SHA-512"; // <-- hyphen matters
    const baseKey = await subtle.importKey(
      "raw",
      password,
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );
    const bits = await subtle.deriveBits(
      { name: "PBKDF2", salt, iterations, hash: hashName },
      baseKey,
      keyLen * 8
    );
    return new Uint8Array(bits);
  }

  // 3) Fallback: pure JS (works everywhere)
  const h = hash === "sha256" ? nobleSha256 : nobleSha512;
  const out = noblePbkdf2(h, password, salt, { c: iterations, dkLen: keyLen });
  return out;
};

export interface MasterKey {
  /**
   * The derived key in hexadecimal format.
   */
  key: string;

  /**
   * The mnemonic phrase used to generate the key.
   * @note If a mnemonic is provided, it will not be included in the output.
   */
  mnemonic?: string | undefined;
}

/**
 * Generates a master key using a passphrase and an optional mnemonic.
 * The passphrase must be strong, and the mnemonic must consist of 12 words.
 *
 * @param {string} passphraseString - The passphrase to derive the key from.
 * @param {string} [mnemonicString] - An optional mnemonic string.
 * @returns {Promise<MasterKey>} A promise that resolves to the generated master key.
 * @throws {Error} If the passphrase is too weak or if the mnemonic does not contain 12 words.
 */
export const generateMasterKey = async (
  passphraseString: string,
  mnemonicString?: string
): Promise<MasterKey> => {
  if (!passphraseString || !PASSPHRASE_REGEX.test(passphraseString)) {
    throw new Error("passphrase is too weak");
  }

  if (mnemonicString && !MNEMONIC_REGEX.test(mnemonicString)) {
    throw new Error("mnemonic does not contain 12 words");
  }

  const mnemonic = mnemonicString || generateMnemonic(wordlist, 128);

  const passwordBuf = encodeUTF8(passphraseString);
  const saltBuf = encodeUTF8(mnemonic);

  const derivedKey = await pbkdf2Derive(
    passwordBuf,
    saltBuf,
    300000,
    32,
    "sha256"
  );

  const output: MasterKey = {
    key: Array.from(derivedKey)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(""),
    mnemonic: mnemonicString ? undefined : mnemonic,
  };

  derivedKey.fill(0);
  passwordBuf.fill(0);
  saltBuf.fill(0);

  return output;
};
