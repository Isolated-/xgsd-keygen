import { generateMnemonic } from "bip39";

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
  if (isNode) {
    const { pbkdf2 } = await import("crypto");
    return new Promise((resolve, reject) => {
      pbkdf2(password, salt, iterations, keyLen, hash, (err, derived) => {
        if (err) reject(err);
        else resolve(derived);
      });
    });
  } else {
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      password,
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations,
        hash: hash.toUpperCase(),
      },
      cryptoKey,
      keyLen * 8
    );

    return new Uint8Array(bits);
  }
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

  const mnemonic = mnemonicString || generateMnemonic();

  const passwordBuf = encodeUTF8(passphraseString);
  const saltBuf = encodeUTF8(mnemonic);

  const derivedKey = await pbkdf2Derive(
    passwordBuf,
    saltBuf,
    50000,
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
