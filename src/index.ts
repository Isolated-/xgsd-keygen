import { generateMnemonic } from "bip39";
import { promisify } from "util";
const asyncPbkdf2 = promisify(require("crypto").pbkdf2);

export const PASSPHRASE_REGEX =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_\-+=\[\]{}|\\;:'",.<>/?]).{12,}$/;

export const MNEMONIC_REGEX = /^([a-z]+ ){11}[a-z]+$/;

export interface MasterKey {
  /**
   * The derived key in hexadecimal format.
   */
  key: string;

  /**
   * The mnemonic phrase used to generate the key.
   * @note If a mnemonic is provided, it will not be included in the output.
   */
  mnemonic?: string;
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

  const passphraseBuf = Buffer.from(passphraseString, "utf-8");
  const mnemonicBuf = mnemonicString
    ? Buffer.from(mnemonicString, "utf-8")
    : generateMnemonic();

  const key = await asyncPbkdf2(
    passphraseBuf,
    mnemonicBuf,
    50000,
    32,
    "sha256"
  );

  const output: MasterKey = {
    key: key.toString("hex"),
    mnemonic: mnemonicBuf.toString("utf-8"),
  };

  key.fill(0);

  if (mnemonicString) {
    delete output.mnemonic;
  }

  return output;
};
