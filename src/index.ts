import { generateMnemonic } from "bip39";
import { promisify } from "util";
const asyncPbkdf2 = promisify(require("crypto").pbkdf2);

export const PASSPHRASE_REGEX =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_\-+=\[\]{}|\\;:'",.<>/?]).{12,}$/;

export const MNEMONIC_REGEX = /^([a-z]+ ){11}[a-z]+$/;

export interface MasterKey {
  key: string;
  mnemonic?: string;
}

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
