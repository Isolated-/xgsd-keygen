import { generateMasterKey } from "../src";

describe("generate master key tests", () => {
  it("should generate a key with passphrase returning key and mnemonic", async () => {
    const passphrase = "Password1234!";

    const { key, mnemonic } = await generateMasterKey(passphrase);
    expect(key).toBeDefined();
    expect(mnemonic).toBeDefined();
  });

  it("should generate a key with passphrase and mnemonic, returning only the key", async () => {
    const passphrase = "Password1234!";
    const mnemonic =
      "enforce crunch zebra about run desk spice napkin bundle carpet muscle income";

    const result = await generateMasterKey(passphrase, mnemonic);
    expect(result.key).toBeDefined();
    expect(result.key).toEqual(
      "7026be248a6bad5fe182f8f5dab1d6092a7c44a4e14fc4534454e1d5eaf6ee59"
    );
    expect(result.mnemonic).not.toBeDefined();
  });

  it("should generate a different key when the mnemonic is the same but passphrase is different", async () => {
    const passphrase1 = "Password1234!";
    const mnemonic =
      "enforce crunch zebra about run desk spice napkin bundle carpet muscle income";
    const { key: key1 } = await generateMasterKey(passphrase1, mnemonic);

    const passphrase2 = "Password1234!2";
    const { key: key2 } = await generateMasterKey(passphrase2, mnemonic);

    expect(key1).not.toEqual(key2);
  });

  it("should throw an error - passphrase is too weak", async () => {
    const passphrase = "weak";

    await expect(generateMasterKey(passphrase)).rejects.toThrow(
      "passphrase is too weak"
    );
  });

  it("should throw an error - mnemonic does not contain 12 words", async () => {
    const passphrase = "Password1234!";
    const mnemonic = "short mnemonic";

    await expect(generateMasterKey(passphrase, mnemonic)).rejects.toThrow(
      "mnemonic does not contain 12 words"
    );
  });
});
