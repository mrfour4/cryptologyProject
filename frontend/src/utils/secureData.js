import {
    createCipheriv,
    createDecipheriv,
    createECDH,
    createSign,
    createVerify,
    randomBytes,
} from "crypto-browserify";

import ecKeyUtils from "eckey-utils";
import parseJson from "parse-json";

const curveName = "secp256k1";

const getRawKey = () => {
    const ecdh = createECDH(curveName);
    ecdh.generateKeys();

    const privateKey = ecdh.getPrivateKey("base64");
    const publicKey = ecdh.getPublicKey("base64");

    return { privateKey, publicKey };
};

const getPemKey = (privateKey) => {
    const ecdh = createECDH(curveName);
    ecdh.setPrivateKey(privateKey, "base64");

    const pems = ecKeyUtils.generatePem({
        curveName,
        privateKey: ecdh.getPrivateKey(),
        publicKey: ecdh.getPublicKey(),
    });

    return {
        privateKey: pems.privateKey,
        publicKey: pems.publicKey,
    };
};

const encryptAes256Gcm = (plaintext, key) => {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const encrypted = Buffer.concat([
        cipher.update(plaintext, "utf8"),
        cipher.final(),
    ]);

    return [encrypted, iv, cipher.getAuthTag()]
        .map((e) => e.toString("base64"))
        .join(".");
};

const decryptAes256Gcm = (ciphertext, key) => {
    const [enc, iv, authTag] = ciphertext
        .split(".")
        .map((e) => Buffer.from(e, "base64"));
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(authTag);

    const plaintext = Buffer.concat([
        decipher.update(enc, "utf8"),
        decipher.final(),
    ]).toString();
    return plaintext;
};

const encryptData = (
    senderPrivateKeyRaw,
    senderPrivateKeyPem,
    message,
    receiverPublicKeyRaw
) => {
    const dataText = JSON.stringify(message);

    const ecdh = createECDH(curveName);
    ecdh.setPrivateKey(senderPrivateKeyRaw, "base64");

    const sharedSecret = ecdh.computeSecret(receiverPublicKeyRaw, "base64");

    const sign = createSign("sha256");
    sign.update(dataText);
    const signature = sign.sign(senderPrivateKeyPem, "base64");

    const encrypted = encryptAes256Gcm(dataText, sharedSecret);
    return {
        signature,
        encrypted,
    };
};

const decryptData = (
    senderPublicKeyRaw,
    senderPublicKeyPem,
    cipher,
    receiverPrivateKeyRaw
) => {
    const ecdh = createECDH(curveName);
    ecdh.setPrivateKey(receiverPrivateKeyRaw, "base64");

    const sharedSecret = ecdh.computeSecret(senderPublicKeyRaw, "base64");

    try {
        const { signature, encrypted } = cipher;

        console.log("server response (cipher): ", cipher);
        const message = decryptAes256Gcm(encrypted, sharedSecret);

        const verify = createVerify("sha256");
        verify.update(message);
        verify.end();
        const isValid = verify.verify(senderPublicKeyPem, signature, "base64");

        if (isValid) return parseJson(message);
        else {
            console.log("Invalid signature");
            return null;
        }
    } catch (err) {
        console.log(err.message, ".... Loi cai gi a");
        return null;
    }
};

export { decryptData, encryptData, getPemKey, getRawKey };
