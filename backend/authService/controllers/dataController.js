require("dotenv").config();

const {
    createECDH,
    createSign,
    randomBytes,
    createCipheriv,
    createVerify,
    createDecipheriv,
} = require("crypto");

const ecKeyUtils = require("eckey-utils");

const curveName = "secp256k1";

const getRawKey = (curveName) => {
    const senderPrivateKeyRaw = Buffer.from(
        process.env.PRIVATE_KEY_HEX,
        "hex"
    ).toString("base64");

    const echd = createECDH(curveName);
    echd.setPrivateKey(senderPrivateKeyRaw, "base64");

    const senderPublicKey = echd.getPublicKey("base64");

    return { privateKey: senderPrivateKeyRaw, publicKey: senderPublicKey };
};

const getPemKey = (curveName, privateKeyRaw) => {
    const ecdh = createECDH(curveName);
    ecdh.setPrivateKey(privateKeyRaw, "base64");

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
    const enc = Buffer.concat([
        cipher.update(plaintext, "utf8"),
        cipher.final(),
    ]);

    return [enc, iv, cipher.getAuthTag()]
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

const encryptAndSign = (
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

const decryptAndVerify = (
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

        const message = decryptAes256Gcm(encrypted, sharedSecret);

        const verify = createVerify("SHA256");
        verify.update(message);
        verify.end();
        const isValid = verify.verify(senderPublicKeyPem, signature, "base64");

        if (isValid) return JSON.parse(message);
        else {
            console.log("Invalid signature");
            return null;
        }
    } catch (err) {
        console.log(err.message);
        return null;
    }
};

const encryptData = (receiverPublicKeyRaw, message) => {
    const senderRawKey = getRawKey(curveName);
    const senderPemKey = getPemKey(curveName, senderRawKey.privateKey);

    const cipher = encryptAndSign(
        senderRawKey.privateKey,
        senderPemKey.privateKey,
        message,
        receiverPublicKeyRaw
    );

    return cipher;
};

const decryptData = (senderPublicKeyRaw, senderPublicKeyPem, cipher) => {
    const receiverPrivateKeyRaw = getRawKey(curveName).privateKey;

    const data = decryptAndVerify(
        senderPublicKeyRaw,
        senderPublicKeyPem,
        cipher,
        receiverPrivateKeyRaw
    );
    return data;
};

const getPublicKeyRaw = () => {
    return getRawKey(curveName).publicKey;
};

const getPublicKeyPem = () => {
    const privateKey = getRawKey(curveName).privateKey;
    return getPemKey(curveName, privateKey).publicKey;
};

module.exports = { encryptData, decryptData, getPublicKeyRaw, getPublicKeyPem };
