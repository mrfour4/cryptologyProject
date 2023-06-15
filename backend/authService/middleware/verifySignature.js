const { decryptData } = require("../controllers/dataController");

const verifySignature = () => {
    return (req, res, next) => {
        const { signature, encrypted } = req.body;
        if (!signature || !encrypted) return res.sendStatus(401);

        const cipher = { signature, encrypted };

        const data = decryptData(req.publicKeyRaw, req.publicKeyPem, cipher);

        console.log("data: ", data);

        console.log("data: ", data);
        if (!data) return res.sendStatus(401);
        req.body = data;
        next();
    };
};

module.exports = verifySignature;
