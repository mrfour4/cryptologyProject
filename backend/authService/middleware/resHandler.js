const { encryptData } = require("../controllers/dataController");

const resHandler = (req, res, next) => {
    const originalSend = res.send;

    res.send = function (data) {
        const message = JSON.parse(data);
        console.log("response from server: ", message);
        const encryptedData = encryptData(req.publicKeyRaw, message);

        originalSend.call(this, JSON.stringify(encryptedData));
    };

    next();
};

module.exports = resHandler;
