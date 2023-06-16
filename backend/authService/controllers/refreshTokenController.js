const User = require("../model/User");
const jwt = require("jsonwebtoken");
const jwtDecode = require("jwt-decode");
const {
    getRefreshToken,
    resetRefreshToken,
    setRefreshToken,
} = require("../config/redisConn");

const { getPublicKeyRaw, getPublicKeyPem } = require("./dataController");

const handleRefreshToken = async (req, res) => {
    const cookies = req.cookies;
    if (!cookies?.jwt) return res.sendStatus(401);

    const { publicKeyRaw, publicKeyPem } = req.body;
    if (!publicKeyRaw || !publicKeyPem) {
        return res.status(400).json({ message: "Public key is required." });
    }

    const refreshToken = cookies.jwt;
    res.clearCookie("jwt", {
        httpOnly: true,
        sameSite: "None",
        // secure: true,
    });

    const user = jwtDecode(refreshToken)?.username;
    if (!user) return res.sendStatus(403); //Forbidden

    const foundUser = await User.findOne({ username: user }).exec();
    if (!foundUser) return res.sendStatus(401); //Unauthorized

    let oldRefreshToken = await getRefreshToken(foundUser.username);
    const hasToken = oldRefreshToken.includes(refreshToken);

    // Detected refresh token reuse!
    if (!hasToken) {
        jwt.verify(
            refreshToken,
            process.env.REFRESH_TOKEN_SECRET,
            async (err, decoded) => {
                if (err) return res.sendStatus(403); //Forbidden

                console.log("attempted refresh token reuse!");
                await resetRefreshToken(decoded.username);
            }
        );
        return res.sendStatus(403); //Forbidden
    }

    const newRefreshTokenArray = oldRefreshToken.filter(
        (rt) => rt !== refreshToken
    );

    // evaluate jwt
    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        async (err, decoded) => {
            if (err) {
                console.log("expired refresh token");
                oldRefreshToken = [...newRefreshTokenArray];
                await setRefreshToken(oldRefreshToken);
            }
            if (err || foundUser.username !== decoded.username)
                return res.sendStatus(403);

            // Refresh token was still valid
            const roles = Object.values(foundUser.roles);
            const accessToken = jwt.sign(
                {
                    UserInfo: {
                        username: decoded.username,
                        roles: roles,
                    },
                    PublicKey: {
                        raw: publicKeyRaw,
                        pem: publicKeyPem,
                    },
                },
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn: "30s" }
            );

            const newRefreshToken = jwt.sign(
                { username: foundUser.username },
                process.env.REFRESH_TOKEN_SECRET,
                { expiresIn: "1d" }
            );
            // Saving refreshToken with current user
            await setRefreshToken(foundUser.username, [
                ...newRefreshTokenArray,
                newRefreshToken,
            ]);

            // Creates Secure Cookie with refresh token
            res.cookie("jwt", newRefreshToken, {
                httpOnly: true,
                // secure: true,
                sameSite: "None",
                maxAge: 24 * 60 * 60 * 1000,
            });

            const severPubKeyRaw = getPublicKeyRaw();
            const severPubKeyPem = getPublicKeyPem();
            // Send authorization roles and access token to user

            res.json({ roles, accessToken, severPubKeyRaw, severPubKeyPem });
        }
    );
};

module.exports = { handleRefreshToken };
