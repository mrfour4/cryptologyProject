const User = require("../model/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const { getPublicKeyRaw, getPublicKeyPem } = require("./dataController");

const { getRefreshToken, setRefreshToken } = require("../config/redisConn");

const handleLogin = async (req, res) => {
    const cookies = req.cookies;
    console.log(`cookie available at login: ${JSON.stringify(cookies)}`);
    const { user, pwd, publicKeyRaw, publicKeyPem } = req.body;
    if (!user || !pwd)
        return res
            .status(400)
            .json({ message: "Username and password are required." });

    if (!publicKeyRaw || !publicKeyPem) {
        return res.status(400).json({ message: "Public key is required." });
    }
    const foundUser = await User.findOne({ username: user }).exec();
    if (!foundUser) return res.sendStatus(401); //Unauthorized

    // evaluate password
    const match = await bcrypt.compare(pwd, foundUser.password);
    if (match) {
        console.log(foundUser);

        const roles = Object.values(foundUser.roles).filter(Boolean);
        // create JWTs
        const accessToken = jwt.sign(
            {
                UserInfo: {
                    username: foundUser.username,
                    roles: roles,
                },
                PublicKey: {
                    raw: publicKeyRaw,
                    pem: publicKeyPem,
                },
            },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: "1d" }
        );
        const newRefreshToken = jwt.sign(
            { username: foundUser.username },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: "1d" }
        );

        let oldRefreshToken = await getRefreshToken(foundUser.username);

        let newRefreshTokenArray = !cookies?.jwt
            ? oldRefreshToken
            : oldRefreshToken.filter((rt) => rt !== cookies.jwt);

        if (cookies?.jwt) {
            /*
            Scenario added here:
                1) User logs in but never uses RT and does not logout
                2) RT is stolen
                3) If 1 & 2, reuse detection is needed to clear all RTs when user logs in
            */
            const refreshToken = cookies.jwt;
            const foundToken = oldRefreshToken.includes(refreshToken);

            // Detected refresh token reuse!
            if (!foundToken) {
                console.log("attempted refresh token reuse at login!");
                // clear out ALL previous refresh tokens
                newRefreshTokenArray = [];
            }

            res.clearCookie("jwt", {
                httpOnly: true,
                sameSite: "None",
                // secure: true,
            });
        }

        oldRefreshToken = [...newRefreshTokenArray, newRefreshToken];
        // Rest of your code using the oldRefreshToken
        console.log(oldRefreshToken);

        await setRefreshToken(foundUser.username, oldRefreshToken);

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
    } else {
        res.sendStatus(401);
    }
};

module.exports = { handleLogin };
