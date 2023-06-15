const { setRefreshToken, getRefreshToken } = require("../config/redisConn");
const User = require("../model/User");

const jwtDecode = require("jwt-decode");

const handleLogout = async (req, res) => {
    // On client, also delete the accessToken

    const cookies = req.cookies;
    if (!cookies?.jwt) return res.sendStatus(204); //No content
    const refreshToken = cookies.jwt;

    const username = jwtDecode(refreshToken)?.username;
    if (!username) return res.sendStatus(403); //Forbidden

    // Is refreshToken in cache?
    let oldRefreshToken = await getRefreshToken(username);
    const foundUser = oldRefreshToken.includes(refreshToken);

    if (!foundUser) {
        res.clearCookie("jwt", {
            httpOnly: true,
            sameSite: "None",
            // secure: true,
        });
        return res.sendStatus(204);
    }

    // Delete refreshToken in cache

    oldRefreshToken = oldRefreshToken.filter((rt) => rt !== refreshToken);
    await setRefreshToken(username, oldRefreshToken);

    res.clearCookie("jwt", {
        httpOnly: true,
        sameSite: "None",
        // secure: true,
    });
    res.sendStatus(204);
};

module.exports = { handleLogout };
