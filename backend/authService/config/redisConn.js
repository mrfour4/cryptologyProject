const { createClient } = require("redis");

const client = createClient({
    password: process.env.REDIS_PASS,
    socket: {
        host: process.env.REDIS_HOST,
        port: process.env.REDIS_PORT,
    },
});

const connectRD = async () => {
    await client.connect();
};

client.on("ready", () => {
    console.log("Connected to Redis");
});

client.on("error", (err) => {
    console.log("Error in the Connection to Redis");
});

const getRefreshToken = async (username) => {
    const result = await client.get(username, (err, reply) => {
        if (err) {
            console.log(err.message);
        }
    });

    return result !== null ? JSON.parse(result) : [];
};

const resetRefreshToken = async (username) => {
    await client.del(username, (err) => {
        if (err) {
            console.log(err.message);
        }
        console.log("Reset refresh token of ", username);
    });
};

const setRefreshToken = async (username, refreshToken) => {
    await client.setEx(
        username,
        24 * 60 * 60,
        JSON.stringify(refreshToken),
        (err, reply) => {
            if (err) {
                console.log(err.message);
            }
            console.log("Refresh token: ", reply);
        }
    );
};

module.exports = {
    connectRD,
    getRefreshToken,
    setRefreshToken,
    resetRefreshToken,
};
