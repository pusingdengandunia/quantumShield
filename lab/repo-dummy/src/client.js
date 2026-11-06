// Dummy application code: the Q-Shield code scanner should flag this file.
const crypto = require("crypto");

const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
module.exports = { pair };
