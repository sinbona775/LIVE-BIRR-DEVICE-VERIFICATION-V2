const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const BOT_TOKEN = process.env.BOT_TOKEN;
const ADMIN_KEY = process.env.ADMIN_KEY;

// Verify Telegram Mini App data
function verifyTelegramData(initData) {
    if (!BOT_TOKEN || !initData) return false;

    const params = new URLSearchParams(initData);
    const hash = params.get("hash");

    if (!hash) return false;

    params.delete("hash");

    const dataCheckString = [...params.entries()]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, value]) => `${key}=${value}`)
        .join("\n");

    const secretKey = crypto
        .createHmac("sha256", "WebAppData")
        .update(BOT_TOKEN)
        .digest();

    const calculatedHash = crypto
        .createHmac("sha256", secretKey)
        .update(dataCheckString)
        .digest("hex");

    return crypto.timingSafeEqual(
        Buffer.from(hash, "hex"),
        Buffer.from(calculatedHash, "hex")
    );
}

app.post("/api/verify", (req, res) => {
    const { initData, deviceId } = req.body;

    if (!verifyTelegramData(initData)) {
        return res.status(401).json({
            success: false,
            message: "Invalid Telegram verification"
        });
    }

    if (!deviceId || typeof deviceId !== "string") {
        return res.status(400).json({
            success: false,
            message: "Device ID required"
        });
    }

    const params = new URLSearchParams(initData);
    const user = JSON.parse(params.get("user") || "{}");

    return res.json({
        success: true,
        userId: user.id,
        deviceId: deviceId,
        status: "REVIEW"
    });
});

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`LIVE BIRR server running on port ${PORT}`);
});
