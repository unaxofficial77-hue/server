require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const OTP_EXPIRY_TIME = 5 * 60 * 1000;
const SESSION_EXPIRY_TIME = 10 * 60 * 1000;

app.use(cors());
app.use(express.json());

const otpStore = new Map();
const sessionStore = new Map();

app.get("/", (req, res) => {
    res.send("OTP server is running with Resend");
});

app.post("/send-otp", async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: "Email is required"
            });
        }

        if (!process.env.RESEND_API_KEY) {
            throw new Error(
                "RESEND_API_KEY is missing"
            );
        }

        const normalizedEmail =
            email.trim().toLowerCase();

        const otp = Math.floor(
            100000 + Math.random() * 900000
        ).toString();

        const emailResponse = await fetch(
            "https://api.resend.com/emails",
            {
                method: "POST",
                headers: {
                    "Authorization":
                        `Bearer ${process.env.RESEND_API_KEY}`,
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    from:
                        "Autofill OTP <onboarding@resend.dev>",
                    to: [normalizedEmail],
                    subject:
                        "Your Autofill Extension OTP",
                    text:
                        `Your OTP is ${otp}. ` +
                        `It will expire in 5 minutes.`
                })
            }
        );

        const emailResult =
            await emailResponse.json();

        if (!emailResponse.ok) {
            console.error(
                "Resend API error:",
                emailResult
            );

            throw new Error(
                emailResult.message ||
                "Resend could not send the email"
            );
        }

        otpStore.set(normalizedEmail, {
            otp,
            expiresAt:
                Date.now() + OTP_EXPIRY_TIME,
            attempts: 0
        });

        res.json({
            success: true,
            message: "OTP sent successfully"
        });
    } catch (error) {
        console.error(
            "Send OTP error:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                error.message ||
                "Could not send OTP"
        });
    }
});

app.post("/verify-otp", (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
        return res.status(400).json({
            success: false,
            message:
                "Email and OTP are required"
        });
    }

    const normalizedEmail =
        email.trim().toLowerCase();

    const savedOtp =
        otpStore.get(normalizedEmail);

    if (!savedOtp) {
        return res.status(400).json({
            success: false,
            message: "OTP not found"
        });
    }

    if (Date.now() > savedOtp.expiresAt) {
        otpStore.delete(normalizedEmail);

        return res.status(400).json({
            success: false,
            message: "OTP expired"
        });
    }

    savedOtp.attempts += 1;

    if (savedOtp.attempts > 5) {
        otpStore.delete(normalizedEmail);

        return res.status(429).json({
            success: false,
            message:
                "Too many incorrect attempts"
        });
    }

    if (savedOtp.otp !== otp.trim()) {
        return res.status(400).json({
            success: false,
            message: "Incorrect OTP"
        });
    }

    otpStore.delete(normalizedEmail);

    const token = crypto
        .randomBytes(32)
        .toString("hex");

    sessionStore.set(token, {
        email: normalizedEmail,
        expiresAt:
            Date.now() + SESSION_EXPIRY_TIME
    });

    res.json({
        success: true,
        message: "OTP verified",
        token,
        expiresIn: SESSION_EXPIRY_TIME
    });
});

app.post("/check-access", (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(401).json({
            success: false,
            allowed: false
        });
    }

    const session =
        sessionStore.get(token);

    if (
        !session ||
        Date.now() > session.expiresAt
    ) {
        sessionStore.delete(token);

        return res.status(401).json({
            success: false,
            allowed: false
        });
    }

    res.json({
        success: true,
        allowed: true,
        expiresAt: session.expiresAt
    });
});

setInterval(() => {
    const now = Date.now();

    for (const [email, data] of otpStore) {
        if (now > data.expiresAt) {
            otpStore.delete(email);
        }
    }

    for (const [token, session] of sessionStore) {
        if (now > session.expiresAt) {
            sessionStore.delete(token);
        }
    }
}, 60 * 1000);

app.listen(PORT, () => {
    console.log(
        `Server running on port ${PORT}`
    );
});
