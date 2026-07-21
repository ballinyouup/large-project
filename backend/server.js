require("dotenv").config();

const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");

const app = express();
const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST || "0.0.0.0";
const TOKEN_TTL_DAYS = 7;
const RESET_TOKEN_TTL_MINUTES = 30;

const corsOrigins = (process.env.CORS_ORIGIN || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: corsOrigins.length > 0 ? corsOrigins : true,
  })
);
app.use(express.json());

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      trim: true,
      maxlength: 80,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    passwordHash: {
      type: String,
      required: true,
    },
    passwordSalt: {
      type: String,
      required: true,
    },
    activeTokens: [
      {
        tokenHash: {
          type: String,
          required: true,
        },
        expiresAt: {
          type: Date,
          required: true,
        },
        createdAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],
    resetPasswordTokenHash: String,
    resetPasswordExpiresAt: Date,
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const passwordHash = crypto
    .pbkdf2Sync(password, salt, 120000, 64, "sha512")
    .toString("hex");

  return { passwordHash, passwordSalt: salt };
}

function verifyPassword(password, user) {
  const { passwordHash } = hashPassword(password, user.passwordSalt);
  return crypto.timingSafeEqual(
    Buffer.from(passwordHash, "hex"),
    Buffer.from(user.passwordHash, "hex")
  );
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function createSession(user) {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000);

  user.activeTokens = user.activeTokens.filter(
    (session) => session.expiresAt > new Date()
  );
  user.activeTokens.push({ tokenHash: hashToken(token), expiresAt });

  return { token, expiresAt };
}

function createPasswordReset(user) {
  const resetToken = crypto.randomBytes(32).toString("hex");

  user.resetPasswordTokenHash = hashToken(resetToken);
  user.resetPasswordExpiresAt = new Date(
    Date.now() + RESET_TOKEN_TTL_MINUTES * 60 * 1000
  );

  return resetToken;
}

function isStrongPassword(password) {
  return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{10,}$/.test(
    password
  );
}

async function sendPasswordResetEmail(email, resetToken) {
  const clientUrl =
    process.env.FRONTEND_URL || process.env.CLIENT_URL || "http://127.0.0.1:5173";
  const resetUrl = `${clientUrl}/reset-password?token=${resetToken}`;

  if (process.env.RESEND_API_KEY && process.env.RESEND_FROM_EMAIL) {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: process.env.RESEND_FROM_EMAIL,
        to: [email],
        subject: "Reset your MoneySim password",
        text: `Reset your MoneySim password here: ${resetUrl}`,
      }),
    });

    if (!response.ok) {
      throw new Error(`Resend returned ${response.status}`);
    }

    return { delivered: true };
  }

  if (!process.env.SENDGRID_API_KEY || !process.env.SENDGRID_FROM_EMAIL) {
    console.log(`Password reset link for ${email}: ${resetUrl}`);
    return { delivered: false, resetUrl };
  }

  const response = await fetch("https://api.sendgrid.com/v3/mail/send", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.SENDGRID_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      personalizations: [{ to: [{ email }] }],
      from: { email: process.env.SENDGRID_FROM_EMAIL, name: "MoneySim" },
      subject: "Reset your MoneySim password",
      content: [
        {
          type: "text/plain",
          value: `Reset your MoneySim password here: ${resetUrl}`,
        },
      ],
    }),
  });

  if (!response.ok) {
    throw new Error(`SendGrid returned ${response.status}`);
  }

  return { delivered: true };
}

function serializeUser(user) {
  return {
    id: user._id,
    name: user.name,
    email: user.email,
    createdAt: user.createdAt,
  };
}

function connectDatabase() {
  const mongoUri = process.env.MONGO_URI || process.env.MONGODB_URI;

  return mongoose
    .connect(mongoUri)
    .then(() => console.log("MongoDB connected"))
    .catch((err) => console.error("MongoDB connection error:", err));
}

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", database: mongoose.connection.readyState });
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!isValidEmail(email)) {
      return res.status(400).json({ message: "A valid email is required." });
    }

    if (!isStrongPassword(password)) {
      return res.status(400).json({
        message:
          "Password must be at least 10 characters and include uppercase, lowercase, number, and symbol.",
      });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "Email is already registered." });
    }

    const passwordFields = hashPassword(password);
    const user = new User({ name, email, ...passwordFields });
    const session = createSession(user);
    await user.save();

    return res.status(201).json({ user: serializeUser(user), ...session });
  } catch (error) {
    console.error("Register error:", error);
    return res.status(500).json({ message: "Unable to register user." });
  }
});

app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);

    if (!isValidEmail(email)) {
      return res.status(400).json({ message: "A valid email is required." });
    }

    const user = await User.findOne({ email });
    let mailResult;
    if (user) {
      const resetToken = createPasswordReset(user);
      await user.save();
      mailResult = await sendPasswordResetEmail(email, resetToken);
    }

    const payload = {
      message:
        "If that email is registered, a password reset link has been sent.",
    };

    if (process.env.NODE_ENV !== "production" && mailResult?.resetUrl) {
      payload.resetUrl = mailResult.resetUrl;
    }

    return res.json(payload);
  } catch (error) {
    console.error("Forgot password error:", error);
    return res
      .status(500)
      .json({ message: "Unable to start password recovery." });
  }
});

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const token = String(req.body.token || "");
    const password = String(req.body.password || "");

    if (!token) {
      return res.status(400).json({ message: "Reset token is required." });
    }

    if (!isStrongPassword(password)) {
      return res.status(400).json({
        message:
          "Password must be at least 10 characters and include uppercase, lowercase, number, and symbol.",
      });
    }

    const user = await User.findOne({
      resetPasswordTokenHash: hashToken(token),
      resetPasswordExpiresAt: { $gt: new Date() },
    });

    if (!user) {
      return res
        .status(400)
        .json({ message: "Reset token is invalid or expired." });
    }

    const passwordFields = hashPassword(password);
    user.passwordHash = passwordFields.passwordHash;
    user.passwordSalt = passwordFields.passwordSalt;
    user.resetPasswordTokenHash = undefined;
    user.resetPasswordExpiresAt = undefined;
    user.activeTokens = [];
    await user.save();

    return res.json({ message: "Password reset successfully." });
  } catch (error) {
    console.error("Reset password error:", error);
    return res.status(500).json({ message: "Unable to reset password." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    const user = await User.findOne({ email });

    if (!user || !verifyPassword(password, user)) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const session = createSession(user);
    await user.save();

    return res.json({ user: serializeUser(user), ...session });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ message: "Unable to log in." });
  }
});

app.post("/api/auth/logout", async (req, res) => {
  try {
    const authorization = req.get("Authorization") || "";
    const token = authorization.startsWith("Bearer ")
      ? authorization.slice("Bearer ".length)
      : req.body.token;

    if (!token) {
      return res.status(400).json({ message: "Bearer token is required." });
    }

    const result = await User.updateOne(
      { "activeTokens.tokenHash": hashToken(token) },
      { $pull: { activeTokens: { tokenHash: hashToken(token) } } }
    );

    if (result.modifiedCount === 0) {
      return res.status(401).json({ message: "Invalid or expired session." });
    }

    return res.json({ message: "Logged out successfully." });
  } catch (error) {
    console.error("Logout error:", error);
    return res.status(500).json({ message: "Unable to log out." });
  }
});

if (require.main === module) {
  connectDatabase().finally(() => {
    app.listen(PORT, HOST, () => {
      console.log(`Server running on ${HOST}:${PORT}`);
    });
  });
}

module.exports = {
  app,
  connectDatabase,
  createPasswordReset,
  hashPassword,
  hashToken,
  isStrongPassword,
  normalizeEmail,
  verifyPassword,
};
