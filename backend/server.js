require("dotenv").config();

const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");

const app = express();
const PORT = process.env.PORT || 5000;
const TOKEN_TTL_DAYS = 7;

app.use(cors());
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

function serializeUser(user) {
  return {
    id: user._id,
    name: user.name,
    email: user.email,
    createdAt: user.createdAt,
  };
}

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

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

    if (password.length < 8) {
      return res
        .status(400)
        .json({ message: "Password must be at least 8 characters long." });
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

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
