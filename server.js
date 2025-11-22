import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mysql from "mysql2/promise";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import multerS3 from "multer-s3";
import { S3Client } from "@aws-sdk/client-s3";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ==== DATABASE CONNECTION (SAFE WAY - NO TOP LEVEL AWAIT) ====
let db;
(async () => {
  try {
    db = await mysql.createPool({
      host: process.env.DB_HOST || "localhost",
      user: process.env.DB_USER || "root",
      password: process.env.DB_PASSWORD || "",
      database: process.env.DB_NAME || "clouddb",
      port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : 3306,
      waitForConnections: true,
      connectionLimit: 10
    });

    await db.query(
      `CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL DEFAULT 'User',
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`
    );
    console.log("Database connected & table ready");
  } catch (err) {
    console.error("DB Error:", err.message);
    process.exit(1);
  }
})();

// ==== AWS S3 ====
const s3 = new S3Client({
  region: process.env.AWS_REGION, // e.g. 'eu-north-1'
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});

const upload = multer({
  storage: multerS3({
    s3,
    bucket: process.env.AWS_S3_BUCKET,
    // acl: "public-read", // <-- REMOVED, do NOT use this with bucket owner enforced
    key: (req, file, cb) => cb(null, `medilocker/${Date.now()}_${file.originalname}`)
  })
});

// ==== ROUTES ====
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ message: "All fields required" });

  try {
    const hashed = await bcrypt.hash(password, 10);
    await db.query(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name.trim() || "User", email.trim().toLowerCase(), hashed]
    );
    res.json({ success: true, message: "Account created!" });
  } catch (err) {
    res.status(400).json({ message: "Email already exists" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const [rows] = await db.query(
      "SELECT * FROM users WHERE email = ?",
      [email.trim().toLowerCase()]
    );
    if (rows.length === 0)
      return res.status(401).json({ message: "Invalid email or password" });

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ message: "Invalid email or password" });

    // 100% SAFE NAME
    const safeName = user.name?.trim() || "User";

    const token = jwt.sign(
      { id: user.id, name: safeName, email: user.email },
      process.env.JWT_SECRET || "medilocker_secret_2025",
      { expiresIn: "30d" }
    );

    res.json({ success: true, token });
  } catch (err) {
    console.error("Login failed:", err.message);
    res.status(500).json({ message: "Server error — check terminal" });
  }
});

// Improved upload endpoint (with error handling)
app.post("/api/upload", (req, res) => {
  upload.single("file")(req, res, function (err) {
    if (err) {
      console.error("Upload Error:", err.message);
      return res.status(500).json({ success: false, message: "Upload failed", error: err.message });
    }
    if (!req.file)
      return res.status(400).json({ success: false, message: "No file uploaded" });
    res.json({ success: true, url: req.file.location });
  });
});

// ==== START SERVER ====
const PORT = process.env.PORT ? parseInt(process.env.PORT) : 5001;
app.listen(PORT, () => {
  console.log("MEDILOCKER IS 100% LIVE!");
  console.log(`Go to → http://127.0.0.1:${PORT}`);
});
