const express = require("express");
const multer = require("multer");
const crypto = require("crypto");
const axios = require("axios");
const path = require("path");
require("dotenv").config();

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));

const upload = multer({ storage: multer.memoryStorage() });

// ===== SUPABASE =====
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

// ===== CLOUDINARY =====
const cloudinary = require("cloudinary").v2;
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});

// ===== SESSION =====
let currentUser = null;

// ===== ENCRYPTION =====
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex");
}

// ===== ROUTES =====

// HOME
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

// REGISTER
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const existing = await axios.get(`${SUPABASE_URL}/rest/v1/users?username=eq.${username}`, {
    headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` }
  });

  if (existing.data.length > 0) {
    return res.json({ error: "User already exists" });
  }

  const salt = crypto.randomBytes(16).toString("hex");
  const hashed = hashPassword(password, salt);

  await axios.post(`${SUPABASE_URL}/rest/v1/users`, {
    username,
    password: hashed,
    salt,
    plan: "free"
  }, {
    headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` }
  });

  res.json({ success: "Registered successfully" });
});

// LOGIN
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await axios.get(`${SUPABASE_URL}/rest/v1/users?username=eq.${username}`, {
    headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` }
  });

  if (user.data.length === 0) return res.json({ error: "User not found" });

  const dbUser = user.data[0];
  const hashed = hashPassword(password, dbUser.salt);

  if (hashed !== dbUser.password) {
    return res.json({ error: "Wrong password" });
  }

  currentUser = username;
  res.json({ success: "Login success" });
});

// GET FILES
app.get("/files", async (req, res) => {
  if (!currentUser) return res.json([]);

  const files = await axios.get(`${SUPABASE_URL}/rest/v1/files?username=eq.${currentUser}`, {
    headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` }
  });

  res.json(files.data);
});

// UPLOAD
app.post("/upload", upload.array("files"), async (req, res) => {
  if (!currentUser) return res.json({ error: "Login first" });

  const user = await axios.get(`${SUPABASE_URL}/rest/v1/users?username=eq.${currentUser}`, {
    headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` }
  });

  const plan = user.data[0].plan;

  const existing = await axios.get(`${SUPABASE_URL}/rest/v1/files?username=eq.${currentUser}`, {
    headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` }
  });

  if (plan === "free" && existing.data.length + req.files.length > 5) {
    return res.json({ error: "Limit reached (5 files)" });
  }

  for (let file of req.files) {
    const iv = crypto.randomBytes(16).toString("hex");

    const uploadRes = await cloudinary.uploader.upload_stream(
      { resource_type: "auto" },
      async (err, result) => {
        await axios.post(`${SUPABASE_URL}/rest/v1/files`, {
          username: currentUser,
          file_name: file.originalname,
          file_url: result.secure_url,
          size: file.size,
          iv
        }, {
          headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` }
        });
      }
    );

    uploadRes.end(file.buffer);
  }

  res.json({ success: "Uploaded" });
});

// DELETE
app.post("/delete", async (req, res) => {
  const { id } = req.body;

  await axios.delete(`${SUPABASE_URL}/rest/v1/files?id=eq.${id}`, {
    headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` }
  });

  res.json({ success: true });
});

// SHARE
app.post("/share", async (req, res) => {
  const { id, toUser } = req.body;

  const file = await axios.get(`${SUPABASE_URL}/rest/v1/files?id=eq.${id}`, {
    headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` }
  });

  if (file.data.length === 0) return res.json({ error: "File not found" });

  await axios.post(`${SUPABASE_URL}/rest/v1/files`, {
    username: toUser,
    file_name: file.data[0].file_name,
    file_url: file.data[0].file_url,
    size: file.data[0].size,
    iv: file.data[0].iv
  }, {
    headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` }
  });

  res.json({ success: "Shared" });
});

// UPGRADE
app.post("/upgrade", async (req, res) => {
  await axios.patch(`${SUPABASE_URL}/rest/v1/users?username=eq.${currentUser}`, {
    plan: "premium"
  }, {
    headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` }
  });

  res.json({ success: "Upgraded" });
});

// START
app.listen(10000, () => console.log("Server running"));
