const express = require("express");
const multer = require("multer");
const crypto = require("crypto");
const axios = require("axios");
const path = require("path");

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ✅ SHARE FILE ROUTE
app.get("/share/:id", async (req, res) => {
    const fileId = req.params.id;

    try {
        const response = await fetch(`${process.env.SUPABASE_URL}/rest/v1/files?id=eq.${fileId}`, {
            headers: {
                apikey: process.env.SUPABASE_KEY,
                Authorization: `Bearer ${process.env.SUPABASE_KEY}`
            }
        });

        const data = await response.json();

        if (!data || data.length === 0) {
            return res.send("File not found");
        }

        // redirect to actual file
        res.redirect(data[0].file_url);

    } catch (err) {
        res.send("Error loading file");
    }
});
// 🔥 FIX: force correct static folder
app.use(express.static(path.join(__dirname, "public")));

const upload = multer({ storage: multer.memoryStorage() });

// ===== CONFIG =====
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

const cloudinary = require("cloudinary").v2;
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});

let currentUser = null;

// ===== ENCRYPTION =====
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex");
}

// ===== HOME =====
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

// ===== REGISTER =====
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

  res.json({ success: "Registered" });
});

// ===== LOGIN =====
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await axios.get(`${SUPABASE_URL}/rest/v1/users?username=eq.${username}`, {
    headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` }
  });

  if (user.data.length === 0) return res.json({ error: "User not found" });

  const db = user.data[0];
  const hashed = hashPassword(password, db.salt);

  if (hashed !== db.password) return res.json({ error: "Wrong password" });

  currentUser = username;
  res.json({ success: true });
});

// ===== FILES =====
app.get("/files", async (req, res) => {
  if (!currentUser) return res.json([]);

  const files = await axios.get(`${SUPABASE_URL}/rest/v1/files?username=eq.${currentUser}`, {
    headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` }
  });

  res.json(files.data);
});

// ===== UPLOAD =====
app.post("/upload", upload.array("files"), async (req, res) => {
  if (!currentUser) return res.json({ error: "Login first" });

  const existing = await axios.get(`${SUPABASE_URL}/rest/v1/files?username=eq.${currentUser}`, {
    headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` }
  });

  if (existing.data.length + req.files.length > 5) {
    return res.json({ error: "Limit 5 files" });
  }

  for (let file of req.files) {
    const iv = crypto.randomBytes(16).toString("hex");

    const stream = cloudinary.uploader.upload_stream(
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

    stream.end(file.buffer);
  }

  res.json({ success: "Uploaded" });
});

// ===== DELETE =====
app.post("/delete", async (req, res) => {
  await axios.delete(`${SUPABASE_URL}/rest/v1/files?id=eq.${req.body.id}`, {
    headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` }
  });

  res.json({ success: true });
});

// ===== SHARE =====
app.post("/share", async (req, res) => {
  const { id, toUser } = req.body;

  const file = await axios.get(`${SUPABASE_URL}/rest/v1/files?id=eq.${id}`, {
    headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` }
  });

  const f = file.data[0];

  await axios.post(`${SUPABASE_URL}/rest/v1/files`, {
    username: toUser,
    file_name: f.file_name,
    file_url: f.file_url,
    size: f.size,
    iv: f.iv
  }, {
    headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` }
  });

  res.json({ success: "Shared" });
});

// ===== START =====
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
