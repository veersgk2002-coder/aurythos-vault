const express = require("express");
const multer = require("multer");
const axios = require("axios");
const crypto = require("crypto");
const cloudinary = require("cloudinary").v2;
const path = require("path");

const app = express();

// ===== MIDDLEWARE =====
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 👉 SERVE FRONTEND
app.use(express.static("public"));

// ===== CONFIG =====
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});

const upload = multer({ storage: multer.memoryStorage() });

// ===== HEALTH CHECK =====
app.get("/health", (req, res) => {
  res.send("Aurythos running 🚀");
});

// ===== REGISTER =====
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const salt = crypto.randomBytes(16).toString("hex");
  const hashed = crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex");

  await axios.post(`${SUPABASE_URL}/rest/v1/users`, {
    username,
    password: hashed,
    salt
  }, {
    headers: {
      apikey: SUPABASE_KEY,
      Authorization: `Bearer ${SUPABASE_KEY}`
    }
  });

  res.json({ success: true });
});

// ===== LOGIN =====
let currentUser = null;

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await axios.get(`${SUPABASE_URL}/rest/v1/users?username=eq.${username}`, {
    headers: {
      apikey: SUPABASE_KEY,
      Authorization: `Bearer ${SUPABASE_KEY}`
    }
  });

  if (!user.data.length) return res.json({ error: "User not found" });

  const db = user.data[0];
  const hashed = crypto.pbkdf2Sync(password, db.salt, 1000, 64, "sha512").toString("hex");

  if (hashed !== db.password) return res.json({ error: "Wrong password" });

  currentUser = username;
  res.json({ success: true });
});

// ===== UPLOAD =====
app.post("/upload", upload.array("files"), async (req, res) => {
  if (!currentUser) return res.json({ error: "Login required" });

  try {
    for (let file of req.files) {
      const uploadStream = cloudinary.uploader.upload_stream(
        { resource_type: "auto" },
        async (err, result) => {
          if (err) return console.error(err);

          await axios.post(`${SUPABASE_URL}/rest/v1/files`, {
            username: currentUser,
            file_name: file.originalname,
            file_url: result.secure_url,
            size: file.size
          }, {
            headers: {
              apikey: SUPABASE_KEY,
              Authorization: `Bearer ${SUPABASE_KEY}`
            }
          });
        }
      );

      uploadStream.end(file.buffer);
    }

    res.json({ success: true });

  } catch (err) {
    console.error(err);
    res.json({ error: "Upload failed" });
  }
});

// ===== GET FILES =====
app.get("/files", async (req, res) => {
  if (!currentUser) return res.json([]);

  const files = await axios.get(
    `${SUPABASE_URL}/rest/v1/files?username=eq.${currentUser}`,
    {
      headers: {
        apikey: SUPABASE_KEY,
        Authorization: `Bearer ${SUPABASE_KEY}`
      }
    }
  );

  res.json(files.data);
});

// ===== DELETE =====
app.post("/delete", async (req, res) => {
  const { id } = req.body;

  await axios.delete(`${SUPABASE_URL}/rest/v1/files?id=eq.${id}`, {
    headers: {
      apikey: SUPABASE_KEY,
      Authorization: `Bearer ${SUPABASE_KEY}`
    }
  });

  res.json({ success: true });
});

// ===== SHARE =====
app.post("/share", async (req, res) => {
  const { id, toUser } = req.body;

  try {
    // check user exists
    const userCheck = await axios.get(
      `${SUPABASE_URL}/rest/v1/users?username=eq.${toUser}`,
      {
        headers: {
          apikey: SUPABASE_KEY,
          Authorization: `Bearer ${SUPABASE_KEY}`
        }
      }
    );

    if (!userCheck.data.length) {
      return res.json({ error: "User not found" });
    }

    // get file
    const file = await axios.get(
      `${SUPABASE_URL}/rest/v1/files?id=eq.${id}`,
      {
        headers: {
          apikey: SUPABASE_KEY,
          Authorization: `Bearer ${SUPABASE_KEY}`
        }
      }
    );

    const f = file.data[0];

    // duplicate file for new user
    await axios.post(
      `${SUPABASE_URL}/rest/v1/files`,
      {
        username: toUser,
        file_name: f.file_name,
        file_url: f.file_url,
        size: f.size
      },
      {
        headers: {
          apikey: SUPABASE_KEY,
          Authorization: `Bearer ${SUPABASE_KEY}`
        }
      }
    );

    res.json({ success: true });

  } catch (err) {
    console.error(err);
    res.json({ error: "Share failed" });
  }
});

// ===== START SERVER =====
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
