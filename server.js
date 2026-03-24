const express = require("express");
const session = require("express-session");
const multer = require("multer");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();

// ===== CONFIG =====
const PORT = process.env.PORT || 3000;

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

const BUCKET = "files";

// ===== ENCRYPTION =====
const ALGO = "aes-256-cbc";

function getKey(password) {
  return crypto.createHash("sha256").update(password).digest().slice(0, 32);
}

function encrypt(buffer, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  return Buffer.concat([iv, encrypted]);
}

function decrypt(buffer, key) {
  const iv = buffer.slice(0, 16);
  const data = buffer.slice(16);
  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

// ===== MIDDLEWARE =====
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: "aurythos-secret",
    resave: false,
    saveUninitialized: false,
  })
);

// ===== FILE STORAGE =====
const storage = multer.diskStorage({
  destination: "./temp",
  filename: (req, file, cb) => {
    const name = Date.now() + "_" + file.originalname.replace(/\s/g, "_");
    cb(null, name);
  },
});
const upload = multer({ storage });

// ===== MEMORY DB =====
let users = {};

// ===== AUTH =====
function auth(req, res, next) {
  if (!req.session.user || !req.session.key) return res.redirect("/");
  next();
}

// ===== HOME =====
app.get("/", (req, res) => {
  res.send(`
  <html>
  <body style="background:#0f2027;color:white;display:flex;justify-content:center;align-items:center;height:100vh;">
    <div style="background:#1c3b45;padding:25px;border-radius:12px;width:300px;">
      <h2>Aurythos Vault</h2>

      <form method="POST" action="/login">
        <input name="username" placeholder="Username" required/><br/><br/>
        <input type="password" name="password" placeholder="Password" required/><br/><br/>
        <button>Login</button>
      </form>

      <br/>

      <form method="POST" action="/register">
        <input name="username" placeholder="Username" required/><br/><br/>
        <input type="password" name="password" placeholder="Password" required/><br/><br/>
        <button>Register</button>
      </form>
    </div>
  </body>
  </html>
  `);
});

// ===== REGISTER =====
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (users[username]) return res.send("User exists");

  const hash = await bcrypt.hash(password, 10);

  users[username] = {
    password: hash,
    plan: "free",
  };

  // AUTO LOGIN
  req.session.user = username;
  req.session.key = getKey(password);

  res.redirect("/dashboard");
});

// ===== LOGIN =====
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users[username];
  if (!user) return res.send("User not found");

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.send("Wrong password");

  req.session.user = username;
  req.session.key = getKey(password);

  res.redirect("/dashboard");
});

// ===== DASHBOARD =====
app.get("/dashboard", auth, async (req, res) => {
  const username = req.session.user;

  const { data } = await supabase.storage.from(BUCKET).list(username);

  let files = "";

  if (data && data.length > 0) {
    data.forEach((f) => {
      files += `
      <div style="background:#ffffff10;padding:10px;margin:10px;border-radius:8px;">
        <b>${f.name}</b><br/>
        <a href="/download/${f.name}">Download</a> |
        <a href="/delete/${f.name}">Delete</a>
      </div>`;
    });
  } else {
    files = "<p>No files uploaded</p>";
  }

  res.send(`
  <html>
  <body style="background:#0f2027;color:white;font-family:sans-serif;padding:20px;">
    
    <h2>Welcome ${username}</h2>

    <a href="/upgrade" style="color:yellow;">Upgrade to Premium</a>

    <br/><br/>

    <form method="POST" action="/upload" enctype="multipart/form-data">
      <input type="file" name="file" required/>
      <button>Upload</button>
    </form>

    <h3>Your Files</h3>
    ${files}

    <br/>
    <a href="/logout">Logout</a>

  </body>
  </html>
  `);
});

// ===== UPLOAD =====
app.post("/upload", auth, upload.single("file"), async (req, res) => {
  const username = req.session.user;

  const { data } = await supabase.storage.from(BUCKET).list(username);

  if (users[username].plan === "free" && data.length >= 3) {
    return res.send("Upgrade to premium to upload more files");
  }

  const buffer = fs.readFileSync(req.file.path);
  const encrypted = encrypt(buffer, req.session.key);

  await supabase.storage
    .from(BUCKET)
    .upload(`${username}/${req.file.filename}`, encrypted);

  fs.unlinkSync(req.file.path);

  res.redirect("/dashboard");
});

// ===== DOWNLOAD =====
app.get("/download/:file", auth, async (req, res) => {
  const username = req.session.user;

  const { data } = await supabase.storage
    .from(BUCKET)
    .download(`${username}/${req.params.file}`);

  const buffer = Buffer.from(await data.arrayBuffer());
  const decrypted = decrypt(buffer, req.session.key);

  res.setHeader(
    "Content-Disposition",
    `attachment; filename="${req.params.file}"`
  );

  res.send(decrypted);
});

// ===== DELETE =====
app.get("/delete/:file", auth, async (req, res) => {
  const username = req.session.user;

  await supabase.storage
    .from(BUCKET)
    .remove([`${username}/${req.params.file}`]);

  res.redirect("/dashboard");
});

// ===== UPGRADE =====
app.get("/upgrade", auth, (req, res) => {
  users[req.session.user].plan = "premium";
  res.send("Premium activated ✅");
});

// ===== LOGOUT =====
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// ===== SERVER =====
app.listen(PORT, () => {
  console.log("Running on port", PORT);
});
