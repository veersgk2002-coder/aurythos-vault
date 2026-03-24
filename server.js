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
const ALGORITHM = "aes-256-cbc";

function getUserKey(password) {
  return crypto.createHash("sha256").update(password).digest().slice(0, 32);
}

function encryptFile(buffer, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  return Buffer.concat([iv, encrypted]);
}

function decryptFile(buffer, key) {
  const iv = buffer.slice(0, 16);
  const encryptedData = buffer.slice(16);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  return Buffer.concat([decipher.update(encryptedData), decipher.final()]);
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
    const unique = Date.now() + "_" + file.originalname.replace(/\s/g, "_");
    cb(null, unique);
  },
});
const upload = multer({ storage });

// ===== TEMP DATABASE =====
let users = {};
let sharedFiles = {};

// ===== AUTH =====
function auth(req, res, next) {
  if (!req.session.user || !req.session.key) {
    return res.redirect("/");
  }
  next();
}

// ===== HOME =====
app.get("/", (req, res) => {
  res.send(`
  <html>
  <body style="background:#0f2027;color:white;display:flex;justify-content:center;align-items:center;height:100vh;">
    <div style="background:#1c3b45;padding:20px;border-radius:10px;width:300px;">
      <h2>Aurythos Vault</h2>

      <form method="POST" action="/login">
        <input name="username" placeholder="Username" required/><br/>
        <input type="password" name="password" placeholder="Password" required/><br/>
        <button>Login</button>
      </form>

      <br/>

      <form method="POST" action="/register">
        <input name="username" placeholder="Username" required/><br/>
        <input type="password" name="password" placeholder="Password" required/><br/>
        <button>Register</button>
      </form>
    </div>
  </body>
  </html>
  `);
});

// ===== REGISTER (AUTO LOGIN FIXED) =====
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (users[username]) return res.send("User already exists");

  const hashedPassword = await bcrypt.hash(password, 10);

  users[username] = {
    username,
    password: hashedPassword,
    plan: "free",
  };

  // 🔐 AUTO LOGIN
  const key = getUserKey(password);
  req.session.user = username;
  req.session.key = key;

  res.redirect("/dashboard");
});

// ===== LOGIN =====
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users[username];
  if (!user) return res.send("User not found");

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.send("Wrong password");

  const key = getUserKey(password);
  req.session.user = username;
  req.session.key = key;

  res.redirect("/dashboard");
});

// ===== DASHBOARD =====
app.get("/dashboard", auth, async (req, res) => {
  const username = req.session.user;

  const { data } = await supabase.storage.from(BUCKET).list(username);

  let filesHTML = "";
  if (data) {
    data.forEach((file) => {
      filesHTML += `
      <div style="background:#fff;color:#000;margin:10px;padding:10px;border-radius:5px;">
        ${file.name}
        <br/>
        <form method="POST" action="/share">
          <input type="hidden" name="file" value="${file.name}" />
          <input name="to" placeholder="username"/>
          <button>Share</button>
        </form>
        <a href="/download/${file.name}">Download</a>
        <a href="/delete/${file.name}">Delete</a>
      </div>`;
    });
  }

  res.send(`
  <html>
  <body style="background:#0f2027;color:white;padding:20px;">
    <h2>Welcome ${username}</h2>

    <a href="/upgrade">Upgrade to Premium</a>

    <form method="POST" action="/upload" enctype="multipart/form-data">
      <input type="file" name="file" required/>
      <button>Upload</button>
    </form>

    <h3>Your Files</h3>
    ${filesHTML || "No files"}

    <br/><a href="/logout">Logout</a>
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

  const fileBuffer = fs.readFileSync(req.file.path);
  const encryptedBuffer = encryptFile(fileBuffer, req.session.key);

  await supabase.storage
    .from(BUCKET)
    .upload(`${username}/${req.file.filename}`, encryptedBuffer);

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
  const decrypted = decryptFile(buffer, req.session.key);

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
  res.send("Upgraded to Premium ✅");
});

// ===== LOGOUT =====
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// ===== SERVER =====
const start = (p) => {
  const s = app.listen(p, () =>
    console.log("Running on port", p)
  );

  s.on("error", (e) => {
    if (e.code === "EADDRINUSE") start(p + 1);
  });
};

start(PORT);
