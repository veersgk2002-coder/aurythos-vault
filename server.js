const express = require("express");
const session = require("express-session");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

// ===== ENCRYPTION =====
function getKey(password) {
  return crypto.createHash("sha256").update(password).digest();
}

function encrypt(buffer, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  return Buffer.concat([iv, cipher.update(buffer), cipher.final()]);
}

function decrypt(buffer, key) {
  const iv = buffer.slice(0, 16);
  const data = buffer.slice(16);
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
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

// ===== MULTER MEMORY STORAGE =====
const upload = multer({ storage: multer.memoryStorage() });

// ===== DATABASE (IN MEMORY) =====
let users = {};
let filesDB = {}; // { username: [ {name, data} ] }

// ===== AUTH =====
function auth(req, res, next) {
  if (!req.session.user || !req.session.key) return res.redirect("/");
  next();
}

// ===== HOME =====
app.get("/", (req, res) => {
  res.send(`
  <html>
  <style>
    body { background:#0f2027;color:white;display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;}
    .box { background:#1c3b45;padding:25px;border-radius:10px;width:300px;}
    input,button { width:100%;padding:10px;margin:5px 0;}
  </style>
  <body>
    <div class="box">
      <h2>Aurythos Vault</h2>

      <form method="POST" action="/login">
        <input name="username" placeholder="Username" required/>
        <input type="password" name="password" placeholder="Password" required/>
        <button>Login</button>
      </form>

      <form method="POST" action="/register">
        <input name="username" placeholder="Username" required/>
        <input type="password" name="password" placeholder="Password" required/>
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

  users[username] = {
    password: await bcrypt.hash(password, 10),
  };

  req.session.user = username;
  req.session.key = getKey(password);

  res.redirect("/dashboard");
});

// ===== LOGIN =====
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users[username];
  if (!user) return res.send("User not found");

  if (!(await bcrypt.compare(password, user.password)))
    return res.send("Wrong password");

  req.session.user = username;
  req.session.key = getKey(password);

  res.redirect("/dashboard");
});

// ===== DASHBOARD =====
app.get("/dashboard", auth, (req, res) => {
  const username = req.session.user;
  const files = filesDB[username] || [];

  let list = files.length
    ? files.map((f, i) =>
        `<div>${f.name} <a href="/download/${i}">Download</a></div>`
      ).join("")
    : "<p>No files</p>";

  res.send(`
  <html>
  <style>
    body { background:#0f2027;color:white;padding:20px;font-family:sans-serif;}
    input,button { margin:5px 0;}
  </style>
  <body>

    <h2>Welcome ${username}</h2>

    <form method="POST" action="/upload" enctype="multipart/form-data">
      <input type="file" name="files" multiple/>
      <button>Upload</button>
    </form>

    <h3>Your Files</h3>
    ${list}

    <br/>
    <a href="/logout">Logout</a>

  </body>
  </html>
  `);
});

// ===== UPLOAD =====
app.post("/upload", auth, upload.array("files"), (req, res) => {
  const username = req.session.user;

  if (!filesDB[username]) filesDB[username] = [];

  for (let file of req.files) {
    const encrypted = encrypt(file.buffer, req.session.key);

    filesDB[username].push({
      name: file.originalname,
      data: encrypted,
    });
  }

  res.redirect("/dashboard");
});

// ===== DOWNLOAD =====
app.get("/download/:id", auth, (req, res) => {
  const username = req.session.user;
  const file = filesDB[username][req.params.id];

  const decrypted = decrypt(file.data, req.session.key);

  res.setHeader("Content-Disposition", `attachment; filename="${file.name}"`);
  res.send(decrypted);
});

// ===== LOGOUT =====
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// ===== START =====
app.listen(PORT, () => {
  console.log("Server running...");
});
