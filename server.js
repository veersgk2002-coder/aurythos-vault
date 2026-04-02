const express = require("express");
const session = require("express-session");
const fileUpload = require("express-fileupload");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");

const app = express();

// ===== CONFIG =====
const PORT = process.env.PORT || 4000;
const DATA_PATH = __dirname;
const UPLOAD_PATH = path.join(__dirname, "uploads");

// ensure files exist
if (!fs.existsSync(UPLOAD_PATH)) fs.mkdirSync(UPLOAD_PATH);
if (!fs.existsSync("users.json")) fs.writeFileSync("users.json", "[]");
if (!fs.existsSync("files.json")) fs.writeFileSync("files.json", "[]");

// ===== MIDDLEWARE =====
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(fileUpload());

app.use(session({
  secret: "aurythos_secret",
  resave: false,
  saveUninitialized: false
}));

app.use(express.static("public"));

// ===== HELPERS =====
function readJSON(file) {
  return JSON.parse(fs.readFileSync(path.join(DATA_PATH, file)));
}

function writeJSON(file, data) {
  fs.writeFileSync(path.join(DATA_PATH, file), JSON.stringify(data, null, 2));
}

// ===== REGISTER =====
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  let users = readJSON("users.json");

  if (users.find(u => u.username === username)) {
    return res.json({ success: false, message: "User exists" });
  }

  const hashed = await bcrypt.hash(password, 10);

  users.push({ username, password: hashed });
  writeJSON("users.json", users);

  res.json({ success: true });
});

// ===== LOGIN =====
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  let users = readJSON("users.json");
  const user = users.find(u => u.username === username);

  if (!user) return res.json({ success: false });

  const match = await bcrypt.compare(password, user.password);

  if (!match) return res.json({ success: false });

  req.session.user = username;
  res.json({ success: true });
});

// ===== UPLOAD =====
app.post("/upload", (req, res) => {
  if (!req.session.user) return res.sendStatus(401);

  const file = req.files.file;
  const filename = Date.now() + "_" + file.name;

  const filepath = path.join(UPLOAD_PATH, filename);
  file.mv(filepath);

  let files = readJSON("files.json");
  files.push({ owner: req.session.user, name: filename });

  writeJSON("files.json", files);

  res.json({ success: true });
});

// ===== GET FILES =====
app.get("/files", (req, res) => {
  if (!req.session.user) return res.sendStatus(401);

  let files = readJSON("files.json");
  const userFiles = files.filter(f => f.owner === req.session.user);

  res.json(userFiles);
});

// ===== DOWNLOAD =====
app.get("/download/:name", (req, res) => {
  const filePath = path.join(UPLOAD_PATH, req.params.name);
  res.download(filePath);
});

// ===== DELETE =====
app.post("/delete", (req, res) => {
  const { name } = req.body;

  let files = readJSON("files.json");
  files = files.filter(f => f.name !== name);

  writeJSON("files.json", files);

  fs.unlinkSync(path.join(UPLOAD_PATH, name));

  res.json({ success: true });
});

// ===== SHARE =====
app.post("/share", (req, res) => {
  const { name, toUser } = req.body;

  let files = readJSON("files.json");

  files.push({ owner: toUser, name });

  writeJSON("files.json", files);

  res.json({ success: true });
});

// ===== LOGOUT =====
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// ===== START =====
app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
