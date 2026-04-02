const express = require("express");
const fileUpload = require("express-fileupload");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(fileUpload());
app.use(cors());
app.use(express.static("public"));

// ===== FILES =====
const USERS_FILE = "users.json";
const FILES_FILE = "files.json";

if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "{}");
if (!fs.existsSync(FILES_FILE)) fs.writeFileSync(FILES_FILE, "{}");
if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");

// ===== HELPERS =====
function getUsers() {
  return JSON.parse(fs.readFileSync(USERS_FILE));
}
function saveUsers(data) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));
}
function getFiles() {
  return JSON.parse(fs.readFileSync(FILES_FILE));
}
function saveFiles(data) {
  fs.writeFileSync(FILES_FILE, JSON.stringify(data, null, 2));
}

// ===== TOKEN STORE =====
const sessions = {};

// ===== REGISTER =====
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const users = getUsers();

  if (users[username]) return res.send("User exists");

  users[username] = await bcrypt.hash(password, 10);
  saveUsers(users);

  res.redirect("/login.html");
});

// ===== LOGIN =====
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const users = getUsers();

  if (!users[username]) return res.send("User not found");

  const ok = await bcrypt.compare(password, users[username]);
  if (!ok) return res.send("Wrong password");

  const token = crypto.randomBytes(16).toString("hex");
  sessions[token] = username;

  res.send(`
    <script>
      localStorage.setItem("token","${token}");
      window.location="/vault.html";
    </script>
  `);
});

// ===== AUTH =====
function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token || !sessions[token]) return res.status(401).send("Unauthorized");
  req.user = sessions[token];
  next();
}

// ===== UPLOAD =====
app.post("/upload", auth, (req, res) => {
  const file = req.files.file;
  const filePath = path.join("uploads", file.name);

  file.mv(filePath);

  const files = getFiles();
  if (!files[req.user]) files[req.user] = [];

  files[req.user].push(file.name);
  saveFiles(files);

  res.send("Uploaded");
});

// ===== FILE LIST =====
app.get("/files", auth, (req, res) => {
  const files = getFiles();
  res.json(files[req.user] || []);
});

// ===== DOWNLOAD =====
app.get("/download/:name", auth, (req, res) => {
  res.download(path.join(__dirname, "uploads", req.params.name));
});

// ===== DELETE =====
app.get("/delete/:name", auth, (req, res) => {
  const file = req.params.name;

  const filePath = path.join("uploads", file);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

  const files = getFiles();
  files[req.user] = (files[req.user] || []).filter(f => f !== file);
  saveFiles(files);

  res.send("Deleted");
});

// ===== SHARE =====
app.post("/share", auth, (req, res) => {
  const { toUser, fileName } = req.body;
  const files = getFiles();

  if (!files[toUser]) files[toUser] = [];
  files[toUser].push(fileName);

  saveFiles(files);

  res.send("Shared");
});

// ===== LOGOUT =====
app.get("/logout", (req, res) => {
  res.send(`
    <script>
      localStorage.removeItem("token");
      window.location="/login.html";
    </script>
  `);
});

app.listen(PORT, () => console.log("Server running", PORT));
