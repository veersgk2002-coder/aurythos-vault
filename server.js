const express = require("express");
const session = require("express-session");
const fileUpload = require("express-fileupload");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 4000;

// ===== MIDDLEWARE =====
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(fileUpload());
app.use(cors());

app.set('trust proxy', 1);

app.use(session({
  secret: "aurythos_secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: "none"
  }
}));

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

// ===== ROUTES =====

// Register
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const users = getUsers();

  if (users[username]) {
    return res.send("User already exists");
  }

  const hashed = await bcrypt.hash(password, 10);
  users[username] = hashed;
  saveUsers(users);

  res.redirect("/login.html");
});

// Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const users = getUsers();

  if (!users[username]) {
    return res.send("User not found");
  }

  const match = await bcrypt.compare(password, users[username]);

  if (!match) {
    return res.send("Wrong password");
  }

  req.session.user = username;

  res.redirect("/vault.html");
});

// Upload
app.post("/upload", (req, res) => {
  if (!req.session.user) return res.redirect("/login.html");

  const file = req.files.file;
  const filePath = path.join("uploads", file.name);

  file.mv(filePath);

  const files = getFiles();

  if (!files[req.session.user]) {
    files[req.session.user] = [];
  }

  files[req.session.user].push(file.name);
  saveFiles(files);

  res.redirect("/vault.html");
});

// List Files
app.get("/files", (req, res) => {
  if (!req.session.user) return res.json([]);

  const files = getFiles();
  res.json(files[req.session.user] || []);
});

// Download
app.get("/download/:name", (req, res) => {
  const filePath = path.join(__dirname, "uploads", req.params.name);
  res.download(filePath);
});

// Delete
app.get("/delete/:name", (req, res) => {
  const username = req.session.user;
  const fileName = req.params.name;

  const filePath = path.join("uploads", fileName);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

  const files = getFiles();
  files[username] = (files[username] || []).filter(f => f !== fileName);
  saveFiles(files);

  res.redirect("/vault.html");
});

// Share (User to User)
app.post("/share", (req, res) => {
  const { toUser, fileName } = req.body;
  const files = getFiles();

  if (!files[toUser]) files[toUser] = [];
  files[toUser].push(fileName);

  saveFiles(files);

  res.redirect("/vault.html");
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login.html");
});

// ===== START =====
app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
