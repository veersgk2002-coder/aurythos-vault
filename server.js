const express = require("express");
const session = require("express-session");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");
const { v4: uuidv4 } = require("uuid");

const app = express();

// ====== CONFIG ======
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));

app.use(session({
  secret: "secret123",
  resave: false,
  saveUninitialized: false
}));

// ====== STORAGE ======
if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");

const storage = multer.diskStorage({
  destination: "uploads/",
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  }
});

const upload = multer({ storage });

// ====== DATABASE (TEMP MEMORY) ======
let users = {};
let filesDB = {};

// ====== AUTH ======
function auth(req, res, next) {
  if (!req.session.user) return res.redirect("/");
  next();
}

// ====== ROUTES ======

// REGISTER
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (users[username]) return res.send("User exists");

  const hash = await bcrypt.hash(password, 10);

  users[username] = { password: hash };
  filesDB[username] = [];

  req.session.user = username;
  res.redirect("/dashboard.html");
});

// LOGIN
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users[username];
  if (!user) return res.send("User not found");

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.send("Wrong password");

  req.session.user = username;
  res.redirect("/dashboard.html");
});

// DASHBOARD DATA
app.get("/files", auth, (req, res) => {
  const username = req.session.user;
  res.json(filesDB[username] || []);
});

// UPLOAD
app.post("/upload", auth, upload.array("files"), (req, res) => {
  const username = req.session.user;

  if (!filesDB[username]) filesDB[username] = [];

  req.files.forEach(file => {
    filesDB[username].push({
      id: uuidv4(),
      name: file.originalname,
      path: file.path,
      size: file.size
    });
  });

  res.redirect("/dashboard.html");
});

// DOWNLOAD
app.get("/download/:id", auth, (req, res) => {
  const username = req.session.user;
  const file = filesDB[username].find(f => f.id === req.params.id);

  if (!file) return res.send("File not found");

  res.download(file.path, file.name);
});

// DELETE
app.get("/delete/:id", auth, (req, res) => {
  const username = req.session.user;
  const fileIndex = filesDB[username].findIndex(f => f.id === req.params.id);

  if (fileIndex === -1) return res.send("File not found");

  const file = filesDB[username][fileIndex];

  fs.unlinkSync(file.path);
  filesDB[username].splice(fileIndex, 1);

  res.redirect("/dashboard.html");
});

// SHARE
app.get("/share/:id", (req, res) => {
  let file;

  for (let user in filesDB) {
    file = filesDB[user].find(f => f.id === req.params.id);
    if (file) break;
  }

  if (!file) return res.send("Not found");

  res.download(file.path, file.name);
});

// LOGOUT
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// START
app.listen(10000, () => console.log("Server running"));
