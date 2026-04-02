const express = require("express");
const session = require("express-session");
const fileUpload = require("express-fileupload");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 4000;

// FILES
const USERS = "users.json";
const FILES = "files.json";
const UPLOADS = "uploads";

// INIT
if (!fs.existsSync(USERS)) fs.writeFileSync(USERS, "{}");
if (!fs.existsSync(FILES)) fs.writeFileSync(FILES, "{}");
if (!fs.existsSync(UPLOADS)) fs.mkdirSync(UPLOADS);

// MIDDLEWARE
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(fileUpload());
app.use(express.static("public"));

app.use(session({
  secret: "aurythos_secret",
  resave: false,
  saveUninitialized: false,
}));

// HELPERS
const getUsers = () => JSON.parse(fs.readFileSync(USERS));
const saveUsers = (d) => fs.writeFileSync(USERS, JSON.stringify(d, null, 2));

const getFiles = () => JSON.parse(fs.readFileSync(FILES));
const saveFiles = (d) => fs.writeFileSync(FILES, JSON.stringify(d, null, 2));

// ROUTES

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

// REGISTER
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const users = getUsers();

  if (users[username]) return res.send("User exists");

  users[username] = await bcrypt.hash(password, 10);
  saveUsers(users);

  res.redirect("/");
});

// LOGIN
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const users = getUsers();

  if (!users[username]) return res.send("User not found");

  const ok = await bcrypt.compare(password, users[username]);
  if (!ok) return res.send("Wrong password");

  req.session.user = username;
  res.redirect("/vault.html");
});

// UPLOAD
app.post("/upload", (req, res) => {
  if (!req.session.user) return res.redirect("/");

  let files = getFiles();
  if (!files[req.session.user]) files[req.session.user] = [];

  let uploaded = req.files.file;
  if (!Array.isArray(uploaded)) uploaded = [uploaded];

  uploaded.forEach(f => {
    const name = Date.now() + "_" + f.name;
    f.mv(path.join(UPLOADS, name));
    files[req.session.user].push(name);
  });

  saveFiles(files);
  res.redirect("/vault.html");
});

// LIST
app.get("/files", (req, res) => {
  if (!req.session.user) return res.json([]);
  const files = getFiles();
  res.json(files[req.session.user] || []);
});

// DOWNLOAD
app.get("/download/:name", (req, res) => {
  const file = path.join(UPLOADS, req.params.name);
  if (!fs.existsSync(file)) return res.send("Not found");
  res.download(file);
});

// DELETE
app.get("/delete/:name", (req, res) => {
  let files = getFiles();
  const user = req.session.user;

  files[user] = (files[user] || []).filter(f => f !== req.params.name);
  saveFiles(files);

  const file = path.join(UPLOADS, req.params.name);
  if (fs.existsSync(file)) fs.unlinkSync(file);

  res.redirect("/vault.html");
});

// 🔥 USER TO USER SHARE
app.post("/share", (req, res) => {
  const { filename, toUser } = req.body;

  let files = getFiles();

  if (!files[toUser]) return res.send("User not found");

  files[toUser].push(filename);
  saveFiles(files);

  res.send("Shared successfully");
});

// LOGOUT
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.listen(PORT, () => console.log("Running on", PORT));
