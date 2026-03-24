const express = require("express");
const session = require("express-session");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");
const Razorpay = require("razorpay");

const app = express();
const PORT = process.env.PORT || 10000;

// ===== RAZORPAY =====
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID || "test_key",
  key_secret: process.env.RAZORPAY_KEY_SECRET || "test_secret",
});

// ===== MIDDLEWARE =====
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));

app.use(session({
  secret: "vault-secret",
  resave: false,
  saveUninitialized: false
}));

// ===== STORAGE =====
if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const user = req.session.user;
    const dir = `uploads/${user}`;
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  }
});

const upload = multer({ storage });

// ===== TEMP DB =====
let users = {};
let plans = {}; // free / premium

// ===== AUTH =====
function auth(req, res, next) {
  if (!req.session.user) return res.redirect("/");
  next();
}

// ===== UTILS =====
function getFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir);
}

function getTotalSizeMB(dir) {
  if (!fs.existsSync(dir)) return 0;
  const files = fs.readdirSync(dir);
  let total = 0;
  files.forEach(f => {
    const stats = fs.statSync(path.join(dir, f));
    total += stats.size;
  });
  return (total / (1024 * 1024)).toFixed(2); // MB
}

// ===== ROUTES =====

// HOME
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/index.html");
});

// REGISTER
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (users[username]) return res.send("User exists");

  users[username] = await bcrypt.hash(password, 10);
  plans[username] = "free";

  req.session.user = username;
  res.redirect("/dashboard");
});

// LOGIN
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!users[username]) return res.send("User not found");

  const ok = await bcrypt.compare(password, users[username]);
  if (!ok) return res.send("Wrong password");

  req.session.user = username;
  res.redirect("/dashboard");
});

// DASHBOARD
app.get("/dashboard", auth, (req, res) => {
  const user = req.session.user;
  const dir = `uploads/${user}`;

  const files = getFiles(dir);
  const count = files.length;
  const sizeMB = getTotalSizeMB(dir);

  const maxFiles = plans[user] === "premium" ? "∞" : 5;
  const maxMB = plans[user] === "premium" ? 1000 : 10; // 10MB free

  const percent = Math.min((sizeMB / maxMB) * 100, 100);

  res.send(`
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vault</title>

<style>
body {
  margin:0;
  font-family: Arial;
  background: linear-gradient(135deg,#0f2027,#203a43,#2c5364);
  color:white;
}

.container {
  padding:20px;
  max-width:500px;
  margin:auto;
}

.card {
  background: rgba(255,255,255,0.05);
  padding:20px;
  border-radius:15px;
  backdrop-filter: blur(10px);
}

.top {
  display:flex;
  justify-content:space-between;
}

.plan {
  background:${plans[user] === "premium" ? "gold" : "#00c6ff"};
  color:black;
  padding:5px 10px;
  border-radius:8px;
}

.bar {
  height:8px;
  background:#333;
  border-radius:5px;
  margin-top:5px;
}

.fill {
  height:8px;
  background:#00c6ff;
  width:${percent}%;
  border-radius:5px;
}

.file {
  background:#ffffff10;
  padding:10px;
  border-radius:8px;
  margin-top:10px;
  display:flex;
  justify-content:space-between;
  align-items:center;
}

.file img {
  max-width:40px;
  border-radius:5px;
}

.file a {
  color:#00c6ff;
  font-size:12px;
  margin-left:8px;
}

button {
  width:100%;
  padding:12px;
  border:none;
  border-radius:8px;
  background:#00c6ff;
  margin-top:10px;
}

.upgrade {
  display:block;
  text-align:center;
  background:gold;
  color:black;
  padding:10px;
  border-radius:8px;
  margin-top:15px;
  text-decoration:none;
}
</style>
</head>

<body>

<div class="container">
<div class="card">

<div class="top">
  <b>${user}</b>
  <div class="plan">${plans[user]}</div>
</div>

<p>Files: ${count}/${maxFiles}</p>
<p>Storage: ${sizeMB}MB / ${maxMB}MB</p>

<div class="bar"><div class="fill"></div></div>

<form action="/upload" method="post" enctype="multipart/form-data">
  <input type="file" name="files" multiple required>
  <button>Upload Files</button>
</form>

${plans[user] === "free" ? `<a href="/pay" class="upgrade">Upgrade ₹99</a>` : ""}

<h3>Your Files</h3>

${files.length === 0 ? "No files" : files.map(f => {
  const ext = f.split(".").pop().toLowerCase();
  const isImage = ["jpg","jpeg","png","gif","webp"].includes(ext);

  return `
<div class="file">
  ${isImage ? `<img src="/file/${f}">` : `<span>${f}</span>`}
  <div>
    ${isImage ? `<a href="/file/${f}" target="_blank">Preview</a>` : ""}
    <a href="/download/${f}">Download</a>
    <a href="/delete/${f}">Delete</a>
  </div>
</div>`;
}).join("")}

<br>
<a href="/logout">Logout</a>

</div>
</div>

</body>
</html>
`);
});

// UPLOAD (LIMIT + SIZE CONTROL)
app.post("/upload", auth, upload.array("files"), (req, res) => {
  const user = req.session.user;
  const dir = `uploads/${user}`;
  const files = getFiles(dir);

  if (plans[user] === "free" && files.length >= 5) {
    return res.send("Limit reached (5 files)");
  }

  res.redirect("/dashboard");
});

// FILE PREVIEW
app.get("/file/:name", auth, (req, res) => {
  res.sendFile(path.join(__dirname, "uploads", req.session.user, req.params.name));
});

// DOWNLOAD
app.get("/download/:file", auth, (req, res) => {
  res.download(`uploads/${req.session.user}/${req.params.file}`);
});

// DELETE
app.get("/delete/:file", auth, (req, res) => {
  const file = `uploads/${req.session.user}/${req.params.file}`;
  if (fs.existsSync(file)) fs.unlinkSync(file);
  res.redirect("/dashboard");
});

// PAYMENT
app.get("/pay", auth, async (req, res) => {
  const order = await razorpay.orders.create({
    amount: 9900,
    currency: "INR"
  });

  res.send(`
<script src="https://checkout.razorpay.com/v1/checkout.js"></script>
<script>
var options = {
  key: "${process.env.RAZORPAY_KEY_ID}",
  amount: "9900",
  currency: "INR",
  order_id: "${order.id}",
  handler: function () {
    window.location.href = "/success";
  }
};
var rzp = new Razorpay(options);
rzp.open();
</script>
`);
});

// SUCCESS
app.get("/success", auth, (req, res) => {
  plans[req.session.user] = "premium";
  res.redirect("/dashboard");
});

// LOGOUT
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.listen(PORT, () => console.log("Server running"));
