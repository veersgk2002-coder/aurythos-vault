const express = require("express");
const session = require("express-session");
const fileUpload = require("express-fileupload");
const fs = require("fs");
const crypto = require("crypto");

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(fileUpload());

app.use(session({
    secret: "vault-secret",
    resave: false,
    saveUninitialized: true
}));

if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");
if (!fs.existsSync("data")) fs.mkdirSync("data");

const USERS_FILE = "data/users.json";
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "{}");

// ---------- HELPERS ----------

// password → hash
function hashPassword(password){
    return crypto.createHash("sha256").update(password).digest("hex");
}

// password → encryption key
function getKey(password){
    return crypto.pbkdf2Sync(password, "salt", 100000, 32, "sha256");
}

// encrypt file
function encrypt(buffer, key){
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
    const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
    return Buffer.concat([iv, encrypted]);
}

// decrypt file
function decrypt(buffer, key){
    const iv = buffer.slice(0,16);
    const encrypted = buffer.slice(16);
    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

// ---------- AUTH ----------

app.post("/register",(req,res)=>{
    let {username,password} = req.body;
    let users = JSON.parse(fs.readFileSync(USERS_FILE));

    if(users[username]) return res.send("User exists");

    users[username] = {
        password: hashPassword(password),
        files:[],
        shared:[],
        plan:"free"
    };

    fs.writeFileSync(USERS_FILE, JSON.stringify(users,null,2));

    req.session.user = username;
    req.session.key = getKey(password);

    res.redirect("/dashboard");
});

app.post("/login",(req,res)=>{
    let {username,password} = req.body;
    let users = JSON.parse(fs.readFileSync(USERS_FILE));

    if(!users[username] || users[username].password !== hashPassword(password)){
        return res.send("Invalid login");
    }

    req.session.user = username;
    req.session.key = getKey(password);

    res.redirect("/dashboard");
});

// ---------- DASHBOARD ----------

app.get("/dashboard",(req,res)=>{
    if(!req.session.user) return res.redirect("/");

    let users = JSON.parse(fs.readFileSync(USERS_FILE));
    let user = users[req.session.user];

    let filesHTML = user.files.map(f=>`
        <div>
            ${f}
            <input id="u_${f}" placeholder="share username">
            <button onclick="share('${f}')">Share</button>
            <button onclick="del('${f}')">Delete</button>
            <a href="/download/${f}">
                <button>Download</button>
            </a>
        </div>
    `).join("");

    res.send(`
    <h2>Dashboard</h2>

    <form action="/upload" method="post" enctype="multipart/form-data">
        <input type="file" name="file" multiple>
        <button>Upload</button>
    </form>

    <h3>Your Files</h3>
    ${filesHTML}

    <a href="/logout">Logout</a>

    <script>
    function del(f){
        fetch('/delete/'+f).then(()=>location.reload())
    }

    function share(f){
        let u=document.getElementById('u_'+f).value;
        fetch('/share',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({file:f,user:u})
        }).then(()=>location.reload())
    }
    </script>
    `);
});

// ---------- FILE ----------

app.post("/upload",(req,res)=>{
    if(!req.session.user) return res.redirect("/");

    let users = JSON.parse(fs.readFileSync(USERS_FILE));
    let user = users[req.session.user];

    let files = req.files.file;
    if(!Array.isArray(files)) files=[files];

    files.forEach(f=>{
        let name = Date.now()+"_"+f.name;

        const encrypted = encrypt(f.data, req.session.key);
        fs.writeFileSync("uploads/"+name, encrypted);

        user.files.push(name);
    });

    fs.writeFileSync(USERS_FILE, JSON.stringify(users,null,2));

    res.redirect("/dashboard");
});

// download (decrypt)
app.get("/download/:f",(req,res)=>{
    if(!req.session.user) return res.redirect("/");

    const data = fs.readFileSync("uploads/"+req.params.f);
    const decrypted = decrypt(data, req.session.key);

    res.setHeader("Content-Disposition","attachment");
    res.send(decrypted);
});

// delete
app.get("/delete/:f",(req,res)=>{
    let users = JSON.parse(fs.readFileSync(USERS_FILE));
    let user = users[req.session.user];

    user.files = user.files.filter(x=>x!==req.params.f);
    fs.unlinkSync("uploads/"+req.params.f);

    fs.writeFileSync(USERS_FILE, JSON.stringify(users,null,2));

    res.redirect("/dashboard");
});

// share
app.post("/share",(req,res)=>{
    let {file,user} = req.body;
    let users = JSON.parse(fs.readFileSync(USERS_FILE));

    if(!users[user]) return res.send("User not found");

    users[user].shared.push(file);

    fs.writeFileSync(USERS_FILE, JSON.stringify(users,null,2));

    res.send("ok");
});

// logout
app.get("/logout",(req,res)=>{
    req.session.destroy(()=>res.redirect("/"));
});

// ---------- LOGIN PAGE ----------

app.get("/",(req,res)=>{
    res.send(`
    <h2>Aurythos Vault</h2>

    <form action="/login" method="post">
        <input name="username" placeholder="Username">
        <input name="password" placeholder="Password">
        <button>Login</button>
    </form>

    <form action="/register" method="post">
        <input name="username" placeholder="Username">
        <input name="password" placeholder="Password">
        <button>Register</button>
    </form>
    `);
});

// ---------- SERVER ----------

const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log("Running on "+PORT));
