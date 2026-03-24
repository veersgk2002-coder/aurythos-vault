async function login() {
  let res = await fetch("/login", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({
      username: username.value,
      password: password.value
    })
  });

  let data = await res.json();

  if (data.error) {
    msg.innerText = data.error;
  } else {
    authBox.style.display = "none";
    vault.style.display = "block";
    loadFiles();
  }
}

async function register() {
  let res = await fetch("/register", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({
      username: ruser.value,
      password: rpass.value
    })
  });

  let data = await res.json();
  msg.innerText = data.error || data.success;
}

function toggleRegister() {
  registerBox.style.display =
    registerBox.style.display === "none" ? "block" : "none";
}

// 🔥 IMPORTANT FIX HERE
async function loadFiles() {
  let res = await fetch("/files");
  let files = await res.json();

  limit.innerText = `Files: ${files.length}/5`;

  fileList.innerHTML = "";

  files.forEach(f => {
    fileList.innerHTML += `
    <div style="margin:10px;padding:10px;border-radius:10px;background:#ffffff10">
      <b>${f.file_name}</b><br><br>

      <a href="${f.file_url}" target="_blank">Preview</a> |
      <a href="${f.file_url}" download>Download</a> |

      <button onclick="del(${f.id})">Delete</button> |

      <button onclick="share(${f.id})" style="background:#00d4ff;border:none;padding:5px 10px;border-radius:5px;cursor:pointer;">
        Share
      </button>
    </div>
    `;
  });
}

async function upload() {
  let form = new FormData();
  for (let f of files.files) form.append("files", f);

  let res = await fetch("/upload", {
    method:"POST",
    body: form
  });

  let data = await res.json();
  alert(data.error || data.success);

  loadFiles();
}

async function del(id) {
  await fetch("/delete", {
    method:"POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({ id })
  });

  loadFiles();
}

// 🔥 SHARE FUNCTION (IMPORTANT)
async function share(id) {
  let toUser = prompt("Enter username to share:");

  if (!toUser) return;

  let res = await fetch("/share", {
    method:"POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({
      id: id,
      toUser: toUser
    })
  });

  let data = await res.json();

  alert(data.error || data.success);
}

async function upgrade() {
  await fetch("/upgrade", { method:"POST" });
  alert("Upgraded to Premium 🚀");
}
