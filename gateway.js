// ================== CONFIG ==================

// 🔑 CHANGE THIS → your password hash (SHA-256)
const HASH = "e21fe15e6f6461eca57e6234eefbcb1a623dd4aa3c24a85cb008346bef24bfe2";

// 🔒 Security config
const MAX_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000; // 15 min

// 🔐 Keys (slightly obfuscated)
const K_AUTH = btoa("auth");
const K_ATTEMPTS = btoa("att");
const K_LOCK = btoa("lock");

// ================== HASH FUNCTION ==================
async function hash(input) {
  const enc = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest("SHA-256", enc);
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// ================== DEVTOOLS DETECTION ==================
function detectDevTools() {
  const threshold = 160;
  setInterval(() => {
    if (
      window.outerWidth - window.innerWidth > threshold ||
      window.outerHeight - window.innerHeight > threshold
    ) {
      document.body.innerHTML = "⛔ DEVTOOLS BLOCKED";
    }
  }, 1000);
}

// ================== LOCK SYSTEM ==================
function isLocked() {
  const lock = sessionStorage.getItem(K_LOCK);
  if (!lock) return false;

  if (Date.now() < parseInt(lock)) return true;

  sessionStorage.removeItem(K_LOCK);
  sessionStorage.removeItem(K_ATTEMPTS);
  return false;
}

function addAttempt() {
  let a = parseInt(sessionStorage.getItem(K_ATTEMPTS) || "0");
  a++;
  sessionStorage.setItem(K_ATTEMPTS, a);

  if (a >= MAX_ATTEMPTS) {
    sessionStorage.setItem(K_LOCK, Date.now() + LOCK_TIME);
  }

  return a;
}

// ================== AUTH UI ==================
function createUI() {
  const modal = document.createElement("div");
  modal.innerHTML = `
    <div style="
      position:fixed;
      top:0;left:0;
      width:100%;height:100%;
      background:black;
      display:flex;
      justify-content:center;
      align-items:center;
      z-index:9999;
    ">
      <div style="text-align:center;color:#00ff00;font-family:monospace">
        <h2>🔐 SECURE TERMINAL</h2>
        <input id="pw" type="password" placeholder="Enter password"
          style="padding:10px;margin-top:10px;background:#111;color:#0f0;border:1px solid #0f0;">
        <br><br>
        <button id="go" style="padding:8px 20px;background:#0f0;color:#000;border:none;">ENTER</button>
        <div id="msg" style="margin-top:10px;color:red;"></div>
      </div>
    </div>
  `;
  document.body.appendChild(modal);
  return modal;
}

// ================== MAIN ==================
async function startAuth() {
  const terminal = document.getElementById("terminal-content");
  terminal.style.display = "none";

  // Already authenticated
  if (sessionStorage.getItem(K_AUTH) === "1") {
    terminal.style.display = "block";
    return;
  }

  // Locked
  if (isLocked()) {
    document.body.innerHTML = "⛔ LOCKED (TRY LATER)";
    return;
  }

  const modal = createUI();
  const btn = document.getElementById("go");
  const input = document.getElementById("pw");
  const msg = document.getElementById("msg");

  btn.onclick = async () => {
    const val = input.value.trim();
    if (!val) return;

    const hashed = await hash(val);

    if (hashed === HASH) {
      sessionStorage.setItem(K_AUTH, "1");
      modal.remove();
      terminal.style.display = "block";
    } else {
      const tries = addAttempt();
      msg.innerText = `❌ Wrong (${MAX_ATTEMPTS - tries} left)`;

      if (tries >= MAX_ATTEMPTS) {
        document.body.innerHTML = "⛔ BLOCKED";
      }
    }
  };

  input.addEventListener("keypress", (e) => {
    if (e.key === "Enter") btn.click();
  });
}

// ================== INIT ==================
(function () {
  detectDevTools();
  startAuth();
})();
