// ================== SECURITY CONFIG ==================
// HOW TO SET YOUR PASSWORD:
//   1. Open browser console on any HTTPS page
//   2. Run: crypto.subtle.importKey("raw", new TextEncoder().encode("yourpassword"), {name:"PBKDF2"}, false, ["deriveBits"])
//      then follow the PBKDF2 flow below, OR use the helper at the bottom of this file.
//   3. Paste the resulting CREDENTIAL object below.
//
// NEVER store a plain SHA-256 hash — it's brute-forceable in seconds.
// PBKDF2 (310,000 iterations) makes each guess take ~1 second on modern hardware.

const CREDENTIAL = {
  // Generated via generateCredential("yourpassword") — see helper below
  salt: "772ee2043a0f9699371ed7e2c650ef06",   // 32-char hex salt — CHANGE THIS
  hash: "87df992fec2c478c94eb5f9f0df3af1c3c49134abf0e2c2aba21fb539f9fe569", // CHANGE THIS — run generateCredential()
};

const MAX_ATTEMPTS   = 5;
const LOCK_DURATION  = 15 * 60 * 1000; // 15 min
const MAX_PW_LENGTH  = 128;            // Prevent oversized input DoS
const PBKDF2_ITERS   = 310_000;        // NIST SP 800-132 recommended minimum
const TOKEN_TTL      = 8 * 60 * 60 * 1000; // Auth token expires after 8 hours

// Session keys — use full names; base64 "obfuscation" provides zero security
const SK_TOKEN    = "auth_token";
const SK_ATTEMPTS = "auth_attempts";
const SK_LOCK     = "auth_lock_until";

// ================== CRYPTO ==================

/** Derive PBKDF2 key bits from a password + hex salt */
async function deriveKey(password, saltHex) {
  const enc      = new TextEncoder();
  const salt     = hexToBytes(saltHex);
  const keyMat   = await crypto.subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERS },
    keyMat, 256
  );
  return bytesToHex(new Uint8Array(bits));
}

/** Timing-safe string comparison — prevents timing attacks */
function timingSafeEqual(a, b) {
  if (a.length !== b.length) {
    // Still iterate to avoid length-based timing leak
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ 0;
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/** Generate a random hex string (for salts / HMAC keys) */
function randomHex(bytes = 16) {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(bytes)));
}

/** Sign a payload with HMAC-SHA256 using a session-scoped key */
async function hmacSign(key, data) {
  const enc     = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(data));
  return bytesToHex(new Uint8Array(sig));
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  return out;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ================== TOKEN MANAGEMENT ==================
// Auth token = HMAC("session_key:expiry") so it can't be forged or replayed

let SESSION_KEY = null; // Generated once per page load — not stored anywhere

function getSessionKey() {
  if (!SESSION_KEY) SESSION_KEY = randomHex(32);
  return SESSION_KEY;
}

async function issueToken() {
  const expiry  = Date.now() + TOKEN_TTL;
  const payload = `${getSessionKey()}:${expiry}`;
  const sig     = await hmacSign(getSessionKey(), payload);
  sessionStorage.setItem(SK_TOKEN, JSON.stringify({ expiry, sig }));
}

async function verifyToken() {
  try {
    const raw = sessionStorage.getItem(SK_TOKEN);
    if (!raw) return false;
    const { expiry, sig } = JSON.parse(raw);
    if (Date.now() > expiry) { sessionStorage.removeItem(SK_TOKEN); return false; }
    const payload   = `${getSessionKey()}:${expiry}`;
    const expected  = await hmacSign(getSessionKey(), payload);
    return timingSafeEqual(sig, expected);
  } catch { return false; }
}

// ================== LOCKOUT ==================

function getLockState() {
  const lock = sessionStorage.getItem(SK_LOCK);
  if (!lock) return { locked: false };
  const until = parseInt(lock, 10);
  if (Date.now() < until) return { locked: true, until };
  sessionStorage.removeItem(SK_LOCK);
  sessionStorage.removeItem(SK_ATTEMPTS);
  return { locked: false };
}

function recordFailedAttempt() {
  let attempts = parseInt(sessionStorage.getItem(SK_ATTEMPTS) || "0", 10) + 1;
  sessionStorage.setItem(SK_ATTEMPTS, String(attempts));
  if (attempts >= MAX_ATTEMPTS) {
    sessionStorage.setItem(SK_LOCK, String(Date.now() + LOCK_DURATION));
  }
  return attempts;
}

function clearAttempts() {
  sessionStorage.removeItem(SK_ATTEMPTS);
}

// ================== DEVTOOLS HARDENING ==================
// Note: No client-side measure is foolproof. A determined attacker with
// source access can patch any of this. The real security is on the server.
// These measures raise the bar against casual/script-kiddie attacks.

function hardenDevTools() {
  // 1. Debugger trap — pauses execution when DevTools is open
  (function devToolsTrap() {
    try { (function() { }.constructor("debugger")()) } catch (_) {}
    setTimeout(devToolsTrap, 2000);
  })();

  // 2. Window size heuristic (docked DevTools)
  const THRESHOLD = 160;
  let blurred = false;
  setInterval(() => {
    const widthDiff  = window.outerWidth  - window.innerWidth;
    const heightDiff = window.outerHeight - window.innerHeight;
    if (widthDiff > THRESHOLD || heightDiff > THRESHOLD) {
      if (!blurred) {
        blurred = true;
        lockPage("DevTools detected");
      }
    }
  }, 1000);

  // 3. Console timing detection
  const d = Object.getOwnPropertyDescriptor(console, "log");
  if (d && d.configurable) {
    Object.defineProperty(console, "log", {
      get() { lockPage("Console access detected"); return function() {}; }
    });
  }

  // 4. toString timing trick
  let devOpen = false;
  const img = new Image();
  Object.defineProperty(img, "id", {
    get() { devOpen = true; return ""; }
  });
  setInterval(() => { devOpen = false; console.log(img); if (devOpen) lockPage("DevTools open"); }, 3000);
}

function lockPage(reason) {
  document.documentElement.innerHTML =
    `<body style="background:#000;color:#ff4444;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">` +
    `<p style="font-size:1.2rem">⛔ SESSION TERMINATED</p></body>`;
}

// ================== CSP INJECTION ==================
// Adds a Content Security Policy to block XSS and data exfiltration.
// For real security, set this as an HTTP response header on your server.

function injectCSP() {
  const meta = document.createElement("meta");
  meta.httpEquiv = "Content-Security-Policy";
  meta.content = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "connect-src 'none'",
    "object-src 'none'",
    "base-uri 'self'",
  ].join("; ");
  document.head.prepend(meta);
}

// ================== AUTH UI ==================

function renderLocked(until) {
  const remaining = Math.ceil((until - Date.now()) / 60000);
  document.body.innerHTML =
    `<div style="position:fixed;inset:0;background:#0a0a0a;display:flex;align-items:center;justify-content:center;font-family:monospace">` +
    `<div style="text-align:center;color:#ff4444">` +
    `<p style="font-size:1.5rem">⛔ LOCKED</p>` +
    `<p>Too many failed attempts.<br>Try again in ${remaining} minute${remaining !== 1 ? "s" : ""}.</p>` +
    `</div></div>`;
}

function createAuthModal() {
  const overlay = document.createElement("div");
  overlay.id = "auth-overlay";
  overlay.setAttribute("aria-modal", "true");
  overlay.setAttribute("role", "dialog");
  overlay.setAttribute("aria-label", "Authentication required");
  overlay.innerHTML = `
    <div style="
      position:fixed;inset:0;
      background:#0a0a0a;
      display:flex;justify-content:center;align-items:center;
      z-index:9999;">
      <div style="text-align:center;color:#00ff00;font-family:monospace;max-width:320px;width:90%">
        <h2 style="letter-spacing:.1em;margin-bottom:1.5rem">🔐 SECURE TERMINAL</h2>
        <input
          id="pw-input"
          type="password"
          autocomplete="current-password"
          placeholder="Enter password"
          maxlength="${MAX_PW_LENGTH}"
          style="
            width:100%;box-sizing:border-box;
            padding:10px;
            background:#111;color:#0f0;
            border:1px solid #0f0;
            font-family:monospace;font-size:1rem;
            outline:none;"
          aria-label="Password">
        <button
          id="pw-submit"
          style="
            margin-top:1rem;
            padding:8px 24px;
            background:#0f0;color:#000;
            border:none;cursor:pointer;
            font-family:monospace;font-size:1rem;font-weight:bold;">
          ENTER
        </button>
        <div id="pw-msg" role="alert" aria-live="polite" style="margin-top:1rem;min-height:1.2em;color:#ff4444;font-size:.9rem;"></div>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  return overlay;
}

// ================== MAIN ==================

async function startAuth() {
  injectCSP();
  hardenDevTools();

  const content = document.getElementById("terminal-content");
  if (content) content.style.display = "none";

  // Check lockout first (before any DOM or crypto work)
  const lock = getLockState();
  if (lock.locked) { renderLocked(lock.until); return; }

  // Verify existing session token
  if (await verifyToken()) {
    if (content) content.style.display = "block";
    return;
  }

  // Show auth modal
  const modal  = createAuthModal();
  const input  = document.getElementById("pw-input");
  const btn    = document.getElementById("pw-submit");
  const msg    = document.getElementById("pw-msg");

  input.focus();

  let busy = false; // Prevent double-submit

  async function attempt() {
    if (busy) return;
    const val = input.value;

    // Input validation
    if (!val || val.length === 0) { msg.textContent = "Please enter your password."; return; }
    if (val.length > MAX_PW_LENGTH) { msg.textContent = "Input too long."; return; }

    busy = true;
    btn.disabled = true;
    msg.textContent = "Verifying…";
    input.value = "";

    try {
      // Re-check lockout in case it triggered during a slow derivation
      const currentLock = getLockState();
      if (currentLock.locked) { renderLocked(currentLock.until); return; }

      const derived = await deriveKey(val, CREDENTIAL.salt);

      if (timingSafeEqual(derived, CREDENTIAL.hash)) {
        clearAttempts();
        await issueToken();
        modal.remove();
        if (content) content.style.display = "block";
      } else {
        const tries    = recordFailedAttempt();
        const newLock  = getLockState();
        if (newLock.locked) {
          renderLocked(newLock.until);
        } else {
          const left = MAX_ATTEMPTS - tries;
          msg.textContent = `❌ Wrong password. ${left} attempt${left !== 1 ? "s" : ""} remaining.`;
          busy = false;
          btn.disabled = false;
          input.focus();
        }
      }
    } catch (err) {
      msg.textContent = "An error occurred. Please try again.";
      busy = false;
      btn.disabled = false;
    }
  }

  btn.addEventListener("click", attempt);
  input.addEventListener("keydown", e => { if (e.key === "Enter") attempt(); });
}

// ================== CREDENTIAL GENERATOR (DEV ONLY) ==================
// Run this in console to generate your CREDENTIAL object, then remove it from production.
// Usage: generateCredential("your-secret-password")

async function generateCredential(password) {
  const salt    = randomHex(16);
  const derived = await deriveKey(password, salt);
  const cred    = { salt, hash: derived };
  console.log("Paste this into CREDENTIAL:\n", JSON.stringify(cred, null, 2));
  return cred;
}

// ================== INIT ==================
(function() {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", startAuth);
  } else {
    startAuth();
  }
})();
