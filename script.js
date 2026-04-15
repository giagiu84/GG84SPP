/* GG84 – CORE ECDH + AES-GCM
   Modalità A "Pulita"
   Identità locale nuova, nessuna compatibilità legacy.
*/

const GG84 = {
  version: "GG84_V2_SECURE",
  encoder: new TextEncoder(),
  decoder: new TextDecoder(),
  inviteVersion: "2",
  storage: {
    introDone: "gg84_intro_done",
    onboardingDone: "gg84_onboarding_done",
    userName: "gg84_user_name",

    privateJwk: "gg84_private",
    publicKey: "gg84_public",

    activePeerPub: "gg84_active_peer_pub",
    peerName: "gg84_peer_name",
    verifiedPeerPub: "gg84_verified_peer_pub",

    flowState: "gg84_flow_state",
    pendingApprovalLink: "gg84_pending_approval_link",
    pendingPeerPub: "gg84_pending_peer_pub",
    pendingPeerName: "gg84_pending_peer_name",
    pendingPeerDevice: "gg84_pending_peer_device",

    appLockEnabled: "gg84_app_lock_enabled",
    appPinHash: "gg84_app_pin_hash",
    appPinSalt: "gg84_app_pin_salt",
    appLockSessionUntil: "gg84_app_lock_session_until",
    appLockBackgroundAt: "gg84_app_lock_background_at"
  }
};

/* =========================
   BASI / STORAGE
========================= */

function getEl(id) {
  return document.getElementById(id);
}

function cleanString(value) {
  return String(value || "").trim();
}

function sGet(key) {
  try {
    return localStorage.getItem(key) || "";
  } catch {
    return "";
  }
}

function sSet(key, value) {
  try {
    const normalized = typeof value === "string" ? value : String(value ?? "");
    if (!normalized) {
      localStorage.removeItem(key);
      return;
    }
    localStorage.setItem(key, normalized);
  } catch {}
}

function sDel(key) {
  try {
    localStorage.removeItem(key);
  } catch {}
}

/* =========================
   BASE64 / BYTES
========================= */

function toBase64(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = "";
  const chunk = 0x8000;

  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }

  return btoa(binary);
}

function fromBase64(base64) {
  const normalized = cleanString(base64);
  const binary = atob(normalized);
  const out = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }

  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

/* =========================
   HASH
========================= */

async function sha256Bytes(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(hash);
}

async function sha256Text(text) {
  return sha256Bytes(GG84.encoder.encode(String(text)));
}

/* =========================
   VALIDAZIONI
========================= */

function isValidPub(value) {
  const v = cleanString(value);
  return /^[A-Za-z0-9+/=]+$/.test(v) && v.length >= 80;
}

function validatePrivateKey(pw) {
  return (
    typeof pw === "string" &&
    pw.length >= 8 &&
    /[A-Z]/.test(pw) &&
    /[^a-zA-Z0-9]/.test(pw)
  );
}

function validateConnectionPassword(_pw) {
  return false;
}

function validateAppPin(pin) {
  return typeof pin === "string" && /^\d{6}$/.test(pin);
}

/* =========================
   IDENTITÀ
========================= */

function getUserName() {
  return cleanString(sGet(GG84.storage.userName));
}

function getPublicIdentity() {
  return cleanString(sGet(GG84.storage.publicKey));
}

function hasValidIdentityState() {
  const name = getUserName();
  const pub = getPublicIdentity();
  const priv = sGet(GG84.storage.privateJwk);
  return !!cleanString(name) && !!cleanString(pub) && !!cleanString(priv);
}

async function generateIdentity() {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );

  const publicRaw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

  sSet(GG84.storage.privateJwk, JSON.stringify(privateJwk));
  sSet(GG84.storage.publicKey, toBase64(publicRaw));

  return toBase64(publicRaw);
}

async function ensureIdentity() {
  const pub = getPublicIdentity();
  const priv = sGet(GG84.storage.privateJwk);

  if (isValidPub(pub) && priv) return pub;
  return await generateIdentity();
}

async function initGG84(options = {}) {
  const autoCreateIdentity = options.autoCreateIdentity === true;

  if (!window.crypto?.subtle) {
    throw new Error("Web Crypto API non disponibile su questo dispositivo.");
  }

  if (autoCreateIdentity) {
    await ensureIdentity();
  }

  return true;
}

async function getKeyPair() {
  const jwkRaw = sGet(GG84.storage.privateJwk);
  const pubRaw = getPublicIdentity();

  if (!jwkRaw || !isValidPub(pubRaw)) return null;

  const privateKey = await crypto.subtle.importKey(
    "jwk",
    JSON.parse(jwkRaw),
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );

  const publicKey = await crypto.subtle.importKey(
    "raw",
    fromBase64(pubRaw),
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );

  return { privateKey, publicKey };
}

/* =========================
   PEER ATTIVO
========================= */

function getActivePeerPublicKey() {
  return cleanString(sGet(GG84.storage.activePeerPub));
}

function getActivePeerName() {
  return cleanString(sGet(GG84.storage.peerName));
}

function getActivePeer() {
  const pub = getActivePeerPublicKey();

  return {
    pub,
    name: getActivePeerName(),
    isActive: isValidPub(pub)
  };
}

function setActivePeer(pub, name = "") {
  const normalizedPub = cleanString(pub);
  const normalizedName = cleanString(name);

  if (!isValidPub(normalizedPub)) return false;

  sSet(GG84.storage.activePeerPub, normalizedPub);
  sSet(GG84.storage.peerName, normalizedName);
  clearVerifiedPeer();
  return true;
}

function clearActivePeer() {
  sDel(GG84.storage.activePeerPub);
  sDel(GG84.storage.peerName);
  clearVerifiedPeer();
}

function markActivePeerAsVerified() {
  const active = getActivePeer();
  if (!active.isActive) return false;

  sSet(GG84.storage.verifiedPeerPub, active.pub);
  return true;
}

function clearVerifiedPeer() {
  sDel(GG84.storage.verifiedPeerPub);
}

function isActivePeerVerified() {
  const active = getActivePeer();
  const verified = cleanString(sGet(GG84.storage.verifiedPeerPub));
  return !!active.pub && active.pub === verified;
}

/* =========================
   INVITI
========================= */

function getDeviceLabel() {
  return "mobile";
}

function buildInviteLink() {
  const pub = getPublicIdentity();
  const name = getUserName() || "Una persona";
  const device = getDeviceLabel();

  if (!isValidPub(pub)) return "";

  return `chiave.html?flow=receive&v=${encodeURIComponent(GG84.inviteVersion)}&pub=${encodeURIComponent(pub)}&name=${encodeURIComponent(name)}&device=${encodeURIComponent(device)}`;
}

function buildConfirmationLink() {
  const pub = getPublicIdentity();
  const name = getUserName() || "Una persona";
  const device = getDeviceLabel();

  if (!isValidPub(pub)) return "";

  return `chiave.html?flow=confirm&v=${encodeURIComponent(GG84.inviteVersion)}&pub=${encodeURIComponent(pub)}&name=${encodeURIComponent(name)}&device=${encodeURIComponent(device)}`;
}

function parseInviteData(raw) {
  try {
    const normalized = cleanString(raw);
    if (!normalized) return null;

    const fakeUrl = normalized.startsWith("http")
      ? normalized
      : "https://local.test/" + normalized.replace(/^\//, "");

    const url = new URL(fakeUrl);
    const pub = cleanString(url.searchParams.get("pub") || url.searchParams.get("key"));
    const name = cleanString(url.searchParams.get("name"));
    const flow = cleanString(url.searchParams.get("flow"));
    const device = cleanString(url.searchParams.get("device"));
    const v = cleanString(url.searchParams.get("v")) || GG84.inviteVersion;

    if (!isValidPub(pub)) return null;

    return { pub, name, flow, device, v };
  } catch {
    return null;
  }
}

/* =========================
   FINGERPRINT
========================= */

async function buildConnectionFingerprint(peerPub) {
  const myPub = getPublicIdentity();
  const otherPub = cleanString(peerPub);

  if (!isValidPub(myPub) || !isValidPub(otherPub)) return "";

  const combined = [myPub, otherPub].sort().join("|");
  const hashBytes = await sha256Text(combined);
  const shortHex = bytesToHex(hashBytes.slice(0, 8)).toUpperCase();
  const parts = shortHex.match(/.{1,4}/g);

  return parts ? parts.join("-") : shortHex;
}

/* =========================
   KDF ECDH -> AES
========================= */

async function deriveSharedSecretBytes(peerPublicKeyBase64) {
  const pair = await getKeyPair();
  if (!pair) throw new Error("Identità locale non disponibile.");

  const peerKey = await crypto.subtle.importKey(
    "raw",
    fromBase64(peerPublicKeyBase64),
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );

  const rawSecret = await crypto.subtle.deriveBits(
    { name: "ECDH", public: peerKey },
    pair.privateKey,
    256
  );

  return new Uint8Array(rawSecret);
}

async function deriveSharedKey(peerPublicKeyBase64) {
  const myPub = getPublicIdentity();
  const otherPub = cleanString(peerPublicKeyBase64);

  if (!isValidPub(myPub) || !isValidPub(otherPub)) {
    throw new Error("Chiave pubblica non valida.");
  }

  const rawSecret = await deriveSharedSecretBytes(otherPub);
  const orderedContext = [myPub, otherPub].sort().join("|");
  const contextBytes = GG84.encoder.encode(`GG84|ECDH|AESGCM|${orderedContext}`);

  const merged = new Uint8Array(rawSecret.length + contextBytes.length);
  merged.set(rawSecret, 0);
  merged.set(contextBytes, rawSecret.length);

  const aesMaterial = await sha256Bytes(merged);

  return crypto.subtle.importKey(
    "raw",
    aesMaterial,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

/* =========================
   NAVIGAZIONE / BACK ANDROID
========================= */

let gg84LastBackPress = 0;
let gg84BackListenerReady = false;
let gg84EdgeSwipeReady = false;
let gg84TouchStartX = 0;
let gg84TouchStartY = 0;
let gg84TouchTracking = false;

function gg84IsHomePage() {
  const path = window.location.pathname || "";
  return (
    path.endsWith("/index.html") ||
    path.endsWith("index.html") ||
    path === "/" ||
    path === ""
  );
}

function gg84GoBackOrHome() {
  if (window.history.length > 1) {
    window.history.back();
    return;
  }

  window.location.href = "index.html";
}

function setupAndroidBackNavigation() {
  if (gg84BackListenerReady) return;
  gg84BackListenerReady = true;

  try {
    const appPlugin =
      window.Capacitor &&
      window.Capacitor.Plugins &&
      window.Capacitor.Plugins.App;

    if (!appPlugin || typeof appPlugin.addListener !== "function") return;

    appPlugin.addListener("backButton", () => {
      if (!gg84IsHomePage()) {
        gg84GoBackOrHome();
        return;
      }

      const now = Date.now();
      const EXIT_DELAY = 1500;

      if (now - gg84LastBackPress < EXIT_DELAY) {
        if (typeof appPlugin.exitApp === "function") {
          appPlugin.exitApp();
        }
        return;
      }

      gg84LastBackPress = now;
      console.log("Premi di nuovo indietro per uscire");
    });
  } catch (error) {
    console.error("Android back init error:", error);
  }
}

function setupEdgeSwipeBackNavigation() {
  if (gg84EdgeSwipeReady) return;
  gg84EdgeSwipeReady = true;

  const EDGE_SIZE = 28;
  const MIN_SWIPE_X = 70;
  const MAX_SWIPE_Y = 60;

  window.addEventListener(
    "touchstart",
    event => {
      if (!event.touches || event.touches.length !== 1) {
        gg84TouchTracking = false;
        return;
      }

      const touch = event.touches[0];
      gg84TouchStartX = touch.clientX;
      gg84TouchStartY = touch.clientY;
      gg84TouchTracking = gg84TouchStartX <= EDGE_SIZE;
    },
    { passive: true }
  );

  window.addEventListener(
    "touchend",
    event => {
      if (!gg84TouchTracking || !event.changedTouches || event.changedTouches.length !== 1) {
        gg84TouchTracking = false;
        return;
      }

      const touch = event.changedTouches[0];
      const deltaX = touch.clientX - gg84TouchStartX;
      const deltaY = Math.abs(touch.clientY - gg84TouchStartY);

      gg84TouchTracking = false;

      if (deltaX < MIN_SWIPE_X) return;
      if (deltaY > MAX_SWIPE_Y) return;

      if (!gg84IsHomePage()) {
        gg84GoBackOrHome();
        return;
      }

      const appPlugin =
        window.Capacitor &&
        window.Capacitor.Plugins &&
        window.Capacitor.Plugins.App;

      const now = Date.now();
      const EXIT_DELAY = 1500;

      if (now - gg84LastBackPress < EXIT_DELAY) {
        if (appPlugin && typeof appPlugin.exitApp === "function") {
          appPlugin.exitApp();
        }
        return;
      }

      gg84LastBackPress = now;
      console.log("Swipe di nuovo per uscire");
    },
    { passive: true }
  );
}

/* =========================
   SICUREZZA ACCESSO APP (PIN)
========================= */

const GG84_APP_LOCK = {
  timeoutMs: 120000
};

let gg84AppLockOverlay = null;
let gg84AppLockTimer = null;
let gg84AppLockReady = false;
let gg84AppLocked = false;
let gg84UnlockInProgress = false;
let gg84BackgroundLockPending = false;
let gg84PinInputValue = "";

function isAppLockEnabled() {
  return sGet(GG84.storage.appLockEnabled) === "1";
}

function hasStoredAppPin() {
  return !!cleanString(sGet(GG84.storage.appPinHash)) && !!cleanString(sGet(GG84.storage.appPinSalt));
}

function getSessionUnlockUntil() {
  try {
    return Number(sessionStorage.getItem(GG84.storage.appLockSessionUntil) || "0");
  } catch {
    return 0;
  }
}

function setSessionUnlockUntil(timestamp) {
  try {
    sessionStorage.setItem(GG84.storage.appLockSessionUntil, String(timestamp));
  } catch {}
}

function clearSessionUnlockUntil() {
  try {
    sessionStorage.removeItem(GG84.storage.appLockSessionUntil);
  } catch {}
}

function isSessionCurrentlyUnlocked() {
  const until = getSessionUnlockUntil();
  return until > Date.now();
}

function refreshUnlockedSessionWindow() {
  setSessionUnlockUntil(Date.now() + GG84_APP_LOCK.timeoutMs);
}

function setBackgroundAtNow() {
  try {
    sessionStorage.setItem(GG84.storage.appLockBackgroundAt, String(Date.now()));
  } catch {}
}

function getBackgroundAt() {
  try {
    return Number(sessionStorage.getItem(GG84.storage.appLockBackgroundAt) || "0");
  } catch {
    return 0;
  }
}

function clearBackgroundAt() {
  try {
    sessionStorage.removeItem(GG84.storage.appLockBackgroundAt);
  } catch {}
}

async function hashAppPinWithSalt(pin, saltBase64) {
  const pinBytes = GG84.encoder.encode(String(pin));
  const saltBytes = fromBase64(saltBase64);

  const merged = new Uint8Array(saltBytes.length + pinBytes.length);
  merged.set(saltBytes, 0);
  merged.set(pinBytes, saltBytes.length);

  const digest = await sha256Bytes(merged);
  return toBase64(digest);
}

async function setAppPin(pin) {
  if (!validateAppPin(pin)) {
    throw new Error("PIN non valido.");
  }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltBase64 = toBase64(salt);
  const hash = await hashAppPinWithSalt(pin, saltBase64);

  sSet(GG84.storage.appPinSalt, saltBase64);
  sSet(GG84.storage.appPinHash, hash);
}

async function verifyAppPin(pin) {
  if (!validateAppPin(pin)) return false;

  const storedHash = cleanString(sGet(GG84.storage.appPinHash));
  const saltBase64 = cleanString(sGet(GG84.storage.appPinSalt));

  if (!storedHash || !saltBase64) return false;

  const candidateHash = await hashAppPinWithSalt(pin, saltBase64);
  return candidateHash === storedHash;
}

function removeAppPin() {
  sDel(GG84.storage.appPinHash);
  sDel(GG84.storage.appPinSalt);
  clearSessionUnlockUntil();
  clearBackgroundAt();
}

function shouldEnforceAppLock() {
  return isAppLockEnabled() && hasStoredAppPin() && hasValidIdentityState();
}

function ensureAppLockOverlay() {
  if (gg84AppLockOverlay) return gg84AppLockOverlay;

  const style = document.createElement("style");
  style.textContent = `
    .gg84-lock-overlay {
      position: fixed;
      inset: 0;
      z-index: 20000;
      display: none;
      align-items: center;
      justify-content: center;
      padding: 18px;
      background: rgba(0,0,0,0.45);
      backdrop-filter: blur(6px);
      -webkit-backdrop-filter: blur(6px);
      opacity: 0;
      transition: opacity .22s ease;
    }
    .gg84-lock-overlay.show {
      display: flex;
      opacity: 1;
    }
    .gg84-lock-overlay.unlocking {
      opacity: 0;
    }
    .gg84-lock-card {
      width: min(340px, 92vw);
      background: rgba(255,255,255,0.96);
      border: 1px solid rgba(17,17,17,0.08);
      border-radius: 24px;
      padding: 20px 18px;
      text-align: center;
      box-shadow: 0 18px 40px rgba(0,0,0,0.20);
      font-family: Poppins, Arial, sans-serif;
      color: #111111;
      transform: scale(1);
      transition: transform .22s ease, opacity .22s ease;
    }
    .gg84-lock-overlay.unlocking .gg84-lock-card {
      transform: scale(0.98);
      opacity: 0.88;
    }
    .gg84-lock-logo-wrap {
      width: 72px;
      height: 72px;
      margin: 0 auto 12px;
      border-radius: 20px;
      background: rgba(57,231,95,0.10);
      border: 1px solid rgba(57,231,95,0.18);
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .gg84-lock-logo {
      width: 48px;
      height: 48px;
      object-fit: contain;
      display: block;
    }
    .gg84-lock-title {
      margin: 0;
      font-size: 1rem;
      font-weight: 800;
      line-height: 1.15;
    }
    .gg84-lock-text {
      margin: 8px 0 0;
      font-size: 0.82rem;
      line-height: 1.4;
      color: #4f4f4f;
    }
    .gg84-lock-input {
      width: 100%;
      margin-top: 12px;
      min-height: 48px;
      border-radius: 16px;
      border: 1.5px solid #d9d9d2;
      background: #ffffff;
      color: #111111;
      font-family: inherit;
      font-size: 1rem;
      text-align: center;
      letter-spacing: 0.28em;
      padding: 0 12px;
      outline: none;
    }
    .gg84-lock-input:focus {
      border-color: #39e75f;
      box-shadow: 0 0 0 3px rgba(57,231,95,0.12);
    }
    .gg84-lock-status {
      margin-top: 12px;
      border-radius: 16px;
      padding: 10px 12px;
      font-size: 0.78rem;
      font-weight: 700;
      line-height: 1.35;
      background: #eefaf0;
      border: 1px solid rgba(27,152,63,.22);
      color: #1f6b3b;
      min-height: 42px;
    }
  `;
  document.head.appendChild(style);

  const overlay = document.createElement("div");
  overlay.className = "gg84-lock-overlay";
  overlay.innerHTML = `
    <div class="gg84-lock-card" role="dialog" aria-modal="true" aria-labelledby="gg84-lock-title">
      <div class="gg84-lock-logo-wrap">
        <img src="logo3.png" alt="GG84" class="gg84-lock-logo">
      </div>
      <h2 id="gg84-lock-title" class="gg84-lock-title">GG84 bloccato</h2>
      <input
        id="gg84-lock-pin-input"
        class="gg84-lock-input"
        type="password"
        inputmode="numeric"
        maxlength="6"
        placeholder="••••••"
        autocomplete="off"
      >
      <div id="gg84-lock-status" class="gg84-lock-status">In attesa di sblocco…</div>
    </div>
  `;
  document.body.appendChild(overlay);

  const input = overlay.querySelector("#gg84-lock-pin-input");

  input.addEventListener("input", () => {
    gg84PinInputValue = String(input.value || "").replace(/\D/g, "").slice(0, 6);
    input.value = gg84PinInputValue;

    if (gg84PinInputValue.length === 6 && !gg84UnlockInProgress) {
      unlockAppNow();
    }
  });

  input.addEventListener("keydown", event => {
    if (event.key === "Enter") {
      event.preventDefault();
      unlockAppNow();
    }
  });

  gg84AppLockOverlay = overlay;
  return overlay;
}

function getAppLockOverlayInput() {
  const overlay = ensureAppLockOverlay();
  return overlay.querySelector("#gg84-lock-pin-input");
}

function setAppLockOverlayStatus(message, isError = false) {
  const overlay = ensureAppLockOverlay();
  const status = overlay.querySelector("#gg84-lock-status");
  status.textContent = message;

  if (isError) {
    status.style.background = "#fff1f1";
    status.style.borderColor = "rgba(176,0,32,.22)";
    status.style.color = "#8a1834";
  } else {
    status.style.background = "#eefaf0";
    status.style.borderColor = "rgba(27,152,63,.22)";
    status.style.color = "#1f6b3b";
  }
}

function resetAppLockOverlayInput() {
  gg84PinInputValue = "";
  const input = getAppLockOverlayInput();
  input.value = "";
}

function focusAppLockInput() {
  const input = getAppLockOverlayInput();
  setTimeout(() => {
    try {
      input.focus();
    } catch {}
  }, 80);
}

function clearAppLockTimer() {
  if (gg84AppLockTimer) {
    clearTimeout(gg84AppLockTimer);
    gg84AppLockTimer = null;
  }
}

function scheduleAppRelock() {
  clearAppLockTimer();

  if (!shouldEnforceAppLock() || gg84AppLocked) return;

  refreshUnlockedSessionWindow();

  gg84AppLockTimer = setTimeout(() => {
    clearSessionUnlockUntil();
    lockAppNow("inattività");
  }, GG84_APP_LOCK.timeoutMs);
}

function registerActivityPulse() {
  if (!shouldEnforceAppLock() || gg84AppLocked) return;
  refreshUnlockedSessionWindow();
  scheduleAppRelock();
}

async function playUnlockFade() {
  const overlay = ensureAppLockOverlay();
  overlay.classList.add("unlocking");

  if (navigator.vibrate) {
    try {
      navigator.vibrate(30);
    } catch {}
  }

  await new Promise(resolve => setTimeout(resolve, 180));

  overlay.classList.remove("show");
  overlay.classList.remove("unlocking");
}

async function lockAppNow(reason = "manuale") {
  if (!shouldEnforceAppLock()) return;

  ensureAppLockOverlay().classList.add("show");
  gg84AppLocked = true;
  clearAppLockTimer();
  resetAppLockOverlayInput();

  const message = reason === "inattività"
    ? "App bloccata per inattività."
    : reason === "background"
      ? "App bloccata al rientro."
      : "Inserisci il PIN per continuare.";

  setAppLockOverlayStatus(message, false);
  focusAppLockInput();
}

async function unlockAppNow() {
  if (!shouldEnforceAppLock()) {
    if (gg84AppLockOverlay) {
      gg84AppLockOverlay.classList.remove("show");
      gg84AppLockOverlay.classList.remove("unlocking");
    }
    gg84AppLocked = false;
    registerActivityPulse();
    return true;
  }

  if (gg84UnlockInProgress) return false;

  const pin = cleanString(gg84PinInputValue);

  if (!validateAppPin(pin)) {
    setAppLockOverlayStatus("Inserisci un PIN valido di 6 cifre.", true);
    focusAppLockInput();
    return false;
  }

  gg84UnlockInProgress = true;
  setAppLockOverlayStatus("Verifica PIN in corso…", false);

  try {
    const ok = await verifyAppPin(pin);

    if (!ok) {
      setAppLockOverlayStatus("PIN non corretto.", true);
      resetAppLockOverlayInput();
      focusAppLockInput();
      gg84AppLocked = true;
      return false;
    }

    await playUnlockFade();
    gg84AppLocked = false;
    gg84BackgroundLockPending = false;
    resetAppLockOverlayInput();
    clearBackgroundAt();
    refreshUnlockedSessionWindow();
    registerActivityPulse();
    return true;
  } catch (error) {
    console.error(error);
    setAppLockOverlayStatus("Errore durante la verifica del PIN.", true);
    gg84AppLocked = true;
    return false;
  } finally {
    gg84UnlockInProgress = false;
  }
}

function installAppSecurityActivityHooks() {
  const pulse = () => registerActivityPulse();
  ["click", "touchstart", "keydown", "mousemove"].forEach(eventName => {
    window.addEventListener(eventName, pulse, { passive: true });
  });
}

function installAppSecurityStateHooks() {
  try {
    const appPlugin =
      window.Capacitor &&
      window.Capacitor.Plugins &&
      window.Capacitor.Plugins.App;

    if (!appPlugin || typeof appPlugin.addListener !== "function") return;

    appPlugin.addListener("appStateChange", ({ isActive }) => {
      if (!shouldEnforceAppLock()) return;

      if (!isActive) {
        gg84BackgroundLockPending = true;
        setBackgroundAtNow();
        clearAppLockTimer();
        return;
      }

      const backgroundAt = getBackgroundAt();
      clearBackgroundAt();

      if (gg84BackgroundLockPending) {
        gg84BackgroundLockPending = false;

        if (!backgroundAt) {
          clearSessionUnlockUntil();
          lockAppNow("background");
          return;
        }

        const elapsed = Date.now() - backgroundAt;

        if (elapsed >= GG84_APP_LOCK.timeoutMs) {
          clearSessionUnlockUntil();
          lockAppNow("background");
          return;
        }

        refreshUnlockedSessionWindow();
        registerActivityPulse();
        return;
      }

      registerActivityPulse();
    });
  } catch (error) {
    console.error("App security state hook error:", error);
  }
}

async function setupAppSecurityLayer() {
  if (gg84AppLockReady) return;
  gg84AppLockReady = true;

  installAppSecurityActivityHooks();
  installAppSecurityStateHooks();

  if (!shouldEnforceAppLock()) return;

  ensureAppLockOverlay();

  if (isSessionCurrentlyUnlocked()) {
    registerActivityPulse();
    return;
  }

  await lockAppNow("manuale");
}

/* =========================
   MESSAGGI PROTETTI
========================= */

function isEncryptedPayload(text) {
  return typeof text === "string" && text.startsWith("GG84$2$");
}

async function encryptMessage(plainText, peerPub) {
  const normalizedText = String(plainText ?? "");
  const normalizedPeer = cleanString(peerPub);

  if (!normalizedText) throw new Error("Testo vuoto.");
  if (!isValidPub(normalizedPeer)) throw new Error("Peer non valido.");

  const key = await deriveSharedKey(normalizedPeer);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = GG84.encoder.encode(normalizedText);

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );

  return `GG84$2$${toBase64(iv)}$${toBase64(encrypted)}`;
}

async function decryptMessage(payload, peerPub) {
  try {
    const normalizedPayload = String(payload || "");
    const normalizedPeer = cleanString(peerPub);

    if (!normalizedPayload.startsWith("GG84$2$")) {
      throw new Error("Formato non valido.");
    }

    if (!isValidPub(normalizedPeer)) {
      throw new Error("Peer non valido.");
    }

    const parts = normalizedPayload.split("$");
    if (parts.length !== 4) {
      throw new Error("Payload corrotto.");
    }

    const iv = fromBase64(parts[2]);
    const cipher = fromBase64(parts[3]);

    const key = await deriveSharedKey(normalizedPeer);

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      cipher
    );

    return GG84.decoder.decode(decrypted);
  } catch (_error) {
    throw new Error("Errore decifratura.");
  }
}

/* =========================
   RESET / CLEAN MODE
========================= */

function clearCurrentConnection() {
  clearActivePeer();

  sDel(GG84.storage.flowState);
  sDel(GG84.storage.pendingApprovalLink);
  sDel(GG84.storage.pendingPeerPub);
  sDel(GG84.storage.pendingPeerName);
  sDel(GG84.storage.pendingPeerDevice);
}

async function destroyCurrentConversationKeys() {
  const previousPublicKey = getPublicIdentity();

  clearCurrentConnection();
  clearVerifiedPeer();

  sDel(GG84.storage.privateJwk);
  sDel(GG84.storage.publicKey);

  const regeneratedPub = await generateIdentity();

  if (!isValidPub(regeneratedPub)) {
    throw new Error("Rigenerazione identità non riuscita.");
  }

  return {
    ok: true,
    previousPublicKey,
    newPublicKey: regeneratedPub
  };
}

function resetAllGG84Data() {
  clearCurrentConnection();

  sDel(GG84.storage.privateJwk);
  sDel(GG84.storage.publicKey);
  sDel(GG84.storage.userName);

  sDel(GG84.storage.introDone);
  sDel(GG84.storage.onboardingDone);

  sDel(GG84.storage.appLockEnabled);
  sDel(GG84.storage.appPinHash);
  sDel(GG84.storage.appPinSalt);

  clearSessionUnlockUntil();
  clearBackgroundAt();
}

/* =========================
   LEGACY BRIDGE MINIMO
========================= */

function normalizePublicKey(value) {
  const parsed = parseInviteData(value);
  if (parsed?.pub) return parsed.pub;

  const trimmed = cleanString(value);
  if (isValidPub(trimmed)) return trimmed;
  if (trimmed.startsWith("GG84:")) return cleanString(trimmed.slice(5));
  return "";
}

function extractInviteData(value) {
  const parsed = parseInviteData(value);

  if (!parsed) {
    return {
      key: "",
      pub: "",
      name: "",
      flow: "",
      nonce: "",
      device: "",
      v: ""
    };
  }

  return {
    key: parsed.pub,
    pub: parsed.pub,
    name: parsed.name,
    flow: parsed.flow,
    nonce: "",
    device: parsed.device,
    v: parsed.v
  };
}

function deriveSharedPasswordFromKeys() {
  throw new Error("Motore legacy disattivato in modalità pulita.");
}

function deriveSharedPasswordFromPrivateAndInvite() {
  throw new Error("Motore legacy disattivato in modalità pulita.");
}

/* =========================
   EXPORT
========================= */

window.GG84 = GG84;

window.getEl = getEl;
window.cleanString = cleanString;

window.getUserName = getUserName;
window.getPublicIdentity = getPublicIdentity;
window.hasValidIdentityState = hasValidIdentityState;
window.generateIdentity = generateIdentity;
window.ensureIdentity = ensureIdentity;
window.initGG84 = initGG84;
window.getKeyPair = getKeyPair;

window.getActivePeer = getActivePeer;
window.getActivePeerPublicKey = getActivePeerPublicKey;
window.getActivePeerName = getActivePeerName;
window.setActivePeer = setActivePeer;
window.clearActivePeer = clearActivePeer;

window.buildInviteLink = buildInviteLink;
window.buildConfirmationLink = buildConfirmationLink;
window.parseInviteData = parseInviteData;
window.extractInviteData = extractInviteData;
window.normalizePublicKey = normalizePublicKey;

window.buildConnectionFingerprint = buildConnectionFingerprint;
window.markActivePeerAsVerified = markActivePeerAsVerified;
window.clearVerifiedPeer = clearVerifiedPeer;
window.isActivePeerVerified = isActivePeerVerified;

window.isEncryptedPayload = isEncryptedPayload;
window.encryptMessage = encryptMessage;
window.decryptMessage = decryptMessage;

window.clearCurrentConnection = clearCurrentConnection;
window.destroyCurrentConversationKeys = destroyCurrentConversationKeys;
window.resetAllGG84Data = resetAllGG84Data;

window.validatePrivateKey = validatePrivateKey;
window.validateConnectionPassword = validateConnectionPassword;
window.validateAppPin = validateAppPin;
window.isAppLockEnabled = isAppLockEnabled;
window.hasStoredAppPin = hasStoredAppPin;
window.setAppPin = setAppPin;
window.verifyAppPin = verifyAppPin;
window.removeAppPin = removeAppPin;
window.setupAndroidBackNavigation = setupAndroidBackNavigation;
window.setupEdgeSwipeBackNavigation = setupEdgeSwipeBackNavigation;
window.setupAppSecurityLayer = setupAppSecurityLayer;
window.unlockAppNow = unlockAppNow;
window.lockAppNow = lockAppNow;

/* Bootstrap silenzioso */
(async () => {
  try {
    await initGG84({ autoCreateIdentity: false });
  } catch (error) {
    console.error("GG84 init error:", error);
  }

  try {
    setupAndroidBackNavigation();
    setupEdgeSwipeBackNavigation();
    await setupAppSecurityLayer();
  } catch (error) {
    console.error("GG84 app security error:", error);
  }
})();