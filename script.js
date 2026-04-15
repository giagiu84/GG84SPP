/* GG84 – CORE ECDH + AES-GCM / HKDF
   Modalità Android APK
   Revisione evolutiva pulita
   Nessuna compatibilità legacy
   Visual fingerprint GG84 integrato
   Supporto pairing QR / link / file .gg84
   GG84_V.2_15.04.2026
*/

const GG84 = {
  version: "GG84_V.2_15.04.2026",
  updateTag: "GG84_V.2_15.04.2026",
  inviteVersion: "2",
  messageVersion: "3",
  encoder: new TextEncoder(),
  decoder: new TextDecoder(),

  appLock: {
    timeoutMs: 120000
  },

  visualFingerprint: {
    logoPrimary: "logo3.png",
    logoFallback: "logo3.png"
  },

  linkPayload: {
    type: "gg84_link"
  },

  file: {
    extension: ".gg84",
    version: "2",
    mimeType: "application/json",
    appName: "GG84",
    types: {
      INVITE: "gg84_contact_invite",
      CONFIRM: "gg84_contact_confirm"
    }
  },

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

    pendingInviteFile: "gg84_pending_invite_file",
    pendingConfirmFile: "gg84_pending_confirm_file",
    incomingPayload: "gg84_incoming_payload",

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
  return String(value ?? "").trim();
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

function safeJsonParse(raw, fallback = null) {
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

/* =========================
   BASE64 / BYTES / NUMERI
========================= */

function toBase64(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = "";
  const chunkSize = 0x8000;

  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }

  return btoa(binary);
}

function fromBase64(base64) {
  const normalized = cleanString(base64);
  if (!normalized) return new Uint8Array(0);

  const binary = atob(normalized);
  const out = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }

  return out;
}

function utf8ToBase64(text) {
  return toBase64(GG84.encoder.encode(String(text ?? "")));
}

function base64ToUtf8(base64) {
  return GG84.decoder.decode(fromBase64(base64));
}

function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

function numberToUint32Bytes(value) {
  const out = new Uint8Array(4);
  const normalized = Number(value) >>> 0;

  out[0] = (normalized >>> 24) & 0xff;
  out[1] = (normalized >>> 16) & 0xff;
  out[2] = (normalized >>> 8) & 0xff;
  out[3] = normalized & 0xff;

  return out;
}

function parsePositiveCounter(value) {
  const num = Number(value);
  if (!Number.isInteger(num)) return 0;
  if (num < 1) return 0;
  if (num > 0xffffffff) return 0;
  return num;
}

function concatUint8Arrays(...parts) {
  const validParts = parts.filter(part => part instanceof Uint8Array);
  const total = validParts.reduce((sum, part) => sum + part.length, 0);
  const merged = new Uint8Array(total);

  let offset = 0;
  for (const part of validParts) {
    merged.set(part, offset);
    offset += part.length;
  }

  return merged;
}

/* =========================
   HASH / KDF
========================= */

async function sha256Bytes(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(hash);
}

async function sha256Text(text) {
  return sha256Bytes(GG84.encoder.encode(String(text)));
}

async function deriveHkdfAesKey(rawSecretBytes, saltBytes, infoBytes) {
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    rawSecretBytes,
    "HKDF",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: saltBytes,
      info: infoBytes
    },
    hkdfKey,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["encrypt", "decrypt"]
  );
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
  return !!name && !!pub && !!priv;
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

  if (isValidPub(pub) && priv) {
    return pub;
  }

  return generateIdentity();
}

async function initGG84() {
  if (!window.crypto?.subtle) {
    throw new Error("Web Crypto API non disponibile su questo dispositivo.");
  }

  await ensureIdentity();
  return true;
}

async function getKeyPair() {
  const jwkRaw = sGet(GG84.storage.privateJwk);
  const pubRaw = getPublicIdentity();

  if (!jwkRaw || !isValidPub(pubRaw)) {
    return null;
  }

  const jwk = safeJsonParse(jwkRaw);
  if (!jwk) {
    return null;
  }

  const privateKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
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
   PEER ATTIVO / PENDING
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

  if (!isValidPub(normalizedPub)) {
    return false;
  }

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

function setPendingPeer(pub, name = "", device = "") {
  const normalizedPub = cleanString(pub);
  if (!isValidPub(normalizedPub)) return false;

  sSet(GG84.storage.pendingPeerPub, normalizedPub);
  sSet(GG84.storage.pendingPeerName, cleanString(name));
  sSet(GG84.storage.pendingPeerDevice, cleanString(device));
  return true;
}

function getPendingPeer() {
  const pub = cleanString(sGet(GG84.storage.pendingPeerPub));
  return {
    pub,
    name: cleanString(sGet(GG84.storage.pendingPeerName)),
    device: cleanString(sGet(GG84.storage.pendingPeerDevice)),
    isPending: isValidPub(pub)
  };
}

function clearPendingPeer() {
  sDel(GG84.storage.pendingPeerPub);
  sDel(GG84.storage.pendingPeerName);
  sDel(GG84.storage.pendingPeerDevice);
}

function activatePendingPeer() {
  const pending = getPendingPeer();
  if (!pending.isPending) return false;

  const ok = setActivePeer(pending.pub, pending.name);
  if (!ok) return false;

  clearPendingPeer();
  sDel(GG84.storage.pendingApprovalLink);
  sDel(GG84.storage.flowState);
  return true;
}

/* =========================
   INVITI LINK / PAYLOAD
========================= */

function getDeviceLabel() {
  return "mobile";
}

function buildInvitePayload() {
  const pub = getPublicIdentity();
  if (!isValidPub(pub)) return null;

  return {
    type: GG84.linkPayload.type,
    flow: "invite",
    v: GG84.inviteVersion,
    pub,
    name: getUserName() || "Una persona",
    device: getDeviceLabel(),
    ts: Date.now()
  };
}

function buildConfirmationPayload() {
  const pub = getPublicIdentity();
  if (!isValidPub(pub)) return null;

  return {
    type: GG84.linkPayload.type,
    flow: "confirm",
    v: GG84.inviteVersion,
    pub,
    name: getUserName() || "Una persona",
    device: getDeviceLabel(),
    ts: Date.now()
  };
}

function serializeLinkPayload(payloadOrFlow, pub = "", name = "", device = "mobile") {
  try {
    if (typeof payloadOrFlow === "object" && payloadOrFlow) {
      return JSON.stringify(payloadOrFlow);
    }

    const flow = cleanString(payloadOrFlow);
    const normalizedPub = cleanString(pub);
    const normalizedName = cleanString(name);
    const normalizedDevice = cleanString(device) || "mobile";

    if (!flow || !isValidPub(normalizedPub)) {
      return "";
    }

    let out = `chiave.html?flow=${encodeURIComponent(flow)}&v=${encodeURIComponent(GG84.inviteVersion)}&pub=${encodeURIComponent(normalizedPub)}`;

    if (normalizedName) {
      out += `&name=${encodeURIComponent(normalizedName)}`;
    }

    out += `&device=${encodeURIComponent(normalizedDevice)}`;
    return out;
  } catch {
    return "";
  }
}

function buildInviteLink() {
  const payload = buildInvitePayload();
  if (!payload) return "";

  return `chiave.html?flow=receive&v=${encodeURIComponent(payload.v)}&pub=${encodeURIComponent(payload.pub)}&name=${encodeURIComponent(payload.name)}&device=${encodeURIComponent(payload.device)}`;
}

function buildConfirmationLink() {
  const payload = buildConfirmationPayload();
  if (!payload) return "";

  return `chiave.html?flow=confirm&v=${encodeURIComponent(payload.v)}&pub=${encodeURIComponent(payload.pub)}&name=${encodeURIComponent(payload.name)}&device=${encodeURIComponent(payload.device)}`;
}

function parseLinkPayload(raw) {
  try {
    const parsed = typeof raw === "string" ? JSON.parse(raw) : raw;

    if (!parsed || parsed.type !== GG84.linkPayload.type) return null;
    if (parsed.flow !== "invite" && parsed.flow !== "confirm") return null;

    const pub = cleanString(parsed.pub);
    if (!isValidPub(pub)) return null;

    return {
      type: GG84.linkPayload.type,
      flow: cleanString(parsed.flow),
      v: cleanString(parsed.v || GG84.inviteVersion),
      pub,
      name: cleanString(parsed.name),
      device: cleanString(parsed.device),
      ts: Number(parsed.ts || 0)
    };
  } catch {
    return null;
  }
}

function parseInviteData(raw) {
  const normalized = cleanString(raw);
  if (!normalized) return null;

  const parsedFilePayload = parseGg84File(normalized);
  if (parsedFilePayload) {
    return {
      pub: parsedFilePayload.pub,
      name: parsedFilePayload.name,
      flow: parsedFilePayload.flow,
      device: parsedFilePayload.meta?.device || "",
      v: parsedFilePayload.v,
      type: parsedFilePayload.type,
      ts: parsedFilePayload.ts,
      source: "gg84_file"
    };
  }

  const parsedLinkPayload = parseLinkPayload(normalized);
  if (parsedLinkPayload) {
    return {
      pub: parsedLinkPayload.pub,
      name: parsedLinkPayload.name,
      flow: parsedLinkPayload.flow,
      device: parsedLinkPayload.device,
      v: parsedLinkPayload.v,
      type: parsedLinkPayload.type,
      ts: parsedLinkPayload.ts,
      source: "gg84_link"
    };
  }

  try {
    const fakeUrl = normalized.startsWith("http")
      ? normalized
      : `https://local.test/${normalized.replace(/^\//, "")}`;

    const url = new URL(fakeUrl);
    const pub = cleanString(url.searchParams.get("pub") || url.searchParams.get("key"));
    const name = cleanString(url.searchParams.get("name"));
    const flow = cleanString(url.searchParams.get("flow"));
    const device = cleanString(url.searchParams.get("device"));
    const v = cleanString(url.searchParams.get("v")) || GG84.inviteVersion;

    if (!isValidPub(pub)) return null;

    return { pub, name, flow, device, v, source: "url" };
  } catch {
    return null;
  }
}

function handleLinkPayload(raw) {
  const parsed = parseInviteData(raw);
  if (!parsed) return null;

  if (parsed.flow === "invite") {
    setPendingPeer(parsed.pub, parsed.name, parsed.device);
    sSet(GG84.storage.flowState, "pending");
    return {
      ok: true,
      mode: "invite",
      peer: parsed
    };
  }

  if (parsed.flow === "confirm") {
    const ok = setActivePeer(parsed.pub, parsed.name);
    if (!ok) return null;

    sDel(GG84.storage.flowState);
    clearPendingPeer();

    return {
      ok: true,
      mode: "confirm",
      peer: parsed
    };
  }

  return null;
}

async function autoHandleScannedQr(raw) {
  const parsed = parseInviteData(raw);
  if (!parsed) return null;

  if (parsed.flow === "confirm") {
    const ok = setActivePeer(parsed.pub, parsed.name);
    if (!ok) return null;

    clearPendingPeer();
    sDel(GG84.storage.pendingApprovalLink);
    sDel(GG84.storage.flowState);

    return {
      ok: true,
      mode: "confirm",
      peer: parsed
    };
  }

  setPendingPeer(parsed.pub, parsed.name, parsed.device);
  sSet(GG84.storage.flowState, "pending");

  const confirmPayload = buildConfirmationLink();
  sSet(GG84.storage.pendingApprovalLink, confirmPayload);

  return {
    ok: true,
    mode: "invite",
    peer: parsed,
    approval: confirmPayload
  };
}

/* =========================
   FILE GG84 (.gg84)
========================= */

function getSafeFileBaseName(value, fallback = "contatto_GG84") {
  const cleaned = cleanString(value)
    .replace(/[^\p{L}\p{N}_-]+/gu, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "");

  return cleaned || fallback;
}

function buildInviteFilePayload() {
  const pub = getPublicIdentity();
  if (!isValidPub(pub)) return null;

  return {
    v: GG84.file.version,
    type: GG84.file.types.INVITE,
    flow: "invite",
    name: getUserName() || "Una persona",
    pub,
    ts: Date.now(),
    meta: {
      device: "android",
      app: GG84.file.appName
    }
  };
}

function buildConfirmFilePayload() {
  const pub = getPublicIdentity();
  if (!isValidPub(pub)) return null;

  return {
    v: GG84.file.version,
    type: GG84.file.types.CONFIRM,
    flow: "confirm",
    name: getUserName() || "Una persona",
    pub,
    ts: Date.now(),
    meta: {
      device: "android",
      app: GG84.file.appName
    }
  };
}

function serializeGg84File(payload) {
  try {
    if (!payload || typeof payload !== "object") return "";
    return JSON.stringify(payload, null, 2);
  } catch (error) {
    console.error("Serialize GG84 file error:", error);
    return "";
  }
}

function tryParseJsonObject(text) {
  const normalized = String(text || "").replace(/^\uFEFF/, "");
  const parsed = safeJsonParse(normalized, null);
  return parsed && typeof parsed === "object" ? parsed : null;
}

function sanitizeBase64String(raw) {
  return cleanString(raw)
    .replace(/[\r\n\t ]+/g, "")
    .replace(/[^A-Za-z0-9+/=]/g, "");
}

function tryDecodeBase64ToUtf8(raw) {
  try {
    const normalized = sanitizeBase64String(raw);
    if (!normalized || normalized.length < 16) return "";
    return base64ToUtf8(normalized);
  } catch {
    return "";
  }
}

function parseGg84File(text) {
  try {
    const raw = String(text || "");
    const candidates = [];

    if (raw) candidates.push(raw);

    const trimmed = cleanString(raw);
    if (trimmed && trimmed !== raw) {
      candidates.push(trimmed);
    }

    const decodedRaw = tryDecodeBase64ToUtf8(raw);
    if (decodedRaw) {
      candidates.push(decodedRaw);
    }

    const decodedTrimmed = tryDecodeBase64ToUtf8(trimmed);
    if (decodedTrimmed && !candidates.includes(decodedTrimmed)) {
      candidates.push(decodedTrimmed);
    }

    let parsed = null;
    for (const candidate of candidates) {
      parsed = tryParseJsonObject(candidate);
      if (parsed) break;
    }

    if (!parsed) return null;

    const type = cleanString(parsed.type);
    const flow = cleanString(parsed.flow);
    const pub = cleanString(parsed.pub);
    const name = cleanString(parsed.name);
    const v = cleanString(parsed.v || GG84.file.version);
    const ts = Number(parsed.ts || 0);

    if (
      type !== GG84.file.types.INVITE &&
      type !== GG84.file.types.CONFIRM
    ) {
      return null;
    }

    if (flow !== "invite" && flow !== "confirm") {
      return null;
    }

    if (!isValidPub(pub)) {
      return null;
    }

    const meta = parsed.meta && typeof parsed.meta === "object" ? parsed.meta : {};

    return {
      v,
      type,
      flow,
      name,
      pub,
      ts: Number.isFinite(ts) ? ts : 0,
      meta: {
        device: cleanString(meta.device),
        app: cleanString(meta.app)
      }
    };
  } catch (error) {
    console.error("Parse GG84 file error:", error);
    return null;
  }
}

function buildInviteFileName() {
  const name = getSafeFileBaseName(getUserName(), "contatto_GG84");
  return `invito_${name}${GG84.file.extension}`;
}

function buildConfirmFileName() {
  const name = getSafeFileBaseName(getUserName(), "contatto_GG84");
  return `risposta_${name}${GG84.file.extension}`;
}

async function exportGg84File(payload, filename) {
  try {
    const json = serializeGg84File(payload);
    if (!json) {
      throw new Error("Payload file vuoto.");
    }

    const safeName = cleanString(filename) || `contatto${GG84.file.extension}`;
    const mimeType = GG84.file.mimeType || "application/json";
    const blob = new Blob([json], { type: mimeType });

    if (window.Capacitor?.Plugins?.Filesystem && window.Capacitor?.Plugins?.Share) {
      try {
        const Filesystem = window.Capacitor.Plugins.Filesystem;
        const Share = window.Capacitor.Plugins.Share;

        const data = utf8ToBase64(json);
        const result = await Filesystem.writeFile({
          path: safeName,
          data,
          directory: "CACHE"
        });

        await Share.share({
          title: "Contatto GG84",
          text: "File GG84 pronto",
          url: result.uri,
          dialogTitle: "Condividi con GG84"
        });

        return {
          ok: true,
          uri: result.uri,
          path: safeName,
          method: "capacitor-share"
        };
      } catch (nativeError) {
        console.warn("GG84 native share fallback:", nativeError);
      }
    }

    if (navigator.share && typeof File !== "undefined") {
      try {
        const file = new File([blob], safeName, { type: mimeType });

        if (!navigator.canShare || navigator.canShare({ files: [file] })) {
          await navigator.share({
            title: "Contatto GG84",
            files: [file]
          });

          return {
            ok: true,
            path: safeName,
            method: "web-share-files"
          };
        }
      } catch (shareError) {
        console.warn("GG84 web share fallback:", shareError);
      }
    }

    try {
      const objectUrl = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = objectUrl;
      a.download = safeName;
      a.rel = "noopener";
      a.style.display = "none";
      document.body.appendChild(a);
      a.click();
      setTimeout(() => {
        try { document.body.removeChild(a); } catch {}
        URL.revokeObjectURL(objectUrl);
      }, 1200);

      return {
        ok: true,
        path: safeName,
        method: "blob-download"
      };
    } catch (downloadError) {
      console.warn("GG84 blob download fallback:", downloadError);
    }

    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(json);
      return {
        ok: true,
        path: safeName,
        method: "clipboard",
        clipboard: true,
        text: json
      };
    }

    return {
      ok: true,
      path: safeName,
      method: "plain-text",
      text: json
    };
  } catch (error) {
    console.error("Export GG84 file error:", error);
    return {
      ok: false,
      error
    };
  }
}

async function exportInviteGg84File() {
  const payload = buildInviteFilePayload();
  if (!payload) {
    return { ok: false, error: new Error("Payload invito non disponibile.") };
  }

  return exportGg84File(payload, buildInviteFileName());
}

async function exportConfirmGg84File() {
  const payload = buildConfirmFilePayload();
  if (!payload) {
    return { ok: false, error: new Error("Payload conferma non disponibile.") };
  }

  return exportGg84File(payload, buildConfirmFileName());
}

function handleGg84FileContent(fileText) {
  const parsed = parseGg84File(fileText);
  if (!parsed) return null;

  if (parsed.flow === "invite") {
    setPendingPeer(parsed.pub, parsed.name, parsed.meta.device);
    sSet(GG84.storage.flowState, "pending");
    sSet(GG84.storage.pendingInviteFile, serializeGg84File(parsed));

    return {
      ok: true,
      flow: "invite",
      data: parsed,
      name: parsed.name || ""
    };
  }

  if (parsed.flow === "confirm") {
    const ok = setActivePeer(parsed.pub, parsed.name);
    if (!ok) return null;

    clearPendingPeer();
    sDel(GG84.storage.pendingApprovalLink);
    sDel(GG84.storage.flowState);
    sSet(GG84.storage.pendingConfirmFile, serializeGg84File(parsed));

    return {
      ok: true,
      flow: "confirm",
      data: parsed,
      name: parsed.name || ""
    };
  }

  return null;
}

async function tryReadIncomingUrl(url) {
  try {
    const normalized = cleanString(url);
    if (!normalized) return null;

    if (normalized.startsWith("data:")) {
      const commaIndex = normalized.indexOf(",");
      if (commaIndex > -1) {
        const rawData = normalized.slice(commaIndex + 1);
        return decodeURIComponent(rawData);
      }
    }

    if (/\.gg84($|\?)/i.test(normalized)) {
      const response = await fetch(normalized);
      return await response.text();
    }

    return null;
  } catch (error) {
    console.error("Read incoming URL error:", error);
    return null;
  }
}

async function handleIncomingFile(url) {
  const content = await tryReadIncomingUrl(url);
  if (!content) return null;

  return handleGg84FileContent(content);
}

function consumeNativeIncomingStoredFile() {
  try {
    const storedB64 = cleanString(localStorage.getItem("gg84_native_incoming_file_b64") || "");
    if (!storedB64) return null;

    const content = base64ToUtf8(storedB64);

    localStorage.removeItem("gg84_native_incoming_file_b64");
    localStorage.removeItem("gg84_native_incoming_file_uri_b64");

    return handleGg84FileContent(content);
  } catch (error) {
    console.error("Consume native stored GG84 file error:", error);
    return null;
  }
}

/* =========================
   FINGERPRINT
========================= */

async function buildConnectionFingerprint(peerPub) {
  const myPub = getPublicIdentity();
  const otherPub = cleanString(peerPub);

  if (!isValidPub(myPub) || !isValidPub(otherPub)) {
    return "";
  }

  const combined = [myPub, otherPub].sort().join("|");
  const hashBytes = await sha256Text(`GG84|FPR|${combined}`);
  const shortHex = bytesToHex(hashBytes.slice(0, 8)).toUpperCase();
  const parts = shortHex.match(/.{1,4}/g);

  return parts ? parts.join("-") : shortHex;
}

function clampNumber(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function hslToHex(h, s, l) {
  const hue = ((Number(h) % 360) + 360) % 360;
  const sat = clampNumber(Number(s), 0, 100) / 100;
  const lig = clampNumber(Number(l), 0, 100) / 100;

  const c = (1 - Math.abs(2 * lig - 1)) * sat;
  const x = c * (1 - Math.abs((hue / 60) % 2 - 1));
  const m = lig - c / 2;

  let r = 0;
  let g = 0;
  let b = 0;

  if (hue < 60) {
    r = c; g = x; b = 0;
  } else if (hue < 120) {
    r = x; g = c; b = 0;
  } else if (hue < 180) {
    r = 0; g = c; b = x;
  } else if (hue < 240) {
    r = 0; g = x; b = c;
  } else if (hue < 300) {
    r = x; g = 0; b = c;
  } else {
    r = c; g = 0; b = x;
  }

  const toHex = n => Math.round((n + m) * 255).toString(16).padStart(2, "0");
  return `#${toHex(r)}${toHex(g)}${toHex(b)}`.toUpperCase();
}

function hexToRgba(hex, alpha = 1) {
  const normalized = cleanString(hex).replace("#", "");
  if (!/^[0-9a-fA-F]{6}$/.test(normalized)) {
    return `rgba(17,17,17,${alpha})`;
  }

  const r = parseInt(normalized.slice(0, 2), 16);
  const g = parseInt(normalized.slice(2, 4), 16);
  const b = parseInt(normalized.slice(4, 6), 16);
  const safeAlpha = clampNumber(Number(alpha), 0, 1);

  return `rgba(${r}, ${g}, ${b}, ${safeAlpha})`;
}

function buildVisualFingerprintFromFingerprint(fingerprint) {
  const normalized = cleanString(fingerprint).replace(/-/g, "");
  if (!/^[0-9A-Fa-f]{8,}$/.test(normalized)) {
    return {
      fingerprint: "",
      shortCode: "",
      logoPrimary: GG84.visualFingerprint.logoPrimary,
      logoFallback: GG84.visualFingerprint.logoFallback,
      hue: 0,
      accentHex: "#39E75F",
      accentSoftHex: "#EEFAF0",
      accentDarkHex: "#1B983F",
      glowRgba: "rgba(57, 231, 95, 0.28)",
      ringRgba: "rgba(57, 231, 95, 0.18)",
      textHex: "#111111"
    };
  }

  const seedA = parseInt(normalized.slice(0, 2), 16);
  const seedD = parseInt(normalized.slice(6, 8), 16);

  const hue = Math.round((seedA / 255) * 359);
  const saturation = 78;
  const lightness = 48;

  const accentHex = hslToHex(hue, saturation, lightness);
  const accentSoftHex = hslToHex(hue, 64, 94);
  const accentDarkHex = hslToHex(hue, 84, 34);

  const shortCodeParts = normalized.slice(0, 8).toUpperCase().match(/.{1,4}/g);
  const shortCode = shortCodeParts ? shortCodeParts.join("-") : normalized.slice(0, 8).toUpperCase();

  return {
    fingerprint: normalized.toUpperCase(),
    shortCode,
    logoPrimary: GG84.visualFingerprint.logoPrimary,
    logoFallback: GG84.visualFingerprint.logoFallback,
    hue,
    accentHex,
    accentSoftHex,
    accentDarkHex,
    glowRgba: hexToRgba(accentHex, 0.28),
    ringRgba: hexToRgba(accentHex, 0.18),
    textHex: seedD > 127 ? "#111111" : "#1B1B1B"
  };
}

async function buildConnectionVisualFingerprint(peerPub) {
  const fingerprint = await buildConnectionFingerprint(peerPub);
  return buildVisualFingerprintFromFingerprint(fingerprint);
}

async function verifyConnectionVisualCode(pubA, pubB) {
  const a = cleanString(pubA);
  const b = cleanString(pubB);
  if (!isValidPub(a) || !isValidPub(b)) return "";

  const ordered = [a, b].sort().join("|");
  const digest = await sha256Text(`GG84|VERIFY|${ordered}`);
  return Array.from(digest.slice(0, 3)).join("-");
}

/* =========================
   KDF ECDH -> AES
========================= */

async function deriveSharedSecretBytes(peerPublicKeyBase64) {
  const pair = await getKeyPair();

  if (!pair) {
    throw new Error("Identità locale non disponibile.");
  }

  const normalizedPeer = cleanString(peerPublicKeyBase64);

  if (!isValidPub(normalizedPeer)) {
    throw new Error("Chiave pubblica peer non valida.");
  }

  const peerKey = await crypto.subtle.importKey(
    "raw",
    fromBase64(normalizedPeer),
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

async function deriveMessageKey(peerPublicKeyBase64, saltBytes, counter) {
  const myPub = getPublicIdentity();
  const otherPub = cleanString(peerPublicKeyBase64);

  if (!isValidPub(myPub) || !isValidPub(otherPub)) {
    throw new Error("Chiave pubblica non valida.");
  }

  if (!(saltBytes instanceof Uint8Array) || saltBytes.length < 16) {
    throw new Error("Salt non valido.");
  }

  const normalizedCounter = parsePositiveCounter(counter);
  if (!normalizedCounter) {
    throw new Error("Counter non valido.");
  }

  const rawSecret = await deriveSharedSecretBytes(otherPub);
  const orderedContext = [myPub, otherPub].sort().join("|");
  const infoBytes = concatUint8Arrays(
    GG84.encoder.encode(`GG84|ECDH|AESGCM|MSG|${orderedContext}|`),
    numberToUint32Bytes(normalizedCounter)
  );

  return deriveHkdfAesKey(rawSecret, saltBytes, infoBytes);
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
      const exitDelay = 1500;

      if (now - gg84LastBackPress < exitDelay) {
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

  const edgeSize = 28;
  const minSwipeX = 70;
  const maxSwipeY = 60;

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
      gg84TouchTracking = gg84TouchStartX <= edgeSize;
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

      if (deltaX < minSwipeX) return;
      if (deltaY > maxSwipeY) return;

      if (!gg84IsHomePage()) {
        gg84GoBackOrHome();
        return;
      }

      const appPlugin =
        window.Capacitor &&
        window.Capacitor.Plugins &&
        window.Capacitor.Plugins.App;

      const now = Date.now();
      const exitDelay = 1500;

      if (now - gg84LastBackPress < exitDelay) {
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
  return getSessionUnlockUntil() > Date.now();
}

function refreshUnlockedSessionWindow() {
  setSessionUnlockUntil(Date.now() + GG84.appLock.timeoutMs);
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
  const merged = concatUint8Arrays(saltBytes, pinBytes);
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

  if (!shouldEnforceAppLock() || gg84AppLocked) {
    return;
  }

  refreshUnlockedSessionWindow();

  gg84AppLockTimer = setTimeout(() => {
    clearSessionUnlockUntil();
    lockAppNow("inattività");
  }, GG84.appLock.timeoutMs);
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

  const message =
    reason === "inattività"
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

  if (gg84UnlockInProgress) {
    return false;
  }

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

        if (elapsed >= GG84.appLock.timeoutMs) {
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
  return typeof text === "string" && text.startsWith("GG84$3$");
}

async function encryptMessage(plainText, peerPub) {
  const normalizedText = String(plainText ?? "");
  const normalizedPeer = cleanString(peerPub);

  if (!normalizedText) {
    throw new Error("Testo vuoto.");
  }

  if (!isValidPub(normalizedPeer)) {
    throw new Error("Peer non valido.");
  }

  const counterBytes = crypto.getRandomValues(new Uint8Array(4));
  let counter = (
    (counterBytes[0] << 24) |
    (counterBytes[1] << 16) |
    (counterBytes[2] << 8) |
    counterBytes[3]
  ) >>> 0;

  if (counter === 0) {
    counter = 1;
  }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = GG84.encoder.encode(normalizedText);
  const key = await deriveMessageKey(normalizedPeer, salt, counter);

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );

  return [
    "GG84",
    GG84.messageVersion,
    String(counter),
    toBase64(salt),
    toBase64(iv),
    toBase64(encrypted)
  ].join("$");
}

async function decryptMessage(payload, peerPub) {
  try {
    const normalizedPayload = String(payload || "");
    const normalizedPeer = cleanString(peerPub);

    if (!normalizedPayload.startsWith("GG84$3$")) {
      throw new Error("Formato non valido.");
    }

    if (!isValidPub(normalizedPeer)) {
      throw new Error("Peer non valido.");
    }

    const parts = normalizedPayload.split("$");
    if (parts.length !== 6) {
      throw new Error("Payload corrotto.");
    }

    const counter = parsePositiveCounter(parts[2]);
    const salt = fromBase64(parts[3]);
    const iv = fromBase64(parts[4]);
    const cipher = fromBase64(parts[5]);

    if (!counter) throw new Error("Counter non valido.");
    if (salt.length < 16) throw new Error("Salt non valido.");
    if (iv.length !== 12) throw new Error("IV non valido.");
    if (!cipher.length) throw new Error("Ciphertext non valido.");

    const key = await deriveMessageKey(normalizedPeer, salt, counter);

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      cipher
    );

    return GG84.decoder.decode(decrypted);
  } catch {
    throw new Error("Errore decifratura.");
  }
}

/* =========================
   RESET / CLEAN MODE
========================= */

function clearCurrentConnection() {
  clearActivePeer();
  clearPendingPeer();

  sDel(GG84.storage.flowState);
  sDel(GG84.storage.pendingApprovalLink);
  sDel(GG84.storage.pendingInviteFile);
  sDel(GG84.storage.pendingConfirmFile);
  sDel(GG84.storage.incomingPayload);
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
   CAPACITOR INCOMING HOOK
========================= */

function setupIncomingFileListener() {
  try {
    const appPlugin =
      window.Capacitor &&
      window.Capacitor.Plugins &&
      window.Capacitor.Plugins.App;

    if (!appPlugin || typeof appPlugin.addListener !== "function") return;

    appPlugin.addListener("appUrlOpen", async data => {
      const url = cleanString(data && data.url);
      if (!url) return;

      sSet(GG84.storage.incomingPayload, url);

      if (/\.gg84($|\?)/i.test(url)) {
        await handleIncomingFile(url);
      }
    });
  } catch (error) {
    console.error("Incoming file listener error:", error);
  }
}

/* =========================
   EXPORT GLOBALI
========================= */

window.GG84 = GG84;

window.getEl = getEl;
window.cleanString = cleanString;
window.safeJsonParse = safeJsonParse;

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
window.setPendingPeer = setPendingPeer;
window.getPendingPeer = getPendingPeer;
window.clearPendingPeer = clearPendingPeer;
window.activatePendingPeer = activatePendingPeer;

window.buildInvitePayload = buildInvitePayload;
window.buildConfirmationPayload = buildConfirmationPayload;
window.serializeLinkPayload = serializeLinkPayload;
window.buildInviteLink = buildInviteLink;
window.buildConfirmationLink = buildConfirmationLink;
window.parseInviteData = parseInviteData;
window.parseLinkPayload = parseLinkPayload;
window.handleLinkPayload = handleLinkPayload;
window.autoHandleScannedQr = autoHandleScannedQr;
window.extractInviteData = extractInviteData;
window.normalizePublicKey = normalizePublicKey;

window.buildInviteFilePayload = buildInviteFilePayload;
window.buildConfirmFilePayload = buildConfirmFilePayload;
window.serializeGg84File = serializeGg84File;
window.parseGg84File = parseGg84File;
window.buildInviteFileName = buildInviteFileName;
window.buildConfirmFileName = buildConfirmFileName;
window.exportGg84File = exportGg84File;
window.exportInviteGg84File = exportInviteGg84File;
window.exportConfirmGg84File = exportConfirmGg84File;
window.handleGg84FileContent = handleGg84FileContent;
window.handleIncomingFile = handleIncomingFile;
window.consumeNativeIncomingStoredFile = consumeNativeIncomingStoredFile;

window.buildConnectionFingerprint = buildConnectionFingerprint;
window.buildVisualFingerprintFromFingerprint = buildVisualFingerprintFromFingerprint;
window.buildConnectionVisualFingerprint = buildConnectionVisualFingerprint;
window.verifyConnectionVisualCode = verifyConnectionVisualCode;
window.markActivePeerAsVerified = markActivePeerAsVerified;
window.clearVerifiedPeer = clearVerifiedPeer;
window.isActivePeerVerified = isActivePeerVerified;

window.deriveSharedSecretBytes = deriveSharedSecretBytes;
window.deriveMessageKey = deriveMessageKey;

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
window.setupIncomingFileListener = setupIncomingFileListener;
window.unlockAppNow = unlockAppNow;
window.lockAppNow = lockAppNow;

/* Bootstrap silenzioso */
(async () => {
  try {
    await initGG84();
  } catch (error) {
    console.error("GG84 init error:", error);
  }

  try {
    setupAndroidBackNavigation();
    setupEdgeSwipeBackNavigation();
    setupIncomingFileListener();
    await setupAppSecurityLayer();
  } catch (error) {
    console.error("GG84 app security error:", error);
  }
})();