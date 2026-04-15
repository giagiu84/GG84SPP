<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>script.js aligned - GG84_V.2_15.04.2026</title>
<style>
body { margin:0; font-family: Arial, sans-serif; background:#f4f4f2; color:#111; }
header { padding:14px 16px; background:#111; color:#fff; font-weight:700; }
main { padding:16px; }
pre { white-space: pre-wrap; word-break: break-word; background:#fff; border:1px solid #ddd; border-radius:12px; padding:14px; font-size:12px; line-height:1.45; }
</style>
</head>
<body>
<header>script.js aligned - GG84_V.2_15.04.2026</header>
<main><pre>/* GG84 – CORE ECDH + AES-GCM / HKDF
   Modalità Android APK
   Revisione evolutiva pulita
   Nessuna compatibilità legacy
   Visual fingerprint GG84 integrato
   Supporto pairing QR / link / file .gg84
   GG84_V.2_13.04.26
*/

const GG84 = {
  version: &quot;GG84_V.2_13.04.26&quot;,
  updateTag: &quot;GG84_V.2_13.04.26&quot;,
  inviteVersion: &quot;2&quot;,
  messageVersion: &quot;3&quot;,
  encoder: new TextEncoder(),
  decoder: new TextDecoder(),

  appLock: {
    timeoutMs: 120000
  },

  visualFingerprint: {
    logoPrimary: &quot;logo3.jpg&quot;,
    logoFallback: &quot;logo3.png&quot;
  },

  linkPayload: {
    type: &quot;gg84_link&quot;
  },

  file: {
    extension: &quot;.gg84&quot;,
    version: &quot;2&quot;,
    mimeType: &quot;application/x-gg84&quot;,
    appName: &quot;GG84&quot;,
    types: {
      INVITE: &quot;gg84_contact_invite&quot;,
      CONFIRM: &quot;gg84_contact_confirm&quot;
    }
  },

  storage: {
    introDone: &quot;gg84_intro_done&quot;,
    onboardingDone: &quot;gg84_onboarding_done&quot;,
    userName: &quot;gg84_user_name&quot;,

    privateJwk: &quot;gg84_private&quot;,
    publicKey: &quot;gg84_public&quot;,

    activePeerPub: &quot;gg84_active_peer_pub&quot;,
    peerName: &quot;gg84_peer_name&quot;,
    verifiedPeerPub: &quot;gg84_verified_peer_pub&quot;,

    flowState: &quot;gg84_flow_state&quot;,
    pendingApprovalLink: &quot;gg84_pending_approval_link&quot;,
    pendingPeerPub: &quot;gg84_pending_peer_pub&quot;,
    pendingPeerName: &quot;gg84_pending_peer_name&quot;,
    pendingPeerDevice: &quot;gg84_pending_peer_device&quot;,

    pendingInviteFile: &quot;gg84_pending_invite_file&quot;,
    pendingConfirmFile: &quot;gg84_pending_confirm_file&quot;,
    incomingPayload: &quot;gg84_incoming_payload&quot;,

    appLockEnabled: &quot;gg84_app_lock_enabled&quot;,
    appPinHash: &quot;gg84_app_pin_hash&quot;,
    appPinSalt: &quot;gg84_app_pin_salt&quot;,
    appLockSessionUntil: &quot;gg84_app_lock_session_until&quot;,
    appLockBackgroundAt: &quot;gg84_app_lock_background_at&quot;
  }
};

/* =========================
   BASI / STORAGE
========================= */

function getEl(id) {
  return document.getElementById(id);
}

function cleanString(value) {
  return String(value ?? &quot;&quot;).trim();
}

function sGet(key) {
  try {
    return localStorage.getItem(key) || &quot;&quot;;
  } catch {
    return &quot;&quot;;
  }
}

function sSet(key, value) {
  try {
    const normalized = typeof value === &quot;string&quot; ? value : String(value ?? &quot;&quot;);
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
  let binary = &quot;&quot;;
  const chunkSize = 0x8000;

  for (let i = 0; i &lt; bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }

  return btoa(binary);
}

function fromBase64(base64) {
  const normalized = cleanString(base64);
  if (!normalized) return new Uint8Array(0);

  const binary = atob(normalized);
  const out = new Uint8Array(binary.length);

  for (let i = 0; i &lt; binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }

  return out;
}

function utf8ToBase64(text) {
  return toBase64(GG84.encoder.encode(String(text ?? &quot;&quot;)));
}

function base64ToUtf8(base64) {
  return GG84.decoder.decode(fromBase64(base64));
}

function bytesToHex(bytes) {
  return Array.from(bytes, b =&gt; b.toString(16).padStart(2, &quot;0&quot;)).join(&quot;&quot;);
}

function parsePositiveCounter(value) {
  const num = Number(value);
  if (!Number.isInteger(num)) return 0;
  if (num &lt; 1) return 0;
  if (num &gt; 0xffffffff) return 0;
  return num;
}

function numberToUint32Bytes(value) {
  const out = new Uint8Array(4);
  const normalized = Number(value) &gt;&gt;&gt; 0;

  out[0] = (normalized &gt;&gt;&gt; 24) &amp; 0xff;
  out[1] = (normalized &gt;&gt;&gt; 16) &amp; 0xff;
  out[2] = (normalized &gt;&gt;&gt; 8) &amp; 0xff;
  out[3] = normalized &amp; 0xff;

  return out;
}

function parsePositiveCounter(value) {
  const num = Number(value);
  if (!Number.isInteger(num)) return 0;
  if (num &lt; 1) return 0;
  if (num &gt; 0xffffffff) return 0;
  return num;
}

function concatUint8Arrays(...parts) {
  const validParts = parts.filter(part =&gt; part instanceof Uint8Array);
  const total = validParts.reduce((sum, part) =&gt; sum + part.length, 0);
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
  const hash = await crypto.subtle.digest(&quot;SHA-256&quot;, bytes);
  return new Uint8Array(hash);
}

async function sha256Text(text) {
  return sha256Bytes(GG84.encoder.encode(String(text)));
}

async function deriveHkdfAesKey(rawSecretBytes, saltBytes, infoBytes) {
  const hkdfKey = await crypto.subtle.importKey(
    &quot;raw&quot;,
    rawSecretBytes,
    &quot;HKDF&quot;,
    false,
    [&quot;deriveKey&quot;]
  );

  return crypto.subtle.deriveKey(
    {
      name: &quot;HKDF&quot;,
      hash: &quot;SHA-256&quot;,
      salt: saltBytes,
      info: infoBytes
    },
    hkdfKey,
    {
      name: &quot;AES-GCM&quot;,
      length: 256
    },
    false,
    [&quot;encrypt&quot;, &quot;decrypt&quot;]
  );
}

/* =========================
   VALIDAZIONI
========================= */

function isValidPub(value) {
  const v = cleanString(value);
  return /^[A-Za-z0-9+/=]+$/.test(v) &amp;&amp; v.length &gt;= 80;
}

function validatePrivateKey(pw) {
  return (
    typeof pw === &quot;string&quot; &amp;&amp;
    pw.length &gt;= 8 &amp;&amp;
    /[A-Z]/.test(pw) &amp;&amp;
    /[^a-zA-Z0-9]/.test(pw)
  );
}

function validateConnectionPassword(_pw) {
  return false;
}

function validateAppPin(pin) {
  return typeof pin === &quot;string&quot; &amp;&amp; /^\d{6}$/.test(pin);
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
  return !!name &amp;&amp; !!pub &amp;&amp; !!priv;
}

async function generateIdentity() {
  const keyPair = await crypto.subtle.generateKey(
    { name: &quot;ECDH&quot;, namedCurve: &quot;P-256&quot; },
    true,
    [&quot;deriveBits&quot;]
  );

  const publicRaw = await crypto.subtle.exportKey(&quot;raw&quot;, keyPair.publicKey);
  const privateJwk = await crypto.subtle.exportKey(&quot;jwk&quot;, keyPair.privateKey);

  sSet(GG84.storage.privateJwk, JSON.stringify(privateJwk));
  sSet(GG84.storage.publicKey, toBase64(publicRaw));

  return toBase64(publicRaw);
}

async function ensureIdentity() {
  const pub = getPublicIdentity();
  const priv = sGet(GG84.storage.privateJwk);

  if (isValidPub(pub) &amp;&amp; priv) {
    return pub;
  }

  return generateIdentity();
}

async function initGG84() {
  if (!window.crypto?.subtle) {
    throw new Error(&quot;Web Crypto API non disponibile su questo dispositivo.&quot;);
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
    &quot;jwk&quot;,
    jwk,
    { name: &quot;ECDH&quot;, namedCurve: &quot;P-256&quot; },
    true,
    [&quot;deriveBits&quot;]
  );

  const publicKey = await crypto.subtle.importKey(
    &quot;raw&quot;,
    fromBase64(pubRaw),
    { name: &quot;ECDH&quot;, namedCurve: &quot;P-256&quot; },
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

function setActivePeer(pub, name = &quot;&quot;) {
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
  return !!active.pub &amp;&amp; active.pub === verified;
}

function setPendingPeer(pub, name = &quot;&quot;, device = &quot;&quot;) {
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
  return &quot;mobile&quot;;
}

function buildInvitePayload() {
  const pub = getPublicIdentity();
  if (!isValidPub(pub)) return null;

  return {
    type: GG84.linkPayload.type,
    flow: &quot;invite&quot;,
    v: GG84.inviteVersion,
    pub,
    name: getUserName() || &quot;Una persona&quot;,
    device: getDeviceLabel(),
    ts: Date.now()
  };
}

function buildConfirmationPayload() {
  const pub = getPublicIdentity();
  if (!isValidPub(pub)) return null;

  return {
    type: GG84.linkPayload.type,
    flow: &quot;confirm&quot;,
    v: GG84.inviteVersion,
    pub,
    name: getUserName() || &quot;Una persona&quot;,
    device: getDeviceLabel(),
    ts: Date.now()
  };
}

function serializeLinkPayload(payload) {
  try {
    return JSON.stringify(payload);
  } catch {
    return &quot;&quot;;
  }
}

function buildInviteLink() {
  const payload = buildInvitePayload();
  if (!payload) return &quot;&quot;;

  return `chiave.html?flow=receive&amp;v=${encodeURIComponent(payload.v)}&amp;pub=${encodeURIComponent(payload.pub)}&amp;name=${encodeURIComponent(payload.name)}&amp;device=${encodeURIComponent(payload.device)}`;
}

function buildConfirmationLink() {
  const payload = buildConfirmationPayload();
  if (!payload) return &quot;&quot;;

  return `chiave.html?flow=confirm&amp;v=${encodeURIComponent(payload.v)}&amp;pub=${encodeURIComponent(payload.pub)}&amp;name=${encodeURIComponent(payload.name)}&amp;device=${encodeURIComponent(payload.device)}`;
}

function parseLinkPayload(raw) {
  try {
    const parsed = typeof raw === &quot;string&quot; ? JSON.parse(raw) : raw;

    if (!parsed || parsed.type !== GG84.linkPayload.type) return null;
    if (parsed.flow !== &quot;invite&quot; &amp;&amp; parsed.flow !== &quot;confirm&quot;) return null;

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
      device: parsedFilePayload.meta?.device || &quot;&quot;,
      v: parsedFilePayload.v,
      type: parsedFilePayload.type,
      ts: parsedFilePayload.ts,
      source: &quot;gg84_file&quot;
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
      source: &quot;gg84_link&quot;
    };
  }

  try {
    const fakeUrl = normalized.startsWith(&quot;http&quot;)
      ? normalized
      : `https://local.test/${normalized.replace(/^\//, &quot;&quot;)}`;

    const url = new URL(fakeUrl);
    const pub = cleanString(url.searchParams.get(&quot;pub&quot;) || url.searchParams.get(&quot;key&quot;));
    const name = cleanString(url.searchParams.get(&quot;name&quot;));
    const flow = cleanString(url.searchParams.get(&quot;flow&quot;));
    const device = cleanString(url.searchParams.get(&quot;device&quot;));
    const v = cleanString(url.searchParams.get(&quot;v&quot;)) || GG84.inviteVersion;

    if (!isValidPub(pub)) return null;

    return { pub, name, flow, device, v, source: &quot;url&quot; };
  } catch {
    return null;
  }
}

function handleLinkPayload(raw) {
  const parsed = parseInviteData(raw);
  if (!parsed) return null;

  if (parsed.flow === &quot;invite&quot;) {
    setPendingPeer(parsed.pub, parsed.name, parsed.device);
    sSet(GG84.storage.flowState, &quot;pending&quot;);
    return {
      ok: true,
      mode: &quot;invite&quot;,
      peer: parsed
    };
  }

  if (parsed.flow === &quot;confirm&quot;) {
    const ok = setActivePeer(parsed.pub, parsed.name);
    if (!ok) return null;

    sDel(GG84.storage.flowState);
    clearPendingPeer();

    return {
      ok: true,
      mode: &quot;confirm&quot;,
      peer: parsed
    };
  }

  return null;
}

async function autoHandleScannedQr(raw) {
  const parsed = parseInviteData(raw);
  if (!parsed) return null;

  if (parsed.flow === &quot;confirm&quot;) {
    const ok = setActivePeer(parsed.pub, parsed.name);
    if (!ok) return null;

    clearPendingPeer();
    sDel(GG84.storage.pendingApprovalLink);
    sDel(GG84.storage.flowState);

    return {
      ok: true,
      mode: &quot;confirm&quot;,
      peer: parsed
    };
  }

  setPendingPeer(parsed.pub, parsed.name, parsed.device);
  sSet(GG84.storage.flowState, &quot;pending&quot;);

  const confirmPayload = buildConfirmationLink();
  sSet(GG84.storage.pendingApprovalLink, confirmPayload);

  return {
    ok: true,
    mode: &quot;invite&quot;,
    peer: parsed,
    approval: confirmPayload
  };
}

/* =========================
   FILE GG84 (.gg84)
========================= */

function getSafeFileBaseName(value, fallback = &quot;contatto_GG84&quot;) {
  const cleaned = cleanString(value)
    .replace(/[^\p{L}\p{N}_-]+/gu, &quot;_&quot;)
    .replace(/_+/g, &quot;_&quot;)
    .replace(/^_+|_+$/g, &quot;&quot;);

  return cleaned || fallback;
}

function buildInviteFilePayload() {
  const pub = getPublicIdentity();
  if (!isValidPub(pub)) return null;

  return {
    v: GG84.file.version,
    type: GG84.file.types.INVITE,
    flow: &quot;invite&quot;,
    name: getUserName() || &quot;Una persona&quot;,
    pub,
    ts: Date.now(),
    meta: {
      device: &quot;android&quot;,
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
    flow: &quot;confirm&quot;,
    name: getUserName() || &quot;Una persona&quot;,
    pub,
    ts: Date.now(),
    meta: {
      device: &quot;android&quot;,
      app: GG84.file.appName
    }
  };
}

function serializeGg84File(payload) {
  try {
    if (!payload || typeof payload !== &quot;object&quot;) return &quot;&quot;;
    return JSON.stringify(payload, null, 2);
  } catch (error) {
    console.error(&quot;Serialize GG84 file error:&quot;, error);
    return &quot;&quot;;
  }
}

function tryParseJsonObject(text) {
  const normalized = String(text || &quot;&quot;).replace(/^\uFEFF/, &quot;&quot;);
  const parsed = safeJsonParse(normalized, null);
  return parsed &amp;&amp; typeof parsed === &quot;object&quot; ? parsed : null;
}

function sanitizeBase64String(raw) {
  return cleanString(raw)
    .replace(/[\r\n\t ]+/g, &quot;&quot;)
    .replace(/[^A-Za-z0-9+/=]/g, &quot;&quot;);
}

function tryDecodeBase64ToUtf8(raw) {
  try {
    const normalized = sanitizeBase64String(raw);
    if (!normalized || normalized.length &lt; 16) return &quot;&quot;;
    return base64ToUtf8(normalized);
  } catch {
    return &quot;&quot;;
  }
}

function parseGg84File(text) {
  try {
    const raw = String(text || &quot;&quot;);
    const candidates = [];

    if (raw) candidates.push(raw);

    const trimmed = cleanString(raw);
    if (trimmed &amp;&amp; trimmed !== raw) {
      candidates.push(trimmed);
    }

    const decodedRaw = tryDecodeBase64ToUtf8(raw);
    if (decodedRaw) {
      candidates.push(decodedRaw);
    }

    const decodedTrimmed = tryDecodeBase64ToUtf8(trimmed);
    if (decodedTrimmed &amp;&amp; !candidates.includes(decodedTrimmed)) {
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
      type !== GG84.file.types.INVITE &amp;&amp;
      type !== GG84.file.types.CONFIRM
    ) {
      return null;
    }

    if (flow !== &quot;invite&quot; &amp;&amp; flow !== &quot;confirm&quot;) {
      return null;
    }

    if (!isValidPub(pub)) {
      return null;
    }

    const meta = parsed.meta &amp;&amp; typeof parsed.meta === &quot;object&quot; ? parsed.meta : {};

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
    console.error(&quot;Parse GG84 file error:&quot;, error);
    return null;
  }
}

function buildInviteFileName() {
  const name = getSafeFileBaseName(getUserName(), &quot;contatto_GG84&quot;);
  return `invito_${name}${GG84.file.extension}`;
}

function buildConfirmFileName() {
  const name = getSafeFileBaseName(getUserName(), &quot;contatto_GG84&quot;);
  return `risposta_${name}${GG84.file.extension}`;
}

async function exportGg84File(payload, filename) {
  try {
    const json = serializeGg84File(payload);
    if (!json) {
      throw new Error(&quot;Payload file vuoto.&quot;);
    }

    const safeName = cleanString(filename) || `contatto${GG84.file.extension}`;

    if (window.Capacitor?.Plugins?.Filesystem &amp;&amp; window.Capacitor?.Plugins?.Share) {
      const Filesystem = window.Capacitor.Plugins.Filesystem;
      const Share = window.Capacitor.Plugins.Share;

      const data = utf8ToBase64(json);
      const result = await Filesystem.writeFile({
        path: safeName,
        data,
        directory: &quot;CACHE&quot;
      });

      await Share.share({
        title: &quot;Contatto GG84&quot;,
        files: [result.uri],
        dialogTitle: &quot;Condividi con GG84&quot;
      });

      return {
        ok: true,
        uri: result.uri,
        path: safeName
      };
    }

    if (navigator.share &amp;&amp; typeof File !== &quot;undefined&quot;) {
      const file = new File([json], safeName, { type: GG84.file.mimeType });

      await navigator.share({
        title: &quot;Contatto GG84&quot;,
        files: [file]
      });

      return {
        ok: true,
        path: safeName
      };
    }

    throw new Error(&quot;Condivisione file non disponibile.&quot;);
  } catch (error) {
    console.error(&quot;Export GG84 file error:&quot;, error);
    return {
      ok: false,
      error
    };
  }
}

async function exportInviteGg84File() {
  const payload = buildInviteFilePayload();
  if (!payload) {
    return { ok: false, error: new Error(&quot;Payload invito non disponibile.&quot;) };
  }

  return exportGg84File(payload, buildInviteFileName());
}

async function exportConfirmGg84File() {
  const payload = buildConfirmFilePayload();
  if (!payload) {
    return { ok: false, error: new Error(&quot;Payload conferma non disponibile.&quot;) };
  }

  return exportGg84File(payload, buildConfirmFileName());
}

function handleGg84FileContent(fileText) {
  const parsed = parseGg84File(fileText);
  if (!parsed) return null;

  if (parsed.flow === &quot;invite&quot;) {
    setPendingPeer(parsed.pub, parsed.name, parsed.meta.device);
    sSet(GG84.storage.flowState, &quot;pending&quot;);
    sSet(GG84.storage.pendingInviteFile, serializeGg84File(parsed));

    return {
      ok: true,
      flow: &quot;invite&quot;,
      data: parsed,
      name: parsed.name || &quot;&quot;
    };
  }

  if (parsed.flow === &quot;confirm&quot;) {
    const ok = setActivePeer(parsed.pub, parsed.name);
    if (!ok) return null;

    clearPendingPeer();
    sDel(GG84.storage.pendingApprovalLink);
    sDel(GG84.storage.flowState);
    sSet(GG84.storage.pendingConfirmFile, serializeGg84File(parsed));

    return {
      ok: true,
      flow: &quot;confirm&quot;,
      data: parsed,
      name: parsed.name || &quot;&quot;
    };
  }

  return null;
}

async function tryReadIncomingUrl(url) {
  try {
    const normalized = cleanString(url);
    if (!normalized) return null;

    if (normalized.startsWith(&quot;data:&quot;)) {
      const commaIndex = normalized.indexOf(&quot;,&quot;);
      if (commaIndex &gt; -1) {
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
    console.error(&quot;Read incoming URL error:&quot;, error);
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
    const storedB64 = cleanString(localStorage.getItem(&quot;gg84_native_incoming_file_b64&quot;) || &quot;&quot;);
    if (!storedB64) return null;

    const content = base64ToUtf8(storedB64);

    localStorage.removeItem(&quot;gg84_native_incoming_file_b64&quot;);
    localStorage.removeItem(&quot;gg84_native_incoming_file_uri_b64&quot;);

    return handleGg84FileContent(content);
  } catch (error) {
    console.error(&quot;Consume native stored GG84 file error:&quot;, error);
    return null;
  }
}

/* =========================
   FINGERPRINT
========================= */

async function buildConnectionFingerprint(peerPub) {
  const myPub = getPublicIdentity();
  const normalizedPeer = cleanString(peerPub);

  if (!isValidPub(myPub) || !isValidPub(normalizedPeer)) {
    throw new Error(&quot;Impossibile creare fingerprint.&quot;);
  }

  const ordered = [myPub, normalizedPeer].sort().join(&quot;|&quot;);
  const hash = await sha256Text(ordered);
  return bytesToHex(hash);
}

function buildVisualFingerprintFromFingerprint(fingerprintHex) {
  const normalized = cleanString(fingerprintHex).replace(/[^a-f0-9]/gi, &quot;&quot;).toLowerCase();
  if (normalized.length &lt; 16) {
    throw new Error(&quot;Fingerprint non valida.&quot;);
  }

  const code = `${normalized.slice(0, 4).toUpperCase()}-${normalized.slice(4, 8).toUpperCase()}`;
  const hue = parseInt(normalized.slice(8, 12), 16) % 360;
  return {
    shortCode: code,
    accentSoftHex: `hsl(${hue} 76% 84%)`,
    accentDarkHex: `hsl(${hue} 68% 30%)`,
    ringRgba: `hsla(${hue}, 72%, 44%, 0.28)`,
    glowRgba: `hsla(${hue}, 88%, 55%, 0.20)`,
    logoPrimary: GG84.visualFingerprint.logoPrimary,
    logoFallback: GG84.visualFingerprint.logoFallback,
    fingerprintHex: normalized
  };
}

async function buildConnectionVisualFingerprint(peerPub) {
  const fingerprint = await buildConnectionFingerprint(peerPub);
  return buildVisualFingerprintFromFingerprint(fingerprint);
}

async function verifyConnectionVisualCode(peerPub, candidateCode) {
  const vf = await buildConnectionVisualFingerprint(peerPub);
  return cleanString(candidateCode).toUpperCase() === vf.shortCode.toUpperCase();
}

/* =========================
   KDF ECDH -&gt; AES
========================= */

async function deriveSharedSecretBytes(peerPublicKeyBase64) {
  const pair = await getKeyPair();
  if (!pair) throw new Error(&quot;Identità locale non disponibile.&quot;);

  const peerKey = await crypto.subtle.importKey(
    &quot;raw&quot;,
    fromBase64(peerPublicKeyBase64),
    { name: &quot;ECDH&quot;, namedCurve: &quot;P-256&quot; },
    true,
    []
  );

  const rawSecret = await crypto.subtle.deriveBits(
    { name: &quot;ECDH&quot;, public: peerKey },
    pair.privateKey,
    256
  );

  return new Uint8Array(rawSecret);
}

async function deriveHkdfAesKey(rawSecretBytes, saltBytes, infoBytes) {
  const hkdfKey = await crypto.subtle.importKey(
    &quot;raw&quot;,
    rawSecretBytes,
    &quot;HKDF&quot;,
    false,
    [&quot;deriveKey&quot;]
  );

  return crypto.subtle.deriveKey(
    {
      name: &quot;HKDF&quot;,
      hash: &quot;SHA-256&quot;,
      salt: saltBytes,
      info: infoBytes
    },
    hkdfKey,
    {
      name: &quot;AES-GCM&quot;,
      length: 256
    },
    false,
    [&quot;encrypt&quot;, &quot;decrypt&quot;]
  );
}

async function deriveMessageKey(peerPub, saltBytes, counter) {
  const sharedSecret = await deriveSharedSecretBytes(cleanString(peerPub));
  const info = GG84.encoder.encode(`GG84|ECDH|AESGCM|MSG|${counter}`);
  return deriveHkdfAesKey(sharedSecret, saltBytes, info);
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
  const path = window.location.pathname || &quot;&quot;;
  return (
    path.endsWith(&quot;/index.html&quot;) ||
    path.endsWith(&quot;index.html&quot;) ||
    path === &quot;/&quot; ||
    path === &quot;&quot;
  );
}

function gg84GoBackOrHome() {
  if (window.history.length &gt; 1) {
    window.history.back();
    return;
  }

  window.location.href = &quot;index.html&quot;;
}

function setupAndroidBackNavigation() {
  if (gg84BackListenerReady) return;
  gg84BackListenerReady = true;

  try {
    const appPlugin =
      window.Capacitor &amp;&amp;
      window.Capacitor.Plugins &amp;&amp;
      window.Capacitor.Plugins.App;

    if (!appPlugin || typeof appPlugin.addListener !== &quot;function&quot;) return;

    appPlugin.addListener(&quot;backButton&quot;, () =&gt; {
      if (!gg84IsHomePage()) {
        gg84GoBackOrHome();
        return;
      }

      const now = Date.now();
      const exitDelay = 1500;

      if (now - gg84LastBackPress &lt; exitDelay) {
        if (typeof appPlugin.exitApp === &quot;function&quot;) {
          appPlugin.exitApp();
        }
        return;
      }

      gg84LastBackPress = now;
      console.log(&quot;Premi di nuovo indietro per uscire&quot;);
    });
  } catch (error) {
    console.error(&quot;Android back init error:&quot;, error);
  }
}

function setupEdgeSwipeBackNavigation() {
  if (gg84EdgeSwipeReady) return;
  gg84EdgeSwipeReady = true;

  const edgeSize = 28;
  const minSwipeX = 70;
  const maxSwipeY = 60;

  window.addEventListener(
    &quot;touchstart&quot;,
    event =&gt; {
      if (!event.touches || event.touches.length !== 1) {
        gg84TouchTracking = false;
        return;
      }

      const touch = event.touches[0];
      gg84TouchStartX = touch.clientX;
      gg84TouchStartY = touch.clientY;
      gg84TouchTracking = gg84TouchStartX &lt;= edgeSize;
    },
    { passive: true }
  );

  window.addEventListener(
    &quot;touchend&quot;,
    event =&gt; {
      if (!gg84TouchTracking || !event.changedTouches || event.changedTouches.length !== 1) {
        gg84TouchTracking = false;
        return;
      }

      const touch = event.changedTouches[0];
      const deltaX = touch.clientX - gg84TouchStartX;
      const deltaY = Math.abs(touch.clientY - gg84TouchStartY);

      gg84TouchTracking = false;

      if (deltaX &lt; minSwipeX) return;
      if (deltaY &gt; maxSwipeY) return;

      if (!gg84IsHomePage()) {
        gg84GoBackOrHome();
        return;
      }

      const appPlugin =
        window.Capacitor &amp;&amp;
        window.Capacitor.Plugins &amp;&amp;
        window.Capacitor.Plugins.App;

      const now = Date.now();
      const exitDelay = 1500;

      if (now - gg84LastBackPress &lt; exitDelay) {
        if (appPlugin &amp;&amp; typeof appPlugin.exitApp === &quot;function&quot;) {
          appPlugin.exitApp();
        }
        return;
      }

      gg84LastBackPress = now;
      console.log(&quot;Swipe di nuovo per uscire&quot;);
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
let gg84PinInputValue = &quot;&quot;;

function isAppLockEnabled() {
  return sGet(GG84.storage.appLockEnabled) === &quot;1&quot;;
}

function hasStoredAppPin() {
  return !!cleanString(sGet(GG84.storage.appPinHash)) &amp;&amp; !!cleanString(sGet(GG84.storage.appPinSalt));
}

function getSessionUnlockUntil() {
  try {
    return Number(sessionStorage.getItem(GG84.storage.appLockSessionUntil) || &quot;0&quot;);
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
  return getSessionUnlockUntil() &gt; Date.now();
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
    return Number(sessionStorage.getItem(GG84.storage.appLockBackgroundAt) || &quot;0&quot;);
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
    throw new Error(&quot;PIN non valido.&quot;);
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
  return isAppLockEnabled() &amp;&amp; hasStoredAppPin() &amp;&amp; hasValidIdentityState();
}

function ensureAppLockOverlay() {
  if (gg84AppLockOverlay) return gg84AppLockOverlay;

  const style = document.createElement(&quot;style&quot;);
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

  const overlay = document.createElement(&quot;div&quot;);
  overlay.className = &quot;gg84-lock-overlay&quot;;
  overlay.innerHTML = `
    &lt;div class=&quot;gg84-lock-card&quot; role=&quot;dialog&quot; aria-modal=&quot;true&quot; aria-labelledby=&quot;gg84-lock-title&quot;&gt;
      &lt;div class=&quot;gg84-lock-logo-wrap&quot;&gt;
        &lt;img src=&quot;logo3.png&quot; alt=&quot;GG84&quot; class=&quot;gg84-lock-logo&quot;&gt;
      &lt;/div&gt;
      &lt;h2 id=&quot;gg84-lock-title&quot; class=&quot;gg84-lock-title&quot;&gt;GG84 bloccato&lt;/h2&gt;
      &lt;input
        id=&quot;gg84-lock-pin-input&quot;
        class=&quot;gg84-lock-input&quot;
        type=&quot;password&quot;
        inputmode=&quot;numeric&quot;
        maxlength=&quot;6&quot;
        placeholder=&quot;••••••&quot;
        autocomplete=&quot;off&quot;
      &gt;
      &lt;div id=&quot;gg84-lock-status&quot; class=&quot;gg84-lock-status&quot;&gt;In attesa di sblocco…&lt;/div&gt;
    &lt;/div&gt;
  `;
  document.body.appendChild(overlay);

  const input = overlay.querySelector(&quot;#gg84-lock-pin-input&quot;);

  input.addEventListener(&quot;input&quot;, () =&gt; {
    gg84PinInputValue = String(input.value || &quot;&quot;).replace(/\D/g, &quot;&quot;).slice(0, 6);
    input.value = gg84PinInputValue;

    if (gg84PinInputValue.length === 6 &amp;&amp; !gg84UnlockInProgress) {
      unlockAppNow();
    }
  });

  input.addEventListener(&quot;keydown&quot;, event =&gt; {
    if (event.key === &quot;Enter&quot;) {
      event.preventDefault();
      unlockAppNow();
    }
  });

  gg84AppLockOverlay = overlay;
  return overlay;
}

function getAppLockOverlayInput() {
  const overlay = ensureAppLockOverlay();
  return overlay.querySelector(&quot;#gg84-lock-pin-input&quot;);
}

function setAppLockOverlayStatus(message, isError = false) {
  const overlay = ensureAppLockOverlay();
  const status = overlay.querySelector(&quot;#gg84-lock-status&quot;);
  status.textContent = message;

  if (isError) {
    status.style.background = &quot;#fff1f1&quot;;
    status.style.borderColor = &quot;rgba(176,0,32,.22)&quot;;
    status.style.color = &quot;#8a1834&quot;;
  } else {
    status.style.background = &quot;#eefaf0&quot;;
    status.style.borderColor = &quot;rgba(27,152,63,.22)&quot;;
    status.style.color = &quot;#1f6b3b&quot;;
  }
}

function resetAppLockOverlayInput() {
  gg84PinInputValue = &quot;&quot;;
  const input = getAppLockOverlayInput();
  input.value = &quot;&quot;;
}

function focusAppLockInput() {
  const input = getAppLockOverlayInput();
  setTimeout(() =&gt; {
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

  gg84AppLockTimer = setTimeout(() =&gt; {
    clearSessionUnlockUntil();
    lockAppNow(&quot;inattività&quot;);
  }, GG84.appLock.timeoutMs);
}

function registerActivityPulse() {
  if (!shouldEnforceAppLock() || gg84AppLocked) return;
  refreshUnlockedSessionWindow();
  scheduleAppRelock();
}

async function playUnlockFade() {
  const overlay = ensureAppLockOverlay();
  overlay.classList.add(&quot;unlocking&quot;);

  if (navigator.vibrate) {
    try {
      navigator.vibrate(30);
    } catch {}
  }

  await new Promise(resolve =&gt; setTimeout(resolve, 180));

  overlay.classList.remove(&quot;show&quot;);
  overlay.classList.remove(&quot;unlocking&quot;);
}

async function lockAppNow(reason = &quot;manuale&quot;) {
  if (!shouldEnforceAppLock()) return;

  ensureAppLockOverlay().classList.add(&quot;show&quot;);
  gg84AppLocked = true;
  clearAppLockTimer();
  resetAppLockOverlayInput();

  const message =
    reason === &quot;inattività&quot;
      ? &quot;App bloccata per inattività.&quot;
      : reason === &quot;background&quot;
        ? &quot;App bloccata al rientro.&quot;
        : &quot;Inserisci il PIN per continuare.&quot;;

  setAppLockOverlayStatus(message, false);
  focusAppLockInput();
}

async function unlockAppNow() {
  if (!shouldEnforceAppLock()) {
    if (gg84AppLockOverlay) {
      gg84AppLockOverlay.classList.remove(&quot;show&quot;);
      gg84AppLockOverlay.classList.remove(&quot;unlocking&quot;);
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
    setAppLockOverlayStatus(&quot;Inserisci un PIN valido di 6 cifre.&quot;, true);
    focusAppLockInput();
    return false;
  }

  gg84UnlockInProgress = true;
  setAppLockOverlayStatus(&quot;Verifica PIN in corso…&quot;, false);

  try {
    const ok = await verifyAppPin(pin);

    if (!ok) {
      setAppLockOverlayStatus(&quot;PIN non corretto.&quot;, true);
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
    setAppLockOverlayStatus(&quot;Errore durante la verifica del PIN.&quot;, true);
    gg84AppLocked = true;
    return false;
  } finally {
    gg84UnlockInProgress = false;
  }
}

function installAppSecurityActivityHooks() {
  const pulse = () =&gt; registerActivityPulse();
  [&quot;click&quot;, &quot;touchstart&quot;, &quot;keydown&quot;, &quot;mousemove&quot;].forEach(eventName =&gt; {
    window.addEventListener(eventName, pulse, { passive: true });
  });
}

function installAppSecurityStateHooks() {
  try {
    const appPlugin =
      window.Capacitor &amp;&amp;
      window.Capacitor.Plugins &amp;&amp;
      window.Capacitor.Plugins.App;

    if (!appPlugin || typeof appPlugin.addListener !== &quot;function&quot;) return;

    appPlugin.addListener(&quot;appStateChange&quot;, ({ isActive }) =&gt; {
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
          lockAppNow(&quot;background&quot;);
          return;
        }

        const elapsed = Date.now() - backgroundAt;

        if (elapsed &gt;= GG84.appLock.timeoutMs) {
          clearSessionUnlockUntil();
          lockAppNow(&quot;background&quot;);
          return;
        }

        refreshUnlockedSessionWindow();
        registerActivityPulse();
        return;
      }

      registerActivityPulse();
    });
  } catch (error) {
    console.error(&quot;App security state hook error:&quot;, error);
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

  await lockAppNow(&quot;manuale&quot;);
}

/* =========================
   MESSAGGI PROTETTI
========================= */

function isEncryptedPayload(text) {
  return typeof text === &quot;string&quot; &amp;&amp; text.startsWith(&quot;GG84$3$&quot;);
}

async function encryptMessage(plainText, peerPub) {
  const normalizedText = String(plainText ?? &quot;&quot;);
  const normalizedPeer = cleanString(peerPub);

  if (!normalizedText) throw new Error(&quot;Testo vuoto.&quot;);
  if (!isValidPub(normalizedPeer)) throw new Error(&quot;Peer non valido.&quot;);

  const counterBytes = crypto.getRandomValues(new Uint8Array(4));
  let counter = (
    (counterBytes[0] &lt;&lt; 24) |
    (counterBytes[1] &lt;&lt; 16) |
    (counterBytes[2] &lt;&lt; 8) |
    counterBytes[3]
  ) &gt;&gt;&gt; 0;
  if (counter === 0) counter = 1;

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = GG84.encoder.encode(normalizedText);
  const key = await deriveMessageKey(normalizedPeer, salt, counter);

  const encrypted = await crypto.subtle.encrypt(
    { name: &quot;AES-GCM&quot;, iv },
    key,
    data
  );

  return [
    &quot;GG84&quot;,
    GG84.messageVersion,
    String(counter),
    toBase64(salt),
    toBase64(iv),
    toBase64(encrypted)
  ].join(&quot;$&quot;);
}

async function decryptMessage(payload, peerPub) {
  try {
    const normalizedPayload = String(payload || &quot;&quot;);
    const normalizedPeer = cleanString(peerPub);

    if (!normalizedPayload.startsWith(&quot;GG84$3$&quot;)) {
      throw new Error(&quot;Formato non valido.&quot;);
    }
    if (!isValidPub(normalizedPeer)) {
      throw new Error(&quot;Peer non valido.&quot;);
    }

    const parts = normalizedPayload.split(&quot;$&quot;);
    if (parts.length !== 6) {
      throw new Error(&quot;Payload corrotto.&quot;);
    }

    const counter = parsePositiveCounter(parts[2]);
    const salt = fromBase64(parts[3]);
    const iv = fromBase64(parts[4]);
    const cipher = fromBase64(parts[5]);

    if (!counter) throw new Error(&quot;Counter non valido.&quot;);
    if (salt.length &lt; 16) throw new Error(&quot;Salt non valido.&quot;);
    if (iv.length !== 12) throw new Error(&quot;IV non valido.&quot;);
    if (!cipher.length) throw new Error(&quot;Ciphertext non valido.&quot;);

    const key = await deriveMessageKey(normalizedPeer, salt, counter);

    const decrypted = await crypto.subtle.decrypt(
      { name: &quot;AES-GCM&quot;, iv },
      key,
      cipher
    );

    return GG84.decoder.decode(decrypted);
  } catch {
    throw new Error(&quot;Errore decifratura.&quot;);
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
  if (trimmed.startsWith(&quot;GG84:&quot;)) return cleanString(trimmed.slice(5));
  return &quot;&quot;;
}

function extractInviteData(value) {
  const parsed = parseInviteData(value);

  if (!parsed) {
    return {
      key: &quot;&quot;,
      pub: &quot;&quot;,
      name: &quot;&quot;,
      flow: &quot;&quot;,
      nonce: &quot;&quot;,
      device: &quot;&quot;,
      v: &quot;&quot;
    };
  }

  return {
    key: parsed.pub,
    pub: parsed.pub,
    name: parsed.name,
    flow: parsed.flow,
    nonce: &quot;&quot;,
    device: parsed.device,
    v: parsed.v
  };
}

function deriveSharedPasswordFromKeys() {
  throw new Error(&quot;Motore legacy disattivato in modalità pulita.&quot;);
}

function deriveSharedPasswordFromPrivateAndInvite() {
  throw new Error(&quot;Motore legacy disattivato in modalità pulita.&quot;);
}

/* =========================
   CAPACITOR INCOMING HOOK
========================= */

function setupIncomingFileListener() {
  try {
    const appPlugin =
      window.Capacitor &amp;&amp;
      window.Capacitor.Plugins &amp;&amp;
      window.Capacitor.Plugins.App;

    if (!appPlugin || typeof appPlugin.addListener !== &quot;function&quot;) return;

    appPlugin.addListener(&quot;appUrlOpen&quot;, async data =&gt; {
      const url = cleanString(data &amp;&amp; data.url);
      if (!url) return;

      sSet(GG84.storage.incomingPayload, url);

      if (/\.gg84($|\?)/i.test(url)) {
        await handleIncomingFile(url);
      }
    });
  } catch (error) {
    console.error(&quot;Incoming file listener error:&quot;, error);
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

window.deriveSharedSecretBytes = deriveSharedSecretBytes;
window.deriveMessageKey = deriveMessageKey;

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
(async () =&gt; {
  try {
    await initGG84();
  } catch (error) {
    console.error(&quot;GG84 init error:&quot;, error);
  }

  try {
    setupAndroidBackNavigation();
    setupEdgeSwipeBackNavigation();
    setupIncomingFileListener();
    await setupAppSecurityLayer();
  } catch (error) {
    console.error(&quot;GG84 app security error:&quot;, error);
  }
})();</pre></main>
</body>
</html>