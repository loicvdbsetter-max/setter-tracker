// Cloudflare Worker — sert le site statique + une route API pour l'accès partagé par entrepreneur.
//
// Secrets attendus (Cloudflare dashboard > Settings > Variables and Secrets) :
//   FIREBASE_CLIENT_EMAIL — le "client_email" du fichier JSON de compte de service Firebase
//   FIREBASE_PRIVATE_KEY  — le "private_key" du même fichier (collé tel quel, avec les retours à la ligne)
//   FIREBASE_DB_URL       — l'URL de la Realtime Database, ex: https://setter-tracker-8ef58-default-rtdb.europe-west1.firebasedatabase.app

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/api/share-token' && request.method === 'POST') {
      return handleShareToken(request, env);
    }

    return env.ASSETS.fetch(request);
  }
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json' }
  });
}

async function handleShareToken(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid request' }, 400);
  }

  const secret = (body && body.secret || '').trim();
  if (!secret) return json({ error: 'missing secret' }, 400);

  const entKey = await lookupEntKey(secret, env);
  if (!entKey) return json({ error: 'invalid link' }, 403);

  try {
    const token = await mintCustomToken(entKey, env);
    return json({ token, entKey });
  } catch (e) {
    return json({ error: 'token mint failed' }, 500);
  }
}

async function lookupEntKey(secret, env) {
  const url = `${env.FIREBASE_DB_URL}/shareLinks/${encodeURIComponent(secret)}/entKey.json`;
  const res = await fetch(url);
  if (!res.ok) return null;
  const entKey = await res.json();
  return typeof entKey === 'string' && entKey ? entKey : null;
}

async function mintCustomToken(entKey, env) {
  const header = { alg: 'RS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: env.FIREBASE_CLIENT_EMAIL,
    sub: env.FIREBASE_CLIENT_EMAIL,
    aud: 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit',
    iat: now,
    exp: now + 3600,
    uid: 'share_' + entKey,
    claims: { entKey }
  };

  const headerB64 = base64urlStr(JSON.stringify(header));
  const payloadB64 = base64urlStr(JSON.stringify(payload));
  const unsigned = `${headerB64}.${payloadB64}`;

  const key = await importPrivateKey(env.FIREBASE_PRIVATE_KEY);
  const signature = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    key,
    new TextEncoder().encode(unsigned)
  );

  return `${unsigned}.${base64urlBuf(signature)}`;
}

async function importPrivateKey(pem) {
  const body = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\\n/g, '\n')
    .replace(/\s+/g, '');
  const der = Uint8Array.from(atob(body), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    'pkcs8',
    der.buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

function base64urlStr(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64urlBuf(buf) {
  let bin = '';
  new Uint8Array(buf).forEach(b => bin += String.fromCharCode(b));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
