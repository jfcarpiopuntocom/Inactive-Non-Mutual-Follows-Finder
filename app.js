// Constants for clarity
const X_API_BASE = 'https://api.twitter.com/2';
const API_KEY = 'QlK4UFjcTMT9vHFtUZho90YIp'; // Legacy X API Key (optional)
const OAUTH2_CLIENT_ID = 'TFNFMUNETm1yR1JtX0trOWJQQ3A6MTpjaQ'; // X OAuth 2.0 Client ID
const REDIRECT_URI = 'https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/callback';
const BEARER_TOKEN = 'AAAAAAAAAAAAAAAAAAAAAMmPvQEAAAAAnMFJgOjandSI9vBjNRfn7C2Y2BU%3Dnyll1sjKYj8PAufR8xOAJ6qEPID621WkwoXaqEKHOVODW5zmbj'; // X API v2 Bearer Token
const MAX_RETRIES = 5; // Max retry attempts per operation
const RETRY_DELAY = 5000; // 5s delay for retries
const MAX_ATTEMPTS = 3; // Max total retry attempts

let retryCount = 0; // Track total retries
const APP_VERSION = '1.16'; // App version for tracking

// Main function for @jfcarpio
async function findInactiveNonMutuals() {
  const start = document.getElementById('startButton');
  const retry = document.getElementById('retryButton');
  const progress = document.getElementById('progress');
  const results = document.getElementById('results');
  const error = document.getElementById('error');
  const loading = document.getElementById('loading');
  const instructions = document.getElementById('instructions');
  const callbackInput = document.getElementById('callbackUrl');
  const submitCallback = document.getElementById('submitCallback');
  const version = document.getElementById('version');

  if (!start || !progress || !results || !error || !loading || !instructions || !callbackInput || !submitCallback || !version) {
    const msg = `DOM Error (v${APP_VERSION}): Missing elements for @jfcarpio. Check index.html, clear cache, and redeploy.`;
    if (error) error.innerHTML = `<pre>${msg}</pre>`;
    console.error(msg);
    if (start) start.disabled = false;
    if (version) version.innerText = `Version: ${APP_VERSION} (Failed - DOM)`;
    return;
  }

  if (version) version.innerText = `Version: ${APP_VERSION} (Loading)`;
  start.disabled = true; retry.style.display = 'none';
  start.innerText = 'Authenticating with X...';
  progress.innerHTML = ''; results.innerHTML = ''; error.innerHTML = '';
  loading.style.display = 'block'; instructions.style.display = 'block';

  try {
    // Try Bearer Token first
    let token = await validateBearerToken(BEARER_TOKEN);
    if (token) {
      progress.innerHTML = `Authenticated as: @jfcarpio (Bearer, v${APP_VERSION})`;
      if (version) version.innerText = `Version: ${APP_VERSION} (Success - Bearer)`;
    } else {
      // Fall back to OAuth 2.0 PKCE if Bearer fails
      const clientValid = await validateClientId(OAUTH2_CLIENT_ID, REDIRECT_URI);
      if (!clientValid) {
        const apiValid = await validateApiKey(API_KEY);
        if (!apiValid) {
          throw new Error(`Invalid Credentials (v${APP_VERSION}): OAuth 2.0 Client ID '${OAUTH2_CLIENT_ID}' and API Key '${API_KEY}' for @jfcarpio are invalid. Verify in X Developer Portal (https://developer.twitter.com/), ensure 'Web App, Automated App or Bot' type, redirect URI '${REDIRECT_URI}', and scopes 'tweet.read', 'users.read', 'follows.read'. Update OAUTH2_CLIENT_ID and API_KEY in app.js, clear cache, and retry.`);
        }
        token = await useApiKey(API_KEY);
        progress.innerHTML = `Authenticated as: @jfcarpio (API Key, v${APP_VERSION})`;
        if (version) version.innerText = `Version: ${APP_VERSION} (Success - API Key)`;
      } else {
        const code = await authFlow();
        token = await exchangeToken(code);
        progress.innerHTML = `Authenticated as: @jfcarpio (OAuth, v${APP_VERSION})`;
        if (version) version.innerText = `Version: ${APP_VERSION} (Success - OAuth)`;
      }
    }

    // Verify user and fetch data
    const userId = await getUserId(token);
    const user = await fetchUserDetails(userId, token);
    if (user.username !== 'jfcarpio') throw new Error(`User Mismatch (v${APP_VERSION}): Authenticated user '${user.username}' isn’t @jfcarpio. Verify credentials in X Developer Portal, update BEARER_TOKEN or OAUTH2_CLIENT_ID, clear cache, and retry.`);

    const follows = await getFollows(userId, token);
    const followers = await getFollowers(userId, token);
    const nonMutuals = follows.filter(f => !followers.some(fol => fol.id === f.id));
    const inactive = await checkInactivity(nonMutuals, token);

    displayResults(inactive, userId);
    if (version) version.innerText = `Version: ${APP_VERSION} (Success)`;
  } catch (error) {
    console.error(`Runtime Error (v${APP_VERSION}):`, error);
    const msg = `Critical Error (v${APP_VERSION}): ${error.message}. Check console for stack trace. Fix by verifying Bearer Token '${BEARER_TOKEN.substring(0, 20)}...', OAuth 2.0 Client ID '${OAUTH2_CLIENT_ID}', API Key '${API_KEY}', and X app settings (https://developer.twitter.com/). Ensure redirect URI '${REDIRECT_URI}', 'Web App' type, and scopes 'tweet.read', 'users.read', 'follows.read'. Update credentials in app.js, clear cache (Ctrl+F5), retry, or redeploy to GitHub Pages.`;
    if (error) error.innerHTML = `<pre>${msg}</pre>`;
    retry.style.display = 'block';
    if (version) version.innerText = `Version: ${APP_VERSION} (Failed)`;

    if (retryCount < MAX_ATTEMPTS && error.message.includes('Invalid') || error.message.includes('HTTP')) {
      retryCount++;
      setTimeout(findInactiveNonMutuals, RETRY_DELAY * Math.pow(2, retryCount - 1));
      if (version) version.innerText = `Version: ${APP_VERSION} (Retrying ${retryCount}/${MAX_ATTEMPTS})`;
    } else {
      console.error(`Max retries reached (v${APP_VERSION}). Follow steps above.`);
      if (version) version.innerText = `Version: ${APP_VERSION} (Failed - Max Retries)`;
    }
  } finally {
    start.disabled = false; start.innerText = 'Authenticate with X and Find Inactive Non-Mutuals';
    loading.style.display = 'none'; instructions.style.display = 'none';
    if (version) version.innerText = `Version: ${APP_VERSION} (Idle)`;
  }
}

// Helper functions
async function validateBearerToken(token) {
  try {
    const res = await fetch(`${X_API_BASE}/users/me?user.fields=username`, { headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) throw new Error(`Bearer Invalid (v${APP_VERSION}): HTTP ${res.status}. Verify '${token.substring(0, 20)}...' in X Developer Portal, update BEARER_TOKEN, clear cache, retry.`);
    return token;
  } catch (e) { return null; }
}

async function validateClientId(clientId, redirectUri) {
  try {
    const res = await fetch(`${X_API_BASE}/oauth2/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `grant_type=client_credentials&client_id=${clientId}` });
    if (!res.ok) throw new Error(`Client ID Invalid (v${APP_VERSION}): '${clientId}'. Verify in X Developer Portal, ensure '${redirectUri}' matches, update OAUTH2_CLIENT_ID, clear cache, retry.`);
    return true;
  } catch (e) { return false; }
}

async function validateApiKey(apiKey) {
  try {
    const res = await fetch(`${X_API_BASE}/oauth2/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `grant_type=client_credentials&client_id=${apiKey}` });
    if (!res.ok) throw new Error(`API Key Invalid (v${APP_VERSION}): '${apiKey}'. Verify or remove in X Developer Portal, clear cache, retry.`);
    return true;
  } catch (e) { return false; }
}

async function useApiKey(apiKey) {
  const res = await fetch(`${X_API_BASE}/oauth2/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `grant_type=client_credentials&client_id=${apiKey}` });
  if (!res.ok) throw new Error(`API Key Token Error (v${APP_VERSION}): HTTP ${res.status}. Verify '${apiKey}', clear cache, retry.`);
  return (await res.json()).access_token;
}

async function authFlow() {
  for (let i = 1; i <= MAX_RETRIES; i++) {
    try {
      const state = crypto.getRandomValues(new Uint8Array(16)).join('');
      const verifier = btoa(crypto.getRandomValues(new Uint8Array(32)).join('')).slice(0, 43);
      sessionStorage.setItem('codeVerifier', verifier);
      const challenge = await sha256(verifier).then(hash => btoa(String.fromCharCode(...new Uint8Array(hash))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));

      const url = `${X_API_BASE}/oauth2/authorize?response_type=code&client_id=${OAUTH2_CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=tweet.read%20users.read%20follows.read&state=${state}&code_challenge=${challenge}&code_challenge_method=S256&prompt=login`;
      let win = window.open(url, '_blank', 'width=600,height=600');
      if (!win) throw new Error(`Popup Blocked (v${APP_VERSION}): Allow popups for '${url}', authorize @jfcarpio, paste callback URL, retry.`);

      return await pollCallback(win, REDIRECT_URI, state, i);
    } catch (e) {
      if (i === MAX_RETRIES) throw new Error(`Auth Failed (v${APP_VERSION}): ${e.message}. Verify credentials, clear cache, retry.`);
      await new Promise(r => setTimeout(r, RETRY_DELAY * Math.pow(2, i - 1)));
    }
  }
}

async function pollCallback(win, redirectUri, state, attempt) {
  return new Promise((resolve, reject) => {
    let interval = setInterval(() => {
      if (win.closed) reject(new Error(`Window Closed (v${APP_VERSION}): Keep popup open, retry at ${redirectUri}.`));
      try { if (win.location.href.includes(redirectUri)) {
        win.close(); clearInterval(interval);
        const params = new URLSearchParams(win.location.href.split('?')[1]);
        if (!params.get('code')) reject(new Error(`No Code (v${APP_VERSION}): Verify '${redirectUri}', clear cache, retry.`));
        if (params.get('state') !== state) reject(new Error(`CSRF Mismatch (v${APP_VERSION}): Check security, retry.`));
        resolve(params.get('code'));
      }} catch (e) {}
    }, 500);
    setTimeout(() => { win.close(); clearInterval(interval); reject(new Error(`Timeout (v${APP_VERSION}): Check network, retry at ${redirectUri}.`)); }, 300000);
  });
}

async function exchangeToken(code) {
  const verifier = sessionStorage.getItem('codeVerifier');
  if (!verifier) throw new Error(`PKCE Error (v${APP_VERSION}): Enable sessionStorage, refresh, retry.`);

  for (let i = 1; i <= MAX_RETRIES; i++) {
    try {
      const res = await fetch(`${X_API_BASE}/oauth2/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&client_id=${OAUTH2_CLIENT_ID}&code_verifier=${verifier}` });
      if (!res.ok) throw new Error(`Token Exchange Failed (v${APP_VERSION}): HTTP ${res.status}. Verify '${OAUTH2_CLIENT_ID}', '${REDIRECT_URI}', clear cache, retry.`);
      return (await res.json()).access_token;
    } catch (e) {
      if (i === MAX_RETRIES) throw new Error(`Token Max Retries (v${APP_VERSION}): ${e.message}. Verify credentials, clear cache, retry.`);
      await new Promise(r => setTimeout(r, RETRY_DELAY * Math.pow(2, i - 1)));
    }
  }
}

async function getUserId(token) {
  const res = await fetchRetry(`${X_API_BASE}/users/me`, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) throw new Error(`User ID Error (v${APP_VERSION}): HTTP ${res.status}. Verify token, scopes, clear cache, retry.`);
  return (await res.json()).data.id;
}

async function fetchUserDetails(userId, token) {
  const res = await fetchRetry(`${X_API_BASE}/users/${userId}?user.fields=username`, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) throw new Error(`User Details Error (v${APP_VERSION}): HTTP ${res.status}. Verify token, scopes, clear cache, retry.`);
  return (await res.json()).data;
}

async function getFollows(userId, token) {
  let follows = [], next = null;
  do {
    const url = `${X_API_BASE}/users/${userId}/following?max_results=100${next ? `&pagination_token=${next}` : ''}&user.fields=username`;
    const res = await fetchRetry(url, { headers: { Authorization: `Bearer ${token}` } });
    const data = await res.json();
    follows = follows.concat(data.data || []);
    next = data.meta?.next_token;
    await handleRateLimits(res);
  } while (next);
  return follows;
}

async function getFollowers(userId, token) {
  let followers = [], next = null;
  do {
    const url = `${X_API_BASE}/users/${userId}/followers?max_results=100${next ? `&pagination_token=${next}` : ''}&user.fields=username`;
    const res = await fetchRetry(url, { headers: { Authorization: `Bearer ${token}` } });
    const data = await res.json();
    followers = followers.concat(data.data || []);
    next = data.meta?.next_token;
    await handleRateLimits(res);
  } while (next);
  return followers;
}

async function checkInactivity(users, token) {
  const inactive = [], fourMonthsAgo = new Date(Date.now() - 4 * 30 * 24 * 60 * 60 * 1000).toISOString();
  for (let i = 0; i < Math.min(users.length, 10000) && inactive.length < 3000; i++) {
    try {
      const res = await fetchRetry(`${X_API_BASE}/users/${users[i].id}/tweets?max_results=1&start_time=${fourMonthsAgo}&tweet.fields=created_at`, { headers: { Authorization: `Bearer ${token}` } });
      if (!(await res.json()).meta.result_count) inactive.push(users[i]);
    } catch (e) {
      console.error(`Inactivity Check Error (v${APP_VERSION}): User ${users[i].username} skipped - ${e.message}. Verify token, clear cache, retry.`);
    }
    updateProgress(i + 1, users.length, inactive.length);
    await handleRateLimits(res);
  }
  return inactive;
}

function displayResults(users, userId) {
  const results = document.getElementById('results');
  if (!users.length) results.innerHTML = `<p>No inactive non-mutuals for @jfcarpio (ID: ${userId}, v${APP_VERSION}).</p>`;
  else results.innerHTML = `<h2>Inactive Non-Mutuals for @jfcarpio (v${APP_VERSION})</h2><table><tr><th>Username</th><th>ID</th><th>Activity</th></tr>${users.map(u => `<tr><td>${u.username}</td><td>${u.id}</td><td>Never (>4 months)</td></tr>`).join('')}</table>`;
}

function updateProgress(current, total, found) {
  document.getElementById('progress').innerText = `Processed ${current}/${total} non-mutuals for @jfcarpio (v${APP_VERSION}). Found ${found} inactive.`;
}

// Utility functions
async function fetchRetry(url, options) {
  for (let i = 1; i <= MAX_RETRIES; i++) {
    try {
      const res = await fetch(url, options);
      if (!res.ok) throw new Error(`API Error (v${APP_VERSION}): HTTP ${res.status}. Verify credentials, clear cache, retry.`);
      return res;
    } catch (e) {
      if (i === MAX_RETRIES) throw new Error(`API Max Retries (v${APP_VERSION}): ${e.message}. Verify credentials, clear cache, retry.`);
      await new Promise(r => setTimeout(r, RETRY_DELAY * Math.pow(2, i - 1)));
    }
  }
}

async function handleRateLimits(res) {
  const remaining = res.headers.get('x-rate-limit-remaining');
  const reset = res.headers.get('x-rate-limit-reset');
  if (remaining && parseInt(remaining) <= 5) {
    const wait = Math.max(0, new Date(parseInt(reset) * 1000) - Date.now() + 1000);
    console.log(`Rate Limit Warning (v${APP_VERSION}): Pausing ${wait / 1000}s for @jfcarpio. Check X limits (https://developer.twitter.com/), clear cache, retry.`);
    await new Promise(r => setTimeout(r, wait));
  } else await new Promise(r => setTimeout(r, 1000));
}

function generateRandomString(length) {
  return btoa(crypto.getRandomValues(new Uint8Array(length)).join('')).slice(0, length);
}

async function sha256(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
  const start = document.getElementById('startButton');
  if (start) start.addEventListener('click', findInactiveNonMutuals);
  else console.error(`Button Error (v${APP_VERSION}): Start button missing. Check index.html, clear cache, retry.`);
});
