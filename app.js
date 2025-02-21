// Constants for clarity and maintainability
const X_API_BASE = 'https://api.twitter.com/2';
const API_KEY = 'QlK4UFjcTMT9vHFtUZho90YIp'; // Your X app API Key (OAuth 1.0a or legacy, for reference)
const OAUTH2_CLIENT_ID = 'TFNFMUNETm1yR1JtX0trOWJQQ3A6MTpjaQ'; // Your X app OAuth 2.0 Client ID
const REDIRECT_URI = 'https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/callback'; // Your live GitHub Pages URL
const ACCESS_TOKEN = '11859152-XTKsuXYZkqAd0djHHqRfmnMaiN3n6rcOgMmLjyLY8'; // Your provided X access token
const MAX_RETRIES = 5; // Increased retries for robustness
const RETRY_DELAY_BASE = 5000; // 5 seconds initial delay to prevent rapid looping
const MAX_RETRY_ATTEMPTS = 3; // Limit total retry attempts to prevent infinite loops

let retryCount = 0; // Track total retry attempts
const APP_VERSION = '1.13'; // Define app version for logging and UI

// Main function to find inactive non-mutuals for @jfcarpio with enhanced failsafes
async function findInactiveNonMutuals() {
  const startButton = document.getElementById('startButton');
  const retryButton = document.getElementById('retryButton');
  const progressDiv = document.getElementById('progress');
  const resultsDiv = document.getElementById('results');
  const errorDiv = document.getElementById('error'); // Explicitly initialize errorDiv
  const loadingDiv = document.getElementById('loading');
  const instructionsDiv = document.getElementById('instructions');
  const callbackInput = document.getElementById('callbackUrl');
  const submitCallbackButton = document.getElementById('submitCallback');
  const versionDiv = document.getElementById('version'); // Add version div for UI updates

  let authCode = null;
  let accessToken = null;

  // Ensure all DOM elements exist (double-check and log)
  const requiredElements = [
    { el: startButton, id: 'startButton' },
    { el: progressDiv, id: 'progress' },
    { el: resultsDiv, id: 'results' },
    { el: errorDiv, id: 'error' },
    { el: loadingDiv, id: 'loading' },
    { el: instructionsDiv, id: 'instructions' },
    { el: callbackInput, id: 'callbackUrl' },
    { el: submitCallbackButton, id: 'submitCallback' },
    { el: versionDiv, id: 'version' }
  ];
  const missingElements = requiredElements.filter(({ el }) => el === null).map(({ id }) => id);
  if (missingElements.length > 0) {
    console.error(`DOM elements missing for @jfcarpio app (v${APP_VERSION}):`, missingElements);
    const errorMessage = `Error: Missing DOM elements (${missingElements.join(', ')}) for @jfcarpio (v${APP_VERSION}). Please refresh, check console, ensure index.html matches this version, and clear browser cache.`;
    if (errorDiv) {
      errorDiv.innerHTML = `<pre>${errorMessage}</pre>`;
    } else {
      console.log(`%c${errorMessage}`, 'color: red; font-weight: bold;');
    }
    if (startButton) startButton.disabled = false;
    if (versionDiv) versionDiv.innerText = `Version: ${APP_VERSION} (Status: Failed)`;
    return;
  }

  // Update version in UI
  if (versionDiv) versionDiv.innerText = `Version: ${APP_VERSION} (Status: Loading)`;

  // Reset UI state and prevent rapid updates
  startButton.disabled = true;
  retryButton.style.display = 'none';
  startButton.innerText = 'Authenticating with X...';
  progressDiv.innerHTML = '';
  resultsDiv.innerHTML = '';
  if (errorDiv.innerHTML) errorDiv.innerHTML += '\n'; // Add newline for readability
  errorDiv.innerHTML = ''; // Clear existing errors to prevent looping
  loadingDiv.style.display = 'block';
  instructionsDiv.style.display = 'block';

  try {
    // Step 1: Try using the provided access token first for simplicity
    console.log(`Attempting to use access token for @jfcarpio (v${APP_VERSION})...`);
    try {
      accessToken = await validateAndUseAccessToken(ACCESS_TOKEN);
      console.log(`Access token validated and used for @jfcarpio (v${APP_VERSION}):`, accessToken);
      progressDiv.innerHTML = `Authenticated as: @jfcarpio (using access token, v${APP_VERSION})`;
      if (versionDiv) versionDiv.innerText = `Version: ${APP_VERSION} (Status: Success)`;
    } catch (tokenError) {
      console.warn(`Access token failed for @jfcarpio (v${APP_VERSION}):`, tokenError.message);
      errorDiv.innerHTML += `<pre>Warning: Access token invalid or expired for @jfcarpio (v${APP_VERSION}) - ${tokenError.message}. Falling back to OAuth 2.0 PKCE authentication.</pre>`;
      console.log(`Falling back to OAuth 2.0 PKCE for @jfcarpio (v${APP_VERSION})...`);

      // Step 2: Validate client ID before OAuth flow with enhanced checking and detailed guidance
      console.log(`Validating OAuth 2.0 Client ID for @jfcarpio (v${APP_VERSION})...`);
      const isClientIdValid = await validateClientIdWithExtendedDetails(OAUTH2_CLIENT_ID, REDIRECT_URI);
      if (!isClientIdValid) {
        // Try API Key as an alternative (if applicable, e.g., for client credentials or verification)
        console.log(`Trying API Key for @jfcarpio (v${APP_VERSION}) as fallback...`);
        const isApiKeyValid = await validateApiKeyWithDetails(API_KEY);
        if (!isApiKeyValid) {
          throw new Error(`Invalid OAuth 2.0 Client ID and API Key for @jfcarpio (v${APP_VERSION}). Please verify your X app credentials in the X Developer Portal (ensure the OAuth 2.0 Client ID '${OAUTH2_CLIENT_ID}' and redirect URI '${REDIRECT_URI}' match exactly, case-sensitive, and API Key '${API_KEY}' is valid). Update OAUTH2_CLIENT_ID and API_KEY in app.js, ensure your app has 'Web App, Automated App or Bot' type with scopes 'tweet.read', 'users.read', and 'follows.read'. Visit https://developer.twitter.com/ for detailed guidance.`);
        }
        // If API Key is valid, use it for client credentials flow (if applicable)
        accessToken = await useApiKeyForToken(API_KEY);
        console.log(`API Key validated and used for @jfcarpio (v${APP_VERSION}):`, accessToken);
        progressDiv.innerHTML = `Authenticated as: @jfcarpio (using API Key, v${APP_VERSION})`;
        if (versionDiv) versionDiv.innerText = `Version: ${APP_VERSION} (Status: Success via API Key)`;
      } else {
        console.log(`OAuth 2.0 Client ID validated for @jfcarpio (v${APP_VERSION}).`);

        // Step 3: Initiate OAuth 2.0 PKCE authentication flow for @jfcarpio, handling already logged-in state
        console.log(`Starting X authentication for @jfcarpio (v${APP_VERSION}, reconfirming even if already logged in)...`);
        authCode = await initiateAuthFlowWithRetries();
        console.log(`Authorization code obtained for @jfcarpio (v${APP_VERSION}):`, authCode);

        // Step 4: Exchange code for access token with failsafes
        accessToken = await exchangeCodeForTokenWithRetries(authCode);
        console.log(`Successfully authenticated with X for @jfcarpio via OAuth (v${APP_VERSION}). Access token:`, accessToken);
        progressDiv.innerHTML = `Authenticated as: @jfcarpio (reconfirmed via OAuth, v${APP_VERSION})`;
        if (versionDiv) versionDiv.innerText = `Version: ${APP_VERSION} (Status: Success)`;
      }
    }

    // Step 5: Fetch and verify user ID for @jfcarpio
    console.log(`Fetching user ID for @jfcarpio (v${APP_VERSION})...`);
    const userId = await getUserId(accessToken);
    console.log(`User ID for @jfcarpio obtained (v${APP_VERSION}):`, userId);

    // Verify X account usage (ensure it’s @jfcarpio, even if already logged in)
    console.log(`Verifying X account details for @jfcarpio (v${APP_VERSION}, reconfirming identity)...`);
    const userDetails = await fetchUserDetails(userId, accessToken);
    if (userDetails.username !== 'jfcarpio') {
      throw new Error(`This app is configured for @jfcarpio (v${APP_VERSION}), but the authenticated account does not match. Please log in with @jfcarpio.`);
    }
    console.log(`Verified X account: @jfcarpio (reconfirmed, v${APP_VERSION})`);
    progressDiv.innerHTML = `Authenticated as: @${userDetails.username} (reconfirmed, v${APP_VERSION})`;

    // Step 6: Fetch follows and followers for @jfcarpio
    progressDiv.innerHTML = `Fetching follows for @jfcarpio (v${APP_VERSION})...`;
    console.log(`Fetching follows for @jfcarpio (v${APP_VERSION})...`);
    const follows = await getAllFollowsWithRetries(userId, accessToken);
    console.log(`Follows for @jfcarpio fetched (v${APP_VERSION}):`, follows.length);

    progressDiv.innerHTML = `Fetching followers for @jfcarpio (v${APP_VERSION})...`;
    console.log(`Fetching followers for @jfcarpio (v${APP_VERSION})...`);
    const followers = await getAllFollowersWithRetries(userId, accessToken);
    console.log(`Followers for @jfcarpio fetched (v${APP_VERSION}):`, followers.length);

    // Step 7: Identify non-mutuals for @jfcarpio
    console.log(`Identifying non-mutuals for @jfcarpio (v${APP_VERSION})...`);
    const followerIds = new Set(followers.map(follower => follower.id));
    const nonMutuals = follows.filter(follow => !followerIds.has(follow.id));
    console.log(`Non-mutuals for @jfcarpio identified (v${APP_VERSION}):`, nonMutuals.length);

    // Step 8: Check inactivity for non-mutuals (expanded scope)
    const inactiveNonMutuals = [];
    const fourMonthsAgo = new Date();
    fourMonthsAgo.setMonth(fourMonthsAgo.getMonth() - 4);
    const startTime = fourMonthsAgo.toISOString();

    progressDiv.innerHTML = `Checking non-mutuals for inactivity for @jfcarpio (v${APP_VERSION})...`;
    console.log(`Checking inactivity for non-mutuals of @jfcarpio (v${APP_VERSION})...`);
    for (let i = 0; i < Math.min(nonMutuals.length, 10000) && inactiveNonMutuals.length < 3000; i++) {
      const user = nonMutuals[i];
      try {
        console.log(`Checking user ${user.id} (${user.username}) for @jfcarpio (v${APP_VERSION})...`);
        const tweets = await getRecentTweetsWithRetries(user.id, startTime, accessToken);
        if (tweets.meta.result_count === 0) {
          inactiveNonMutuals.push(user);
          console.log(`User ${user.id} (${user.username}) is inactive for @jfcarpio (v${APP_VERSION}).`);
        } else {
          console.log(`User ${user.id} (${user.username}) is active for @jfcarpio (v${APP_VERSION}).`);
        }
      } catch (error) {
        console.error(`Error checking user ${user.id} (${user.username}) for @jfcarpio (v${APP_VERSION}):`, error);
        errorDiv.innerHTML += `\n<pre>Warning: Skipped user ${user.username} (ID: ${user.id}) due to error (v${APP_VERSION}) - ${error.message}. Check console for details.</pre>`;
      }
      updateProgress(i + 1, nonMutuals.length, inactiveNonMutuals.length);
      await handleRateLimits();
    }

    // Step 9: Display results professionally for @jfcarpio
    console.log(`Displaying results for @jfcarpio (v${APP_VERSION})...`);
    displayResults(inactiveNonMutuals, userId);
    if (versionDiv) versionDiv.innerText = `Version: ${APP_VERSION} (Status: Success)`;
  } catch (error) {
    console.error(`Error in findInactiveNonMutuals for @jfcarpio (v${APP_VERSION}):`, error);
    const errorMessage = `Critical Error for @jfcarpio (v${APP_VERSION}): ${error.message}. Check the console for detailed bug report, including stack trace and error context.`;
    if (errorDiv) {
      // Prevent rapid updates by checking if the last message matches
      const currentError = errorDiv.innerHTML.trim();
      if (!currentError.includes(errorMessage)) {
        errorDiv.innerHTML = `<pre>${errorMessage}</pre>`;
      } else {
        console.warn(`Duplicate error prevented for @jfcarpio (v${APP_VERSION}):`, errorMessage);
      }
    } else {
      console.log(`%c${errorMessage}`, 'color: red; font-weight: bold;');
    }
    retryButton.style.display = 'block';
    if (versionDiv) versionDiv.innerText = `Version: ${APP_VERSION} (Status: Failed)`;

    // Limit total retries to prevent infinite loops and provide clear guidance
    if (retryCount < MAX_RETRY_ATTEMPTS && (error.message.includes('Authentication') || error.message.includes('token') || error.message.includes('access') || error.message.includes('client') || error.message.includes('HTTP'))) {
      retryCount++;
      console.log(`Retry attempt ${retryCount}/${MAX_RETRY_ATTEMPTS} for @jfcarpio (v${APP_VERSION})...`);
      const waitTime = RETRY_DELAY_BASE * Math.pow(2, retryCount - 1); // Exponential backoff
      setTimeout(() => {
        findInactiveNonMutuals();
      }, waitTime);
      if (versionDiv) versionDiv.innerText = `Version: ${APP_VERSION} (Status: Retrying, Attempt ${retryCount}/${MAX_RETRY_ATTEMPTS})`;
    } else {
      console.error(`Max retry attempts reached for @jfcarpio (v${APP_VERSION}). Please check credentials and retry manually.`);
      if (errorDiv) {
        errorDiv.innerHTML += `\n<pre>Max retries reached for @jfcarpio (v${APP_VERSION}). Please verify your Access Token ('${ACCESS_TOKEN}'), OAuth 2.0 Client ID ('${OAUTH2_CLIENT_ID}'), API Key ('${API_KEY}'), and X app settings in the X Developer Portal (ensure 'Web App, Automated App or Bot' type, redirect URI '${REDIRECT_URI}' matches, and scopes 'tweet.read', 'users.read', 'follows.read' are enabled). Then, click "Retry Authentication", refresh the page, or update app.js. Visit https://developer.twitter.com/ for detailed guidance.</pre>`;
      } else {
        console.log(`%cMax retries reached for @jfcarpio (v${APP_VERSION}). Please verify your Access Token ('${ACCESS_TOKEN}'), OAuth 2.0 Client ID ('${OAUTH2_CLIENT_ID}'), API Key ('${API_KEY}'), and X app settings in the X Developer Portal, then click "Retry Authentication" or refresh the page.`, 'color: red; font-weight: bold;');
      }
      if (versionDiv) versionDiv.innerText = `Version: ${APP_VERSION} (Status: Failed)`;
    }
  } finally {
    startButton.disabled = false;
    startButton.innerText = 'Authenticate with X and Find Inactive Non-Mutuals';
    loadingDiv.style.display = 'none';
    instructionsDiv.style.display = 'none';
    if (versionDiv) versionDiv.innerText = `Version: ${APP_VERSION} (Status: Idle)`;
  }
}

/**
 * Validates and uses the provided access token for @jfcarpio, falling back if invalid, with enhanced logging.
 * @param {string} token - The access token
 * @returns {Promise<string>} Valid access token or throws error
 */
async function validateAndUseAccessToken(token) {
  try {
    const response = await fetchWithRetry(`${X_API_BASE}/users/me?user.fields=username,name`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Access token validation failed for @jfcarpio (v${APP_VERSION}): HTTP ${response.status} - ${errorText}`);
    }
    const userDetails = await response.json().data;
    if (userDetails.username !== 'jfcarpio') {
      throw new Error('Access token does not belong to @jfcarpio (v${APP_VERSION}). Please provide the correct token.');
    }
    console.log(`Access token validated successfully for @jfcarpio (v${APP_VERSION}):`, token);
    return token;
  } catch (error) {
    console.error(`Error validating access token for @jfcarpio (v${APP_VERSION}):`, error);
    throw error;
  }
}

/**
 * Validates the OAuth 2.0 client ID against X API with extended detailed error reporting for @jfcarpio.
 * @param {string} clientId - The OAuth 2.0 client ID to validate
 * @param {string} redirectUri - The redirect URI to verify
 * @returns {Promise<boolean>} Whether the client ID is valid
 */
async function validateClientIdWithExtendedDetails(clientId, redirectUri) {
  try {
    const response = await fetchWithRetry(`${X_API_BASE}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=client_credentials&client_id=${clientId}`
    });
    if (!response.ok) {
      const errorText = await response.text();
      console.warn(`OAuth 2.0 Client ID validation failed for @jfcarpio (v${APP_VERSION}):`, errorText);
      return false;
    }
    // Optionally, verify redirect URI configuration (simplified check; X handles this server-side)
    const appConfigResponse = await fetchWithRetry(`${X_API_BASE}/oauth2/clients/${clientId}`, {
      headers: { Authorization: `Basic ${btoa(`${clientId}:`)}` } // Basic auth with client ID only (simplified)
    });
    if (!appConfigResponse.ok) {
      console.warn(`Redirect URI or app config validation failed for @jfcarpio (v${APP_VERSION}):`, await appConfigResponse.text());
      return false;
    }
    return true;
  } catch (error) {
    console.error(`Error validating OAuth 2.0 Client ID for @jfcarpio (v${APP_VERSION}):`, error);
    return false;
  }
}

/**
 * Validates the API Key against X API with detailed error reporting for @jfcarpio (legacy or client credentials).
 * @param {string} apiKey - The API Key to validate
 * @returns {Promise<boolean>} Whether the API Key is valid
 */
async function validateApiKeyWithDetails(apiKey) {
  try {
    const response = await fetchWithRetry(`${X_API_BASE}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=client_credentials&client_id=${apiKey}`
    });
    if (!response.ok) {
      const errorText = await response.text();
      console.warn(`API Key validation failed for @jfcarpio (v${APP_VERSION}):`, errorText);
      return false;
    }
    return true;
  } catch (error) {
    console.error(`Error validating API Key for @jfcarpio (v${APP_VERSION}):`, error);
    return false;
  }
}

/**
 * Uses the API Key for a client credentials flow to obtain an access token (if applicable).
 * @param {string} apiKey - The API Key
 * @returns {Promise<string>} Access token or throws error
 */
async function useApiKeyForToken(apiKey) {
  try {
    const response = await fetchWithRetry(`${X_API_BASE}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=client_credentials&client_id=${apiKey}`
    });
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Client credentials flow failed for @jfcarpio (v${APP_VERSION}) with API Key: HTTP ${response.status} - ${errorText}`);
    }
    const tokenData = await response.json();
    return tokenData.access_token;
  } catch (error) {
    console.error(`Error using API Key for token for @jfcarpio (v${APP_VERSION}):`, error);
    throw error;
  }
}

/**
 * Initiates OAuth 2.0 PKCE authentication flow for @jfcarpio, handling already logged-in state with retries.
 * @returns {Promise<string>} Authorization code
 */
async function initiateAuthFlowWithRetries() {
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const state = generateRandomString(16); // CSRF protection
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = await generateCodeChallenge(codeVerifier);

      // Use prompt=login to force reconfirmation, even if already logged in, with fallback
      const authUrl = `${X_API_BASE}/oauth2/authorize?response_type=code&client_id=${OAUTH2_CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=tweet.read%20users.read%20follows.read&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256&prompt=login`;
      console.log(`Attempt ${attempt}/${MAX_RETRIES}: Redirecting to X for authentication (reconfirming @jfcarpio, v${APP_VERSION}). Open this URL:`, authUrl);

      let authWindow;
      try {
        authWindow = window.open(authUrl, '_blank', 'width=600,height=600');
        if (!authWindow) throw new Error('Popup blocked. Please open this URL manually:', authUrl);
      } catch (popupError) {
        console.error(`Popup error for @jfcarpio (v${APP_VERSION}, Attempt ${attempt}):`, popupError);
        if (errorDiv) {
          errorDiv.innerHTML = `<p class="error">Popup blocked or failed (Attempt ${attempt}, v${APP_VERSION}). Please open this URL manually: <a href="${authUrl}" target="_blank">${authUrl}</a>, authorize with @jfcarpio, then paste the callback URL below.</p>`;
        } else {
          console.log(`%cPopup blocked or failed (Attempt ${attempt}, v${APP_VERSION}) for @jfcarpio. Please open: ${authUrl}`, 'color: red; font-weight: bold;');
        }
        return await getAuthCodeManuallyWithRetries(REDIRECT_URI, state, attempt);
      }

      return await pollForCallbackWithRetries(authWindow, REDIRECT_URI, state, attempt);
    } catch (error) {
      console.error(`Authentication attempt ${attempt} failed for @jfcarpio (v${APP_VERSION}):`, error);
      if (attempt === MAX_RETRIES) throw new Error(`Authentication failed after ${MAX_RETRIES} retries for @jfcarpio (v${APP_VERSION}): ${error.message}`);
      const waitTime = RETRY_DELAY_BASE * Math.pow(2, attempt - 1); // Exponential backoff
      console.log(`Retrying authentication for @jfcarpio (v${APP_VERSION}) in ${waitTime / 1000} seconds...`);
      if (errorDiv) {
        errorDiv.innerHTML = `<pre>Retrying authentication (attempt ${attempt + 1}/${MAX_RETRIES}, v${APP_VERSION}) for @jfcarpio: ${error.message}. Check console for details.</pre>`;
      } else {
        console.log(`%cRetrying authentication (attempt ${attempt + 1}/${MAX_RETRIES}, v${APP_VERSION}) for @jfcarpio: ${error.message}`, 'color: orange; font-weight: bold;');
      }
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }
  }
}

/**
 * Polls for the callback URL in the authentication window, handling already logged-in state with retries.
 * @param {Window} authWindow - The authentication window
 * @param {string} redirectUri - The redirect URI
 * @param {string} state - CSRF state
 * @param {number} attempt - Current retry attempt
 * @returns {Promise<string>} Authorization code
 */
async function pollForCallbackWithRetries(authWindow, redirectUri, state, attempt) {
  return new Promise((resolve, reject) => {
    let checkInterval = setInterval(async () => {
      try {
        if (authWindow.closed) {
          clearInterval(checkInterval);
          reject(new Error(`Authentication window closed unexpectedly for @jfcarpio (v${APP_VERSION}, Attempt ${attempt}). Please retry.`));
          return;
        }
        const url = authWindow.location.href;
        if (url && url.includes(redirectUri)) {
          authWindow.close();
          clearInterval(checkInterval);
          const params = new URLSearchParams(url.split('?')[1]);
          const code = params.get('code');
          const returnedState = params.get('state');
          if (!code) reject(new Error(`No authorization code found in callback URL for @jfcarpio (v${APP_VERSION}, Attempt ${attempt})`));
          if (returnedState !== state) reject(new Error(`CSRF state mismatch detected for @jfcarpio (v${APP_VERSION}, Attempt ${attempt})`));
          resolve(code);
        }
      } catch (e) {
        // Ignore cross-origin errors
      }
    }, 500);

    setTimeout(() => {
      clearInterval(checkInterval);
      authWindow.close();
      reject(new Error(`Authentication timed out after 5 minutes for @jfcarpio (v${APP_VERSION}, Attempt ${attempt}). Please retry.`));
    }, 300000); // 5-minute timeout
  });
}

/**
 * Manual fallback for authentication with retries, handling user input for callback URL.
 * @param {string} redirectUri - The redirect URI
 * @param {string} state - CSRF state
 * @param {number} attempt - Current retry attempt
 * @returns {Promise<string>} Authorization code
 */
async function getAuthCodeManuallyWithRetries(redirectUri, state, attempt) {
  return new Promise((resolve, reject) => {
    submitCallbackButton.onclick = async () => {
      const callbackUrl = callbackInput.value.trim();
      if (!callbackUrl) {
        if (errorDiv) {
          errorDiv.innerHTML = `<p class="error">Please paste the callback URL from X for @jfcarpio (v${APP_VERSION}, Attempt ${attempt}).</p>`;
        } else {
          console.log(`%cPlease paste the callback URL from X for @jfcarpio (v${APP_VERSION}, Attempt ${attempt}).`, 'color: red; font-weight: bold;');
        }
        return;
      }
      try {
        const params = new URLSearchParams(new URL(callbackUrl).search);
        const code = params.get('code');
        const returnedState = params.get('state');
        if (!code) throw new Error(`No authorization code found in callback URL for @jfcarpio (v${APP_VERSION}, Attempt ${attempt})`);
        if (returnedState !== state) throw new Error(`CSRF state mismatch detected for @jfcarpio (v${APP_VERSION}, Attempt ${attempt})`);
        resolve(code);
      } catch (error) {
        console.error(`Error parsing callback URL for @jfcarpio (v${APP_VERSION}, Attempt ${attempt}):`, error);
        if (errorDiv) {
          errorDiv.innerHTML = `<p class="error">Invalid callback URL for @jfcarpio (v${APP_VERSION}, Attempt ${attempt}): ${error.message}. Please ensure you copied the full URL from X after authentication.</p>`;
        } else {
          console.log(`%cInvalid callback URL for @jfcarpio (v${APP_VERSION}, Attempt ${attempt}): ${error.message}`, 'color: red; font-weight: bold;');
        }
        reject(error);
      }
    };
  });
}

/**
 * Exchanges authorization code for access token with failsafes and retries for @jfcarpio.
 * @param {string} authCode - The authorization code
 * @returns {Promise<string>} Access token
 */
async function exchangeCodeForTokenWithRetries(authCode) {
  const codeVerifier = sessionStorage.getItem('codeVerifier');
  if (!codeVerifier) throw new Error(`Code verifier not found for @jfcarpio (v${APP_VERSION}). Please restart authentication.`);

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const tokenResponse = await fetchWithRetry(`${X_API_BASE}/oauth2/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=authorization_code&code=${authCode}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&client_id=${OAUTH2_CLIENT_ID}&code_verifier=${codeVerifier}`
      });
      if (!tokenResponse.ok) {
        const errorText = await tokenResponse.text();
        throw new Error(`Token exchange failed for @jfcarpio (v${APP_VERSION}): HTTP ${tokenResponse.status} - ${errorText}`);
      }
      const tokenData = await tokenResponse.json();
      return tokenData.access_token;
    } catch (error) {
      console.error(`Token exchange attempt ${attempt} failed for @jfcarpio (v${APP_VERSION}):`, error);
      if (attempt === MAX_RETRIES) throw error;
      const waitTime = RETRY_DELAY_BASE * Math.pow(2, attempt - 1); // Exponential backoff
      console.log(`Retrying token exchange for @jfcarpio (v${APP_VERSION}) in ${waitTime / 1000} seconds...`);
      if (errorDiv) {
        errorDiv.innerHTML += `\n<pre>Retrying token exchange (attempt ${attempt + 1}/${MAX_RETRIES}, v${APP_VERSION}) for @jfcarpio: ${error.message}. Check console for details.</pre>`;
      } else {
        console.log(`%cRetrying token exchange (attempt ${attempt + 1}/${MAX_RETRIES}, v${APP_VERSION}) for @jfcarpio: ${error.message}`, 'color: orange; font-weight: bold;');
      }
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }
  }
}

/**
 * Fetches user ID from X API for @jfcarpio.
 * @param {string} accessToken - The access token
 * @returns {Promise<string>} User ID
 */
async function getUserId(accessToken) {
  try {
    const response = await fetchWithRetry(`${X_API_BASE}/users/me`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!response.ok) throw new Error(`Failed to fetch user ID for @jfcarpio (v${APP_VERSION}): HTTP ${response.status} - ${response.statusText}`);
    const data = await response.json();
    return data.data.id;
  } catch (error) {
    console.error(`Error in getUserId for @jfcarpio (v${APP_VERSION}):`, error);
    throw error;
  }
}

/**
 * Fetches user details to verify @jfcarpio, even if already logged in.
 * @param {string} userId - The user ID
 * @param {string} accessToken - The access token
 * @returns {Promise<Object>} User details
 */
async function fetchUserDetails(userId, accessToken) {
  try {
    const response = await fetchWithRetry(`${X_API_BASE}/users/${userId}?user.fields=username,name`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!response.ok) throw new Error(`Failed to fetch user details for @jfcarpio (v${APP_VERSION}): HTTP ${response.status} - ${response.statusText}`);
    return await response.json().data;
  } catch (error) {
    console.error(`Error in fetchUserDetails for @jfcarpio (v${APP_VERSION}):`, error);
    throw error;
  }
}

/**
 * Fetches all follows with pagination for @jfcarpio with retries.
 * @param {string} userId - The user ID
 * @param {string} accessToken - The access token
 * @returns {Promise<Array>} List of follows
 */
async function getAllFollowsWithRetries(userId, accessToken) {
  let follows = [];
  let nextToken = null;
  do {
    try {
      const url = `${X_API_BASE}/users/${userId}/following?max_results=100${nextToken ? `&pagination_token=${nextToken}` : ''}&user.fields=username`;
      const response = await fetchWithRetry(url, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      const data = await response.json();
      follows = follows.concat(data.data || []);
      nextToken = data.meta.next_token;
      await handleRateLimits(response);
    } catch (error) {
      console.error(`Error in getAllFollows for @jfcarpio (v${APP_VERSION}):`, error);
      throw error;
    }
  } while (nextToken);
  return follows;
}

/**
 * Fetches all followers with pagination for @jfcarpio with retries.
 * @param {string} userId - The user ID
 * @param {string} accessToken - The access token
 * @returns {Promise<Array>} List of followers
 */
async function getAllFollowersWithRetries(userId, accessToken) {
  let followers = [];
  let nextToken = null;
  do {
    try {
      const url = `${X_API_BASE}/users/${userId}/followers?max_results=100${nextToken ? `&pagination_token=${nextToken}` : ''}&user.fields=username`;
      const response = await fetchWithRetry(url, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      const data = await response.json();
      followers = followers.concat(data.data || []);
      nextToken = data.meta.next_token;
      await handleRateLimits(response);
    } catch (error) {
      console.error(`Error in getAllFollowers for @jfcarpio (v${APP_VERSION}):`, error);
      throw error;
    }
  } while (nextToken);
  return followers;
}

/**
 * Fetches recent tweets for a user for @jfcarpio with retries.
 * @param {string} userId - The user ID
 * @param {string} startTime - The start time for tweets
 * @param {string} accessToken - The access token
 * @returns {Promise<Object>} Tweets response
 */
async function getRecentTweetsWithRetries(userId, startTime, accessToken) {
  const url = `${X_API_BASE}/users/${userId}/tweets?max_results=1&start_time=${startTime}&tweet.fields=created_at`;
  return await fetchWithRetry(url, {
    headers: { Authorization: `Bearer ${accessToken}` }
  }).then(response => response.json());
}

/**
 * Performs a fetch with retry logic for @jfcarpio with enhanced failsafes.
 * @param {string} url - The URL to fetch
 * @param {Object} options - Fetch options
 * @returns {Promise<Response>} Fetch response
 */
async function fetchWithRetry(url, options) {
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const response = await fetch(url, options);
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`API call failed for @jfcarpio (v${APP_VERSION}): HTTP ${response.status} - ${errorText}`);
      }
      return response;
    } catch (error) {
      console.error(`Fetch attempt ${attempt} failed for @jfcarpio (v${APP_VERSION}):`, error);
      if (attempt === MAX_RETRIES) throw error;
      const waitTime = RETRY_DELAY_BASE * Math.pow(2, attempt - 1); // Exponential backoff
      console.log(`Retrying API call for @jfcarpio (v${APP_VERSION}) in ${waitTime / 1000} seconds...`);
      if (errorDiv) {
        errorDiv.innerHTML += `\n<pre>Retrying API call (attempt ${attempt + 1}/${MAX_RETRIES}, v${APP_VERSION}) for @jfcarpio: ${error.message}. Check console for details.</pre>`;
      } else {
        console.log(`%cRetrying API call (attempt ${attempt + 1}/${MAX_RETRIES}, v${APP_VERSION}) for @jfcarpio: ${error.message}`, 'color: orange; font-weight: bold;');
      }
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }
  }
}

/**
 * Handles rate limits for X API calls for @jfcarpio with enhanced failsafes.
 * @param {Response} response - The fetch response
 */
async function handleRateLimits(response) {
  try {
    const rateLimitRemaining = response.headers.get('x-rate-limit-remaining');
    const rateLimitReset = response.headers.get('x-rate-limit-reset');
    if (rateLimitRemaining && parseInt(rateLimitRemaining) <= 5) {
      const resetTime = new Date(parseInt(rateLimitReset) * 1000);
      const waitTime = Math.max(0, resetTime - Date.now() + 1000); // Add 1s buffer
      console.log(`Rate limit nearing exhaustion for @jfcarpio (v${APP_VERSION}). Waiting ${waitTime / 1000} seconds...`);
      await new Promise(resolve => setTimeout(resolve, waitTime));
    } else {
      await new Promise(resolve => setTimeout(resolve, 1000)); // Default 1s delay
    }
  } catch (error) {
    console.error(`Error in handleRateLimits for @jfcarpio (v${APP_VERSION}):`, error);
    if (errorDiv) {
      errorDiv.innerHTML += `\n<pre>Rate limit handling error for @jfcarpio (v${APP_VERSION}): ${error.message}. Check console for details.</pre>`;
    } else {
      console.log(`%cRate limit handling error for @jfcarpio (v${APP_VERSION}): ${error.message}`, 'color: red; font-weight: bold;');
    }
    throw error;
  }
}

/**
 * Updates progress UI for @jfcarpio.
 * @param {number} current - Current processed count
 * @param {number} total - Total non-mutuals
 * @param {number} found - Inactive users found
 */
function updateProgress(current, total, found) {
  document.getElementById('progress').innerText = 
    `Processed ${current} of ${total} non-mutuals for @jfcarpio (v${APP_VERSION}). Found ${found} inactive users.`;
}

/**
 * Displays results in a professional table for @jfcarpio.
 * @param {Array} users - List of inactive non-mutuals
 * @param {string} userId - The user ID
 */
function displayResults(users, userId) {
  const resultsDiv = document.getElementById('results');
  if (users.length === 0) {
    resultsDiv.innerHTML = `<p class="no-results">No inactive non-mutuals found for @jfcarpio (ID: ${userId}, v${APP_VERSION}).</p>`;
  } else {
    resultsDiv.innerHTML = `
      <h2>Inactive Non-Mutual Follows for @jfcarpio (v${APP_VERSION})</h2>
      <table class="results-table">
        <thead>
          <tr>
            <th>Username</th>
            <th>User ID</th>
            <th>Last Activity</th>
          </tr>
        </thead>
        <tbody>
          ${users.map(user => {
            const lastActivity = 'Never (or >4 months ago)';
            return `
              <tr>
                <td>${user.username}</td>
                <td>${user.id}</td>
                <td>${lastActivity}</td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    `;
  }
}

/**
 * Generates a random string for CSRF protection or PKCE.
 * @param {number} length - Length of the random string
 * @returns {string} Random string
 */
function generateRandomString(length) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, x => x.toString(36)).join('').slice(0, length);
}

/**
 * Generates a PKCE code verifier for @jfcarpio.
 * @returns {string} Code verifier
 */
function generateCodeVerifier() {
  const verifier = generateRandomString(43); // Minimum length per RFC 7636
  sessionStorage.setItem('codeVerifier', verifier); // Securely store in session storage
  return verifier;
}

/**
 * Generates a PKCE code challenge for @jfcarpio.
 * @param {string} codeVerifier - The code verifier
 * @returns {Promise<string>} Code challenge
 */
async function generateCodeChallenge(codeVerifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Test cases (commented for future implementation)
/*
  test('findInactiveNonMutuals should authenticate with X or access token and fetch data reliably for @jfcarpio (v1.13)', async () => {
    // Mock fetch with X API responses for @jfcarpio, including rate limits and errors
  });
  test('initiateAuthFlowWithRetries should handle already logged-in state and succeed for @jfcarpio (v1.13)', async () => {
    // Mock window.open, location.href, and X API responses
  });
  test('fetchWithRetry should handle multiple failures and succeed for @jfcarpio (v1.13)', async () => {
    // Mock fetch with various error scenarios and retries
  });
*/

// Ensure event listener attaches after DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  const startButton = document.getElementById('startButton');
  if (startButton) {
    startButton.addEventListener('click', findInactiveNonMutuals);
    console.log(`Event listener attached successfully for @jfcarpio (v${APP_VERSION}).`);
  } else {
    console.error(`Start button not found for @jfcarpio (v${APP_VERSION}). Check index.html.`);
    const errorDiv = document.getElementById('error');
    if (errorDiv) {
      errorDiv.innerHTML = `<p class="error">Error: Button not found (v${APP_VERSION}). Please refresh and check console for details.</p>`;
    } else {
      console.log(`%cError: errorDiv not found for @jfcarpio (v${APP_VERSION}). Please ensure index.html includes <div id="error">.`, 'color: red; font-weight: bold;');
    }
    if (versionDiv) versionDiv.innerText = `Version: ${APP_VERSION} (Status: Failed)`;
  }
});
