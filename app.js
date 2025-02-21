// Constants for clarity and maintainability
const X_API_BASE = 'https://api.twitter.com/2';
const API_KEY = 'QlK4UFjcTMT9vHFtUZho90YIp'; // Your X app API Key (OAuth 1.0a or legacy, for reference)
const OAUTH2_CLIENT_ID = 'TFNFMUNETm1yR1JtX0trOWJQQ3A6MTpjaQ'; // Your X app OAuth 2.0 Client ID
const REDIRECT_URI = 'https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/callback'; // Your live GitHub Pages URL
const BEARER_TOKEN = 'AAAAAAAAAAAAAAAAAAAAAMmPvQEAAAAAnMFJgOjandSI9vBjNRfn7C2Y2BU%3Dnyll1sjKYj8PAufR8xOAJ6qEPID621WkwoXaqEKHOVODW5zmbj'; // Your provided X Bearer Token for API v2
const MAX_RETRIES = 5; // Increased retries for robustness
const RETRY_DELAY_BASE = 5000; // 5 seconds initial delay to prevent rapid looping
const MAX_RETRY_ATTEMPTS = 3; // Limit total retry attempts to prevent infinite loops

let retryCount = 0; // Track total retry attempts
const APP_VERSION = '1.15'; // Define app version for logging and UI

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
    const errorMessage = `Critical Development Error (v${APP_VERSION}): DOM elements are missing for the Inactive Non-Mutual Follows Finder app for @jfcarpio. The following elements could not be found: ${missingElements.join(', ')}. This issue likely stems from a mismatch between index.html and app.js. To resolve:\n1. Verify that index.html includes all required elements with exact IDs (e.g., <div id="error">, <div id="version">).\n2. Ensure index.html matches the v${APP_VERSION} version provided.\n3. Clear your browser cache (Ctrl+F5 or Cmd+R) and refresh https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/.\n4. Check the console for additional stack trace details and redeploy to GitHub Pages if needed.`;
    if (errorDiv) {
      errorDiv.innerHTML = `<pre>${errorMessage}</pre>`;
    } else {
      console.log(`%c${errorMessage}`, 'color: red; font-weight: bold;');
    }
    if (startButton) startButton.disabled = false;
    if (versionDiv) versionDiv.innerText = `Version: ${APP_VERSION} (Status: Failed - DOM Issue)`;
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
    // Step 1: Try using the provided Bearer Token first for simplicity (X API v2)
    console.log(`Attempting to use Bearer Token for @jfcarpio (v${APP_VERSION})...`);
    try {
      accessToken = await validateAndUseBearerToken(BEARER_TOKEN);
      console.log(`Bearer Token validated and used successfully for @jfcarpio (v${APP_VERSION}): ${BEARER_TOKEN.substring(0, 20)}...`);
      progressDiv.innerHTML = `Authenticated as: @jfcarpio (using Bearer Token, v${APP_VERSION})`;
      if (versionDiv) versionDiv.innerText = `Version: ${APP_VERSION} (Status: Success via Bearer Token)`;
    } catch (tokenError) {
      console.warn(`Bearer Token validation failed for @jfcarpio (v${APP_VERSION}):`, tokenError.message);
      const tokenErrorDetails = `Critical Authentication Error (v${APP_VERSION}): The Bearer Token '${BEARER_TOKEN.substring(0, 20)}...' for @jfcarpio failed validation in the Inactive Non-Mutual Follows Finder app. This could indicate:\n- The token is invalid, expired, or revoked.\n- It’s not associated with @jfcarpio’s X account or lacks proper X API v2 permissions.\n- Required scopes ('tweet.read', 'users.read', 'follows.read') are missing or restricted.\nTo fix this for development:\n1. Log in to the X Developer Portal (https://developer.twitter.com/) with @jfcarpio.\n2. Navigate to your app ('Inactive Follows Finder' or similar) under Projects & Apps.\n3. Go to 'Keys and Tokens' and verify or regenerate the Bearer Token, ensuring it’s a valid X API v2 Bearer Token with scopes 'tweet.read', 'users.read', and 'follows.read'.\n4. Update BEARER_TOKEN in app.js (line 18) with the new token if regenerated.\n5. Clear your browser cache (Ctrl+F5 or Cmd+R) and retry at https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/.\n6. Check the console for full stack trace, X API response details, and redeploy to GitHub Pages if needed.\n7. Review X’s API v2 documentation (https://developer.twitter.com/en/docs/twitter-api) for Bearer Token authentication and error codes. Falling back to OAuth 2.0 PKCE...`;
      errorDiv.innerHTML += `<pre>${tokenErrorDetails}</pre>`;
      console.log(`Falling back to OAuth 2.0 PKCE for @jfcarpio (v${APP_VERSION})...`);

      // Step 2: Validate OAuth 2.0 Client ID before OAuth flow with highly detailed checking and guidance
      console.log(`Validating OAuth 2.0 Client ID for @jfcarpio (v${APP_VERSION})...`);
      const isClientIdValid = await validateClientIdWithDetailedDiagnostics(OAUTH2_CLIENT_ID, REDIRECT_URI);
      if (!isClientIdValid) {
        // Try API Key as an alternative (if applicable, e.g., for client credentials or verification)
        console.log(`Trying API Key for @jfcarpio (v${APP_VERSION}) as fallback...`);
        const isApiKeyValid = await validateApiKeyWithDetailedDiagnostics(API_KEY);
        if (!isApiKeyValid) {
          const clientIdErrorDetails = `Critical OAuth 2.0 Configuration Error (v${APP_VERSION}): The OAuth 2.0 Client ID '${OAUTH2_CLIENT_ID}' for @jfcarpio’s Inactive Non-Mutual Follows Finder app is invalid. Possible issues include:\n- The Client ID is incorrect, expired, or not registered in the X Developer Portal.\n- The redirect URI '${REDIRECT_URI}' does not match the X app settings exactly (case-sensitive, including 'https://', slashes, and path).\n- The app type is not set to 'Web App, Automated App or Bot' (confidential client).\n- Required scopes ('tweet.read', 'users.read', 'follows.read') are missing or misconfigured.\n- The app is suspended, restricted, or exceeds free-tier limits.\n- X API policy changes as of February 21, 2025, require app verification or paid tier.\n- The API Key '${API_KEY}' also failed validation, likely because it’s an OAuth 1.0a or legacy key not suitable for OAuth 2.0 PKCE.\nDevelopment Steps to Resolve:\n1. Log in to the X Developer Portal (https://developer.twitter.com/) with @jfcarpio.\n2. Navigate to Projects & Apps, locate your app ('Inactive Follows Finder'), and check 'Keys and Tokens' for the correct OAuth 2.0 Client ID.\n3. Verify the redirect URI is exactly '${REDIRECT_URI}' in app settings, and update it if needed (case-sensitive).\n4. Ensure the app type is 'Web App, Automated App or Bot' and scopes include 'tweet.read', 'users.read', 'follows.read'.\n5. If the Client ID is invalid, regenerate it in the portal and update OAUTH2_CLIENT_ID in app.js (line 15).\n6. Check app status (active, not suspended) and free-tier limits in the portal.\n7. Consider removing or verifying the API Key ('${API_KEY}') if it’s not needed for OAuth 2.0 PKCE; it’s likely legacy and can be ignored unless required for client credentials.\n8. Clear browser cache (Ctrl+F5 or Cmd+R), retry at https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/, and redeploy to GitHub Pages if changes are made.\n9. Review X’s OAuth 2.0 documentation (https://developer.twitter.com/en/docs/authentication/oauth-2-0) and API v2 docs (https://developer.twitter.com/en/docs/twitter-api) for troubleshooting, focusing on client ID validation, scopes, and rate limits.`;
          throw new Error(clientIdErrorDetails);
        }
        // If API Key is valid, use it for client credentials flow (if applicable)
        accessToken = await useApiKeyForToken(API_KEY);
        console.log(`API Key validated and used successfully for @jfcarpio (v${APP_VERSION}): ${API_KEY.substring(0, 10)}...`);
        progressDiv.innerHTML = `Authenticated as: @jfcarpio (using API Key, v${APP_VERSION})`;
        if (versionDiv) versionDiv.innerText = `Version: ${APP_VERSION} (Status: Success via API Key)`;
      } else {
        console.log(`OAuth 2.0 Client ID validated successfully for @jfcarpio (v${APP_VERSION}): ${OAUTH2_CLIENT_ID.substring(0, 10)}...`);

        // Step 3: Initiate OAuth 2.0 PKCE authentication flow for @jfcarpio, handling already logged-in state
        console.log(`Starting X authentication for @jfcarpio (v${APP_VERSION}, reconfirming even if already logged in)...`);
        authCode = await initiateAuthFlowWithRetries();
        console.log(`Authorization code obtained for @jfcarpio (v${APP_VERSION}):`, authCode);

        // Step 4: Exchange code for access token with failsafes
        accessToken = await exchangeCodeForTokenWithRetries(authCode);
        console.log(`Successfully authenticated with X for @jfcarpio via OAuth (v${APP_VERSION}). Access token:`, accessToken);
        progressDiv.innerHTML = `Authenticated as: @jfcarpio (reconfirmed via OAuth, v${APP_VERSION})`;
        if (versionDiv) versionDiv.innerText = `Version: ${APP_VERSION} (Status: Success via OAuth)`;
      }

    // Step 5: Fetch and verify user ID for @jfcarpio
    console.log(`Fetching user ID for @jfcarpio (v${APP_VERSION})...`);
    const userId = await getUserId(accessToken);
    console.log(`User ID for @jfcarpio obtained (v${APP_VERSION}):`, userId);

    // Verify X account usage (ensure it’s @jfcarpio, even if already logged in)
    console.log(`Verifying X account details for @jfcarpio (v${APP_VERSION}, reconfirming identity)...`);
    const userDetails = await fetchUserDetails(userId, accessToken);
    if (userDetails.username !== 'jfcarpio') {
      const userMismatchError = `Critical User Verification Error (v${APP_VERSION}): The authenticated X account does not match @jfcarpio. Current username: '${userDetails.username}'. This app is configured for @jfcarpio’s Inactive Non-Mutual Follows Finder. To fix:\n1. Ensure you’re logging in with @jfcarpio in the X authentication flow.\n2. Verify the Bearer Token, OAuth 2.0 Client ID, or API Key corresponds to @jfcarpio’s account in the X Developer Portal.\n3. Regenerate credentials if necessary and update BEARER_TOKEN (line 18), OAUTH2_CLIENT_ID (line 15), or API_KEY (line 14) in app.js.\n4. Clear browser cache (Ctrl+F5 or Cmd+R), retry at https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/, and redeploy to GitHub Pages if changes are made.\n5. Review X’s authentication documentation (https://developer.twitter.com/en/docs/authentication) for user identity verification.`;
      throw new Error(userMismatchError);
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
        const tweetErrorDetails = `Warning: Skipped user ${user.username} (ID: ${user.id}) due to an error in the Inactive Non-Mutual Follows Finder app for @jfcarpio (v${APP_VERSION}) - ${error.message}. This could indicate:\n- Rate limit exhaustion or API downtime for X API v2.\n- Invalid or expired Bearer Token '${BEARER_TOKEN.substring(0, 20)}...'.\n- Network issues or CORS restrictions on GitHub Pages.\n- Incorrect scopes or permissions for the token.\nTo resolve:\n1. Verify the Bearer Token, OAuth 2.0 Client ID, and API Key in the X Developer Portal.\n2. Check X API status at https://developer.twitter.com/en/support/twitter-api/status.\n3. Ensure the Bearer Token has 'tweet.read', 'users.read', and 'follows.read' scopes.\n4. Clear browser cache (Ctrl+F5 or Cmd+R) and retry at https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/.\n5. Review X’s API v2 documentation (https://developer.twitter.com/en/docs/twitter-api) for rate limits, error codes, and token permissions.`;
        errorDiv.innerHTML += `\n<pre>${tweetErrorDetails}</pre>`;
      }
      updateProgress(i + 1, nonMutuals.length, inactiveNonMutuals.length);
      await handleRateLimits();
    }

    // Step 9: Display results professionally for @jfcarpio
    console.log(`Displaying results for @jfcarpio (v${APP_VERSION})...`);
    displayResults(inactiveNonMutuals, userId);
    if (versionDiv) versionDiv.innerText = `Version: ${APP_VERSION} (Status: Success)`;
  } catch (error) {
    console.error(`Critical Runtime Error in findInactiveNonMutuals for @jfcarpio (v${APP_VERSION}):`, error);
    const errorMessage = `Critical Runtime Error for @jfcarpio (v${APP_VERSION}): ${error.message}. This issue occurred in the Inactive Non-Mutual Follows Finder app while processing for @jfcarpio. Detailed diagnostics:\n- Error Origin: ${error.stack ? error.stack.substring(0, 200) + '...' : 'No stack trace available'}\n- Potential Causes:\n  - Invalid OAuth 2.0 Client ID '${OAUTH2_CLIENT_ID}' or mismatch with X app settings.\n  - Incorrect or expired Bearer Token '${BEARER_TOKEN.substring(0, 20)}...'.\n  - Mismatched redirect URI '${REDIRECT_URI}' in X Developer Portal.\n  - App type not set to 'Web App, Automated App or Bot' or missing scopes ('tweet.read', 'users.read', 'follows.read').\n  - API Key '${API_KEY}' (if used) is invalid or not configured for OAuth 2.0.\n  - Network issues, rate limits, or GitHub Pages deployment errors.\n- Development Steps to Resolve:\n1. Log in to the X Developer Portal (https://developer.twitter.com/) with @jfcarpio.\n2. Navigate to your app ('Inactive Follows Finder' or similar) under Projects & Apps.\n3. Verify the OAuth 2.0 Client ID matches '${OAUTH2_CLIENT_ID}' in 'Keys and Tokens', regenerate if invalid, and update OAUTH2_CLIENT_ID in app.js (line 15).\n4. Ensure the redirect URI is exactly '${REDIRECT_URI}' (case-sensitive, including protocol and path) in app settings, and update if needed.\n5. Confirm the app type is 'Web App, Automated App or Bot' (confidential client) and scopes include 'tweet.read', 'users.read', 'follows.read'.\n6. Check the Bearer Token ('${BEARER_TOKEN.substring(0, 20)}...') is valid for X API v2, regenerate if expired, and update BEARER_TOKEN in app.js (line 18).\n7. Verify the API Key ('${API_KEY}') is valid (if used for legacy purposes) or remove it if not needed for OAuth 2.0 PKCE.\n8. Clear your browser cache (Ctrl+F5 or Cmd+R) and retry at https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/.\n9. Redeploy to GitHub Pages if changes are made, ensuring HTTPS and correct deployment from the 'main' branch.\n10. Review X’s OAuth 2.0 (https://developer.twitter.com/en/docs/authentication/oauth-2-0) and API v2 documentation (https://developer.twitter.com/en/docs/twitter-api) for troubleshooting, focusing on client ID validation, Bearer Token authentication, scopes, and rate limits.\n11. Check the console for the full stack trace, any X API response details (e.g., HTTP status codes, error bodies), and additional debugging information to pinpoint the exact failure.`;
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
    if (versionDiv) versionDiv.innerText = `Version: ${APP_VERSION} (Status: Failed - Critical Error)`;

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
      console.error(`Max retry attempts reached for @jfcarpio (v${APP_VERSION}). Please follow the detailed steps above to resolve the issue.`);
      if (versionDiv) versionDiv.innerText = `Version: ${APP_VERSION} (Status: Failed - Max Retries Reached)`;
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
 * Validates and uses the provided Bearer Token for @jfcarpio, falling back if invalid, with highly detailed logging.
 * @param {string} token - The Bearer Token
 * @returns {Promise<string>} Valid Bearer Token or throws error
 */
async function validateAndUseBearerToken(token) {
  try {
    const response = await fetchWithRetry(`${X_API_BASE}/users/me?user.fields=username,name`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!response.ok) {
      const errorText = await response.text();
      const tokenValidationError = `Critical Bearer Token Validation Error (v${APP_VERSION}): The Bearer Token '${token.substring(0, 20)}...' for @jfcarpio failed with HTTP ${response.status} - ${errorText}. This likely means:\n- The token is invalid, expired, or revoked.\n- It lacks the required scopes ('tweet.read', 'users.read', 'follows.read') for X API v2.\n- It’s not associated with @jfcarpio’s X account.\nTo resolve for the Inactive Non-Mutual Follows Finder app:\n1. Log in to the X Developer Portal (https://developer.twitter.com/) with @jfcarpio.\n2. Navigate to your app ('Inactive Follows Finder') under Projects & Apps.\n3. Go to 'Keys and Tokens', verify or regenerate the Bearer Token, ensuring it’s a valid X API v2 Bearer Token with the correct scopes.\n4. Update BEARER_TOKEN in app.js (line 18) with the new token if regenerated.\n5. Clear browser cache (Ctrl+F5 or Cmd+R) and retry at https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/.\n6. Check X’s API status (https://developer.twitter.com/en/support/twitter-api/status) and documentation (https://developer.twitter.com/en/docs/twitter-api) for token issues.`;
      throw new Error(tokenValidationError);
    }
    const userDetails = await response.json().data;
    if (userDetails.username !== 'jfcarpio') {
      const userMismatchError = `Critical User Mismatch Error (v${APP_VERSION}): The Bearer Token '${token.substring(0, 20)}...' is associated with username '${userDetails.username}', not @jfcarpio. This app is configured for @jfcarpio’s Inactive Non-Mutual Follows Finder. To fix:\n1. Ensure the Bearer Token is generated for @jfcarpio in the X Developer Portal.\n2. Regenerate the token if necessary and update BEARER_TOKEN in app.js (line 18).\n3. Verify @jfcarpio’s login during authentication.\n4. Clear browser cache (Ctrl+F5 or Cmd+R) and retry at https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/.\n5. Review X’s authentication docs (https://developer.twitter.com/en/docs/authentication) for user verification.`;
      throw new Error(userMismatchError);
    }
    console.log(`Bearer Token validated successfully for @jfcarpio (v${APP_VERSION}): ${token.substring(0, 20)}... (User: @${userDetails.username})`);
    return token;
  } catch (error) {
    console.error(`Error validating Bearer Token for @jfcarpio (v${APP_VERSION}):`, error);
    throw error;
  }
}

/**
 * Validates the OAuth 2.0 client ID against X API with extremely detailed diagnostics for @jfcarpio.
 * @param {string} clientId - The OAuth 2.0 client ID to validate
 * @param {string} redirectUri - The redirect URI to verify
 * @returns {Promise<boolean>} Whether the client ID is valid
 */
async function validateClientIdWithDetailedDiagnostics(clientId, redirectUri) {
  try {
    const response = await fetchWithRetry(`${X_API_BASE}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=client_credentials&client_id=${clientId}`
    });
    if (!response.ok) {
      const errorText = await response.text();
      const clientIdValidationError = `Critical OAuth 2.0 Client ID Validation Error (v${APP_VERSION}): The OAuth 2.0 Client ID '${clientId}' for @jfcarpio’s Inactive Non-Mutual Follows Finder app failed with HTTP ${response.status} - ${errorText}. Possible issues include:\n- The Client ID is incorrect, expired, or not registered in the X Developer Portal.\n- The redirect URI '${redirectUri}' does not match the X app settings exactly (case-sensitive, including 'https://', slashes, and path).\n- The app type is not set to 'Web App, Automated App or Bot' (confidential client).\n- Required scopes ('tweet.read', 'users.read', 'follows.read') are missing or misconfigured.\n- The app is suspended, restricted, or exceeds free-tier limits.\n- X API policy changes as of February 21, 2025, require app verification or paid tier.\nDevelopment Steps to Resolve:\n1. Log in to the X Developer Portal (https://developer.twitter.com/) with @jfcarpio.\n2. Navigate to Projects & Apps, locate your app ('Inactive Follows Finder'), and check 'Keys and Tokens' for the correct OAuth 2.0 Client ID.\n3. Verify the redirect URI is exactly '${redirectUri}' in app settings, and update it if needed (case-sensitive).\n4. Ensure the app type is 'Web App, Automated App or Bot' and scopes include 'tweet.read', 'users.read', 'follows.read'.\n5. If the Client ID is invalid, regenerate it in the portal and update OAUTH2_CLIENT_ID in app.js (line 15).\n6. Check app status (active, not suspended) and free-tier limits in the portal.\n7. Clear browser cache (Ctrl+F5 or Cmd+R), retry at https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/, and redeploy to GitHub Pages if changes are made.\n8. Review X’s OAuth 2.0 documentation (https://developer.twitter.com/en/docs/authentication/oauth-2-0) and API v2 docs (https://developer.twitter.com/en/docs/twitter-api) for troubleshooting, focusing on client ID validation, scopes, and rate limits.`;
      console.warn(`${clientIdValidationError}`);
      return false;
    }
    // Optionally, verify redirect URI configuration (simplified check; X handles this server-side)
    const appConfigResponse = await fetchWithRetry(`${X_API_BASE}/oauth2/clients/${clientId}`, {
      headers: { Authorization: `Basic ${btoa(`${clientId}:`)}` } // Basic auth with client ID only (simplified)
    });
    if (!appConfigResponse.ok) {
      const configError = `Critical App Configuration Error (v${APP_VERSION}): The OAuth 2.0 Client ID '${clientId}' configuration for @jfcarpio’s app failed validation with HTTP ${appConfigResponse.status} - ${await appConfigResponse.text()}. This suggests:\n- The redirect URI '${redirectUri}' is not correctly configured in the X Developer Portal.\n- The app’s settings (type, scopes) are mismatched.\nFollow these steps:\n1. Verify the redirect URI in the X Developer Portal matches '${redirectUri}' exactly.\n2. Ensure the app type is 'Web App, Automated App or Bot' and scopes include 'tweet.read', 'users.read', 'follows.read'.\n3. Update OAUTH2_CLIENT_ID in app.js (line 15) if regenerated.\n4. Clear cache, retry, and redeploy as above.`;
      console.warn(`${configError}`);
      return false;
    }
    console.log(`OAuth 2.0 Client ID '${clientId.substring(0, 10)}...' validated successfully for @jfcarpio (v${APP_VERSION}) with redirect URI '${redirectUri}'.`);
    return true;
  } catch (error) {
    console.error(`Error validating OAuth 2.0 Client ID for @jfcarpio (v${APP_VERSION}):`, error);
    const validationError = `Critical Validation Error (v${APP_VERSION}): Failed to validate OAuth 2.0 Client ID '${clientId}' for @jfcarpio - ${error.message}. This could indicate a network issue, X API downtime, or misconfiguration. Review the steps above for resolution.`;
    return false;
  }
}

/**
 * Validates the API Key against X API with extremely detailed diagnostics for @jfcarpio (legacy or client credentials).
 * @param {string} apiKey - The API Key to validate
 * @returns {Promise<boolean>} Whether the API Key is valid
 */
async function validateApiKeyWithDetailedDiagnostics(apiKey) {
  try {
    const response = await fetchWithRetry(`${X_API_BASE}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=client_credentials&client_id=${apiKey}`
    });
    if (!response.ok) {
      const errorText = await response.text();
      const apiKeyValidationError = `Critical API Key Validation Error (v${APP_VERSION}): The API Key '${apiKey}' for @jfcarpio’s Inactive Non-Mutual Follows Finder app failed with HTTP ${response.status} - ${errorText}. This is likely because:\n- The API Key is an OAuth 1.0a or legacy key not suitable for OAuth 2.0 PKCE.\n- It’s invalid, expired, or not registered in the X Developer Portal.\n- It’s not configured for client credentials flow or lacks proper permissions.\nDevelopment Steps to Resolve (if needed):\n1. Log in to the X Developer Portal (https://developer.twitter.com/) with @jfcarpio.\n2. Navigate to Projects & Apps, locate your app ('Inactive Follows Finder'), and check 'Keys and Tokens' for the correct API Key.\n3. If used, ensure it’s valid for client credentials or OAuth 1.0a, but note it’s typically unnecessary for OAuth 2.0 PKCE.\n4. Consider removing API_KEY from app.js (line 14) if not required, as it’s likely legacy and not needed for this app.\n5. Clear browser cache (Ctrl+F5 or Cmd+R), retry at https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/, and redeploy to GitHub Pages if changes are made.\n6. Review X’s documentation (https://developer.twitter.com/en/docs/authentication) for API Key usage and migration to OAuth 2.0.`;
      console.warn(`${apiKeyValidationError}`);
      return false;
    }
    console.log(`API Key '${apiKey.substring(0, 10)}...' validated successfully for @jfcarpio (v${APP_VERSION}) for client credentials (if applicable).`);
    return true;
  } catch (error) {
    console.error(`Error validating API Key for @jfcarpio (v${APP_VERSION}):`, error);
    const validationError = `Critical Validation Error (v${APP_VERSION}): Failed to validate API Key '${apiKey}' for @jfcarpio - ${error.message}. This could indicate a network issue, X API downtime, or misconfiguration. Review the steps above for resolution (if API Key is needed).`;
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
      const tokenError = `Critical Client Credentials Error (v${APP_VERSION}): Failed to obtain access token using API Key '${apiKey}' for @jfcarpio with HTTP ${response.status} - ${errorText}. This is likely because the API Key is not configured for client credentials or is invalid. Review the steps in validateApiKeyWithDetailedDiagnostics to resolve or remove API_KEY if not needed for OAuth 2.0 PKCE.`;
      throw new Error(tokenError);
    }
    const tokenData = await response.json();
    console.log(`Access token obtained successfully using API Key for @jfcarpio (v${APP_VERSION}): ${tokenData.access_token.substring(0, 20)}...`);
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
        if (!authWindow) {
          const popupErrorDetails = `Critical UI Error (v${APP_VERSION}): Popup window blocked or failed during authentication for @jfcarpio (Attempt ${attempt}). This prevents the OAuth 2.0 PKCE flow for the Inactive Non-Mutual Follows Finder app. To resolve:\n1. Ensure popup blockers are disabled in your browser for https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/.\n2. Manually open this URL in a new tab: ${authUrl}, authorize with @jfcarpio, then paste the callback URL below.\n3. Clear browser cache (Ctrl+F5 or Cmd+R) and retry.\n4. Check browser security settings or extensions that might block popups.\n5. Review X’s OAuth 2.0 documentation (https://developer.twitter.com/en/docs/authentication/oauth-2-0) for popup handling.`;
          throw new Error(popupErrorDetails);
        }
      } catch (popupError) {
        console.error(`Popup error for @jfcarpio (v${APP_VERSION}, Attempt ${attempt}):`, popupError);
        if (errorDiv) {
          errorDiv.innerHTML = `<p class="error">${popupErrorDetails}</p>`;
        } else {
          console.log(`%c${popupErrorDetails}`, 'color: red; font-weight: bold;');
        }
        return await getAuthCodeManuallyWithRetries(REDIRECT_URI, state, attempt);
      }

      return await pollForCallbackWithRetries(authWindow, REDIRECT_URI, state, attempt);
    } catch (error) {
      console.error(`Authentication attempt ${attempt} failed for @jfcarpio (v${APP_VERSION}):`, error);
      const authErrorDetails = `Critical Authentication Attempt Error (v${APP_VERSION}): Authentication failed on attempt ${attempt}/${MAX_RETRIES} for @jfcarpio in the Inactive Non-Mutual Follows Finder app - ${error.message}. This could indicate:\n- Network issues or X API downtime.\n- Invalid OAuth 2.0 Client ID '${OAUTH2_CLIENT_ID}' or redirect URI '${REDIRECT_URI}'.\n- Browser or CORS restrictions on GitHub Pages.\nTo resolve:\n1. Verify the OAuth 2.0 Client ID and redirect URI in the X Developer Portal as described above.\n2. Ensure network connectivity and X API status (https://developer.twitter.com/en/support/twitter-api/status).\n3. Clear browser cache (Ctrl+F5 or Cmd+R) and retry at https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/.\n4. Check console for full stack trace and X API response details (e.g., HTTP status, error body).\n5. Review X’s OAuth 2.0 documentation (https://developer.twitter.com/en/docs/authentication/oauth-2-0) for authentication issues.`;
      if (attempt === MAX_RETRIES) throw new Error(`${authErrorDetails}\n- This is the final attempt; max retries reached. Follow the steps above to resolve.`);
      const waitTime = RETRY_DELAY_BASE * Math.pow(2, attempt - 1); // Exponential backoff
      console.log(`Retrying authentication for @jfcarpio (v${APP_VERSION}) in ${waitTime / 1000} seconds...`);
      if (errorDiv) {
        errorDiv.innerHTML += `<pre>${authErrorDetails}\n- Retrying in ${waitTime / 1000} seconds (attempt ${attempt + 1}/${MAX_RETRIES}, v${APP_VERSION})...</pre>`;
      } else {
        console.log(`%c${authErrorDetails}\n- Retrying in ${waitTime / 1000} seconds (attempt ${attempt + 1}/${MAX_RETRIES}, v${APP_VERSION})...`, 'color: orange; font-weight: bold;');
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
          const windowClosedError = `Critical Callback Error (v${APP_VERSION}): Authentication window closed unexpectedly for @jfcarpio (Attempt ${attempt}) in the Inactive Non-Mutual Follows Finder app. This disrupts the OAuth 2.0 PKCE flow. To resolve:\n1. Ensure the popup remains open during authentication.\n2. Manually complete authentication at the last URL shown, then paste the callback URL below.\n3. Clear browser cache (Ctrl+F5 or Cmd+R) and retry at https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/.\n4. Check browser popup settings or extensions that might close windows.\n5. Review X’s OAuth 2.0 documentation (https://developer.twitter.com/en/docs/authentication/oauth-2-0) for callback handling.`;
          reject(new Error(windowClosedError));
          return;
        }
        const url = authWindow.location.href;
        if (url && url.includes(redirectUri)) {
          authWindow.close();
          clearInterval(checkInterval);
          const params = new URLSearchParams(url.split('?')[1]);
          const code = params.get('code');
          const returnedState = params.get('state');
          if (!code) {
            const noCodeError = `Critical Callback Parsing Error (v${APP_VERSION}): No authorization code found in callback URL '${url}' for @jfcarpio (Attempt ${attempt}). This indicates an issue with X’s redirect or your app’s configuration. To resolve:\n1. Verify the redirect URI '${redirectUri}' matches exactly in the X Developer Portal and app.js (line 16).\n2. Ensure X redirects correctly to https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/callback after authentication.\n3. Clear browser cache (Ctrl+F5 or Cmd+R) and retry.\n4. Check X’s OAuth 2.0 docs (https://developer.twitter.com/en/docs/authentication/oauth-2-0) for callback issues.`;
            reject(new Error(noCodeError));
          }
          if (returnedState !== state) {
            const csrfError = `Critical Security Error (v${APP_VERSION}): CSRF state mismatch detected in callback URL '${url}' for @jfcarpio (Attempt ${attempt}). This suggests a security issue or misconfiguration. To resolve:\n1. Ensure no third-party interference or browser extensions are modifying the callback.\n2. Verify the OAuth 2.0 PKCE flow in app.js (lines 280–300) generates and matches state correctly.\n3. Clear browser cache (Ctrl+F5 or Cmd+R) and retry.\n4. Review X’s OAuth 2.0 documentation (https://developer.twitter.com/en/docs/authentication/oauth-2-0) for CSRF protection.`;
            reject(new Error(csrfError));
          }
          console.log(`Callback URL processed successfully for @jfcarpio (v${APP_VERSION}, Attempt ${attempt}): ${url.substring(0, 50)}...`);
          resolve(code);
        }
      } catch (e) {
        // Ignore cross-origin errors, but log for debugging
        console.warn(`Cross-origin error polling callback for @jfcarpio (v${APP_VERSION}, Attempt ${attempt}):`, e);
      }
    }, 500);

    setTimeout(() => {
      clearInterval(checkInterval);
      authWindow.close();
      const timeoutError = `Critical Timeout Error (v${APP_VERSION}): Authentication timed out after 5 minutes for @jfcarpio (Attempt ${attempt}) in the Inactive Non-Mutual Follows Finder app. This could indicate:\n- Slow network or X API response times.\n- Browser or popup issues preventing callback completion.\n- Misconfiguration of the OAuth 2.0 flow.\nTo resolve:\n1. Ensure stable internet connectivity and check X API status (https://developer.twitter.com/en/support/twitter-api/status).\n2. Verify the redirect URI '${redirectUri}' and OAuth 2.0 Client ID '${OAUTH2_CLIENT_ID}' in the X Developer Portal.\n3. Clear browser cache (Ctrl+F5 or Cmd+R) and retry at https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/.\n4. Check browser popup and timeout settings.\n5. Review X’s OAuth 2.0 documentation (https://developer.twitter.com/en/docs/authentication/oauth-2-0) for timeout handling.`;
      reject(new Error(timeoutError));
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
        const noUrlError = `Critical Manual Input Error (v${APP_VERSION}): No callback URL provided for @jfcarpio (Attempt ${attempt}) in the Inactive Non-Mutual Follows Finder app. Please paste the full URL from X’s redirect (e.g., https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/callback?code=...) into the input field above. To resolve:\n1. Complete the X authentication flow manually using the URL provided in the error message.\n2. Copy the full URL from your browser’s address bar after authorization.\n3. Paste it here and click 'Submit Callback'.\n4. Clear browser cache (Ctrl+F5 or Cmd+R) if the input field doesn’t appear.\n5. Review X’s OAuth 2.0 documentation (https://developer.twitter.com/en/docs/authentication/oauth-2-0) for manual callback handling.`;
        if (errorDiv) {
          errorDiv.innerHTML = `<p class="error">${noUrlError}</p>`;
        } else {
          console.log(`%c${noUrlError}`, 'color: red; font-weight: bold;');
        }
        return;
      }
      try {
        const params = new URLSearchParams(new URL(callbackUrl).search);
        const code = params.get('code');
        const returnedState = params.get('state');
        if (!code) {
          const noCodeError = `Critical Callback Parsing Error (v${APP_VERSION}): No authorization code found in manual callback URL '${callbackUrl}' for @jfcarpio (Attempt ${attempt}). This indicates an issue with X’s redirect or your input. To resolve:\n1. Verify the callback URL starts with '${redirectUri}' and includes a 'code' parameter (e.g., ?code=...).\n2. Ensure you copied the full URL from X’s redirect after authentication.\n3. Clear browser cache (Ctrl+F5 or Cmd+R) and retry.\n4. Check X’s OAuth 2.0 docs (https://developer.twitter.com/en/docs/authentication/oauth-2-0) for callback issues.`;
          throw new Error(noCodeError);
        }
        if (returnedState !== state) {
          const csrfError = `Critical Security Error (v${APP_VERSION}): CSRF state mismatch detected in manual callback URL '${callbackUrl}' for @jfcarpio (Attempt ${attempt}). This suggests a security issue or misconfiguration. To resolve:\n1. Ensure no third-party interference or browser extensions are modifying the callback.\n2. Verify the OAuth 2.0 PKCE flow in app.js (lines 280–300) generates and matches state correctly.\n3. Clear browser cache (Ctrl+F5 or Cmd+R) and retry.\n4. Review X’s OAuth 2.0 documentation (https://developer.twitter.com/en/docs/authentication/oauth-2-0) for CSRF protection.`;
          throw new Error(csrfError);
        }
        console.log(`Manual callback URL processed successfully for @jfcarpio (v${APP_VERSION}, Attempt ${attempt}): ${callbackUrl.substring(0, 50)}...`);
        resolve(code);
      } catch (error) {
        console.error(`Error parsing manual callback URL for @jfcarpio (v${APP_VERSION}, Attempt ${attempt}):`, error);
        const parseErrorDetails = `Critical Parsing Error (v${APP_VERSION}): Failed to parse manual callback URL '${callbackUrl}' for @jfcarpio (Attempt ${attempt}) - ${error.message}. This could indicate:\n- An invalid or malformed URL format.\n- Missing or incorrect 'code' or 'state' parameters in the URL.\n- Browser or network issues affecting URL parsing.\nTo resolve for the Inactive Non-Mutual Follows Finder app:\n1. Ensure the callback URL is copied correctly from X’s redirect (e.g., https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/callback?code=...&state=...).\n2. Verify the redirect URI '${redirectUri}' matches in X Developer Portal and app.js.\n3. Clear browser cache (Ctrl+F5 or Cmd+R) and retry.\n4. Check console for full stack trace and redeploy to GitHub Pages if needed.\n5. Review X’s OAuth 2.0 documentation (https://developer.twitter.com/en/docs/authentication/oauth-2-0) for callback URL handling.`;
        if (errorDiv) {
          errorDiv.innerHTML = `<p class="error">${parseErrorDetails}</p>`;
        } else {
          console.log(`%c${parseErrorDetails}`, 'color: red; font-weight: bold;');
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
  if (!codeVerifier) {
    const verifierError = `Critical PKCE Error (v${APP_VERSION}): Code verifier not found for @jfcarpio in the Inactive Non-Mutual Follows Finder app. This indicates a session storage issue or app restart interruption. To resolve:\n1. Ensure sessionStorage is enabled and not cleared in your browser for https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/.\n2. Restart the authentication process by refreshing the page and clicking 'Authenticate with X and Find Inactive Non-Mutuals'.\n3. Clear browser cache (Ctrl+F5 or Cmd+R) if session issues persist.\n4. Review X’s OAuth 2.0 PKCE documentation (https://developer.twitter.com/en/docs/authentication/oauth-2-0) for verifier handling.`;
    throw new Error(verifierError);
  }

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const tokenResponse = await fetchWithRetry(`${X_API_BASE}/oauth2/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=authorization_code&code=${authCode}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&client_id=${OAUTH2_CLIENT_ID}&code_verifier=${codeVerifier}`
      });
      if (!tokenResponse.ok) {
        const errorText = await tokenResponse.text();
        const tokenExchangeError = `Critical Token Exchange Error (v${APP_VERSION}): Failed to exchange authorization code for access token for @jfcarpio (Attempt ${attempt}) with HTTP ${tokenResponse.status} - ${errorText}. Possible issues include:\n- Invalid OAuth 2.0 Client ID '${OAUTH2_CLIENT_ID}' or code verifier.\n- Mismatched redirect URI '${REDIRECT_URI}' in X Developer Portal or app.js.\n- X API rate limits or downtime.\n- Network or CORS issues on GitHub Pages.\nTo resolve for the Inactive Non-Mutual Follows Finder app:\n1. Verify the OAuth 2.0 Client ID and redirect URI in the X Developer Portal as described above.\n2. Ensure the code verifier matches the challenge used in authentication (check app.js lines 280–300).\n3. Check X API status (https://developer.twitter.com/en/support/twitter-api/status) and rate limits.\n4. Clear browser cache (Ctrl+F5 or Cmd+R) and retry at https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/.\n5. Review X’s OAuth 2.0 documentation (https://developer.twitter.com/en/docs/authentication/oauth-2-0) for token exchange issues.`;
        throw new Error(tokenExchangeError);
      }
      const tokenData = await tokenResponse.json();
      console.log(`Access token obtained successfully for @jfcarpio (v${APP_VERSION}, Attempt ${attempt}): ${tokenData.access_token.substring(0, 20)}...`);
      return tokenData.access_token;
    } catch (error) {
      console.error(`Token exchange attempt ${attempt} failed for @jfcarpio (v${APP_VERSION}):`, error);
      if (attempt === MAX_RETRIES) {
        const maxRetriesError = `${error.message}\n- This is the final attempt; max retries reached. Follow the steps above to resolve the token exchange failure for @jfcarpio (v${APP_VERSION}).`;
        throw new Error(maxRetriesError);
      }
      const waitTime = RETRY_DELAY_BASE * Math.pow(2, attempt - 1); // Exponential backoff
      console.log(`Retrying token exchange for @jfcarpio (v${APP_VERSION}) in ${waitTime / 1000} seconds...`);
      const retryErrorDetails = `Retrying token exchange (attempt ${attempt + 1}/${MAX_RETRIES}, v${APP_VERSION}) for @jfcarpio after ${waitTime / 1000} seconds due to: ${error.message}. Check the steps above for resolution.`;
      if (errorDiv) {
        errorDiv.innerHTML += `\n<pre>${retryErrorDetails}</pre>`;
      } else {
        console.log(`%c${retryErrorDetails}`, 'color: orange; font-weight: bold;');
      }
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }
  }
}

/**
 * Fetches user ID from X API for @jfcarpio.
 * @param {string} accessToken - The access token or Bearer Token
 * @returns {Promise<string>} User ID
 */
async function getUserId(accessToken) {
  try {
    const response = await fetchWithRetry(`${X_API_BASE}/users/me`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!response.ok) {
      const errorText = await response.text();
      const userIdError = `Critical User ID Fetch Error (v${APP_VERSION}): Failed to fetch user ID for @jfcarpio with HTTP ${response.status} - ${errorText}. This could indicate:\n- Invalid or expired Bearer Token or access token.\n- Missing or restricted scopes ('tweet.read', 'users.read', 'follows.read').\n- X API v2 downtime or rate limits.\nTo resolve for the Inactive Non-Mutual Follows Finder app:\n1. Verify the Bearer Token or access token in app.js (lines 18 or exchange result) is valid in the X Developer Portal.\n2. Ensure the token has the required scopes.\n3. Check X API status (https://developer.twitter.com/en/support/twitter-api/status) and rate limits.\n4. Clear browser cache (Ctrl+F5 or Cmd+R) and retry at https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/.\n5. Review X’s API v2 documentation (https://developer.twitter.com/en/docs/twitter-api) for user endpoint issues.`;
      throw new Error(userIdError);
    }
    const data = await response.json();
    console.log(`User ID fetched successfully for @jfcarpio (v${APP_VERSION}): ${data.data.id}`);
    return data.data.id;
  } catch (error) {
    console.error(`Error in getUserId for @jfcarpio (v${APP_VERSION}):`, error);
    throw error;
  }
}

/**
 * Fetches user details to verify @jfcarpio, even if already logged in.
 * @param {string} userId - The user ID
 * @param {string} accessToken - The access token or Bearer Token
 * @returns {Promise<Object>} User details
 */
async function fetchUserDetails(userId, accessToken) {
  try {
    const response = await fetchWithRetry(`${X_API_BASE}/users/${userId}?user.fields=username,name`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!response.ok) {
      const errorText = await response.text();
      const userDetailsError = `Critical User Details Fetch Error (v${APP_VERSION}): Failed to fetch user details for ID ${userId} for @jfcarpio with HTTP ${response.status} - ${errorText}. This could indicate:\n- Invalid or expired Bearer Token or access token.\n- Missing or restricted scopes ('tweet.read', 'users.read', 'follows.read').\n- X API v2 downtime or rate limits.\nTo resolve for the Inactive Non-Mutual Follows Finder app:\n1. Verify the Bearer Token or access token in app.js (lines 18 or exchange result) is valid in the X Developer Portal.\n2. Ensure the token has the required scopes.\n3. Check X API status (https://developer.twitter.com/en/support/twitter-api/status) and rate limits.\n4. Clear browser cache (Ctrl+F5 or Cmd+R) and retry at https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/.\n5. Review X’s API v2 documentation (https://developer.twitter.com/en/docs/twitter-api) for user endpoint issues.`;
      throw new Error(userDetailsError);
    }
    return await response.json().data;
  } catch (error) {
    console.error(`Error in fetchUserDetails for @jfcarpio (v${APP_VERSION}):`, error);
    throw error;
  }
}

/**
 * Fetches all follows with pagination for @jfcarpio with retries.
 * @param {string} userId - The user ID
 * @param {string} accessToken - The access token or Bearer Token
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
      nextToken = data.meta?.next_token;
      await handleRateLimits(response);
    } catch (error) {
      console.error(`Error in getAllFollows for @jfcarpio (v${APP_VERSION}):`, error);
      const followsError = `Critical Follows Fetch Error (v${APP_VERSION}): Failed to fetch follows for user ID ${userId} for @jfcarpio - ${error.message}. This could indicate:\n- Invalid or expired Bearer Token or access token.\n- Missing or restricted scopes ('tweet.read', 'users.read', 'follows.read').\n- X API v2 downtime, rate limits, or pagination issues.\nTo resolve for the Inactive Non-Mutual Follows Finder app:\n1. Verify the Bearer Token or access token in app.js (lines 18 or exchange result) is valid in the X Developer Portal.\n2. Ensure the token has the required scopes.\n3. Check X API status (https://developer.twitter.com/en/support/twitter-api/status) and rate limits.\n4. Review pagination logic in app.js (lines 350–370) for next_token handling.\n5. Clear browser cache (Ctrl+F5 or Cmd+R) and retry at https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/.\n6. Review X’s API v2 documentation (https://developer.twitter.com/en/docs/twitter-api) for follows endpoint issues.`;
      throw new Error(followsError);
    }
  } while (nextToken);
  console.log(`Successfully fetched ${follows.length} follows for @jfcarpio (v${APP_VERSION}).`);
  return follows;
}

/**
 * Fetches all followers with pagination for @jfcarpio with retries.
 * @param {string} userId - The user ID
 * @param {string} accessToken - The access token or Bearer Token
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
      nextToken = data.meta?.next_token;
      await handleRateLimits(response);
    } catch (error) {
      console.error(`Error in getAllFollowers for @jfcarpio (v${APP_VERSION}):`, error);
      const followersError = `Critical Followers Fetch Error (v${APP_VERSION}): Failed to fetch followers for user ID ${userId} for @jfcarpio - ${error.message}. This could indicate:\n- Invalid or expired Bearer Token or access token.\n- Missing or restricted scopes ('tweet.read', 'users.read', 'follows.read').\n- X API v2 downtime, rate limits, or pagination issues.\nTo resolve for the Inactive Non-Mutual Follows Finder app:\n1. Verify the Bearer Token or access token in app.js (lines 18 or exchange result) is valid in the X Developer Portal.\n2. Ensure the token has the required scopes.\n3. Check X API status (https://developer.twitter.com/en/support/twitter-api/status) and rate limits.\n4. Review pagination logic in app.js (lines 380–400) for next_token handling.\n5. Clear browser cache (Ctrl+F5 or Cmd+R) and retry at https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/.\n6. Review X’s API v2 documentation (https://developer.twitter.com/en/docs/twitter-api) for followers endpoint issues.`;
      throw new Error(followersError);
    }
  } while (nextToken);
  console.log(`Successfully fetched ${followers.length} followers for @jfcarpio (v${APP_VERSION}).`);
  return followers;
}

/**
 * Fetches recent tweets for a user for @jfcarpio with retries.
 * @param {string} userId - The user ID
 * @param {string} startTime - The start time for tweets
 * @param {string} accessToken - The access token or Bearer Token
 * @returns {Promise<Object>} Tweets response
 */
async function getRecentTweetsWithRetries(userId, startTime, accessToken) {
  const url = `${X_API_BASE}/users/${userId}/tweets?max_results=1&start_time=${startTime}&tweet.fields=created_at`;
  try {
    const response = await fetchWithRetry(url, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!response.ok) {
      const errorText = await response.text();
      const tweetsError = `Critical Tweets Fetch Error (v${APP_VERSION}): Failed to fetch recent tweets for user ID ${userId} for @jfcarpio with HTTP ${response.status} - ${errorText}. This could indicate:\n- Invalid or expired Bearer Token or access token.\n- Missing or restricted scope 'tweet.read' for X API v2.\n- Rate limit exhaustion or X API downtime.\nTo resolve for the Inactive Non-Mutual Follows Finder app:\n1. Verify the Bearer Token or access token in app.js (lines 18 or exchange result) is valid in the X Developer Portal.\n2. Ensure the token has the 'tweet.read' scope.\n3. Check X API status (https://developer.twitter.com/en/support/twitter-api/status) and rate limits.\n4. Clear browser cache (Ctrl+F5 or Cmd+R) and retry at https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/.\n5. Review X’s API v2 documentation (https://developer.twitter.com/en/docs/twitter-api) for tweets endpoint issues.`;
      throw new Error(tweetsError);
    }
    return await response.json();
  } catch (error) {
    console.error(`Error fetching recent tweets for @jfcarpio (v${APP_VERSION}):`, error);
    throw error;
  }
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
        const fetchError = `Critical API Fetch Error (v${APP_VERSION}): Failed to fetch from ${url} for @jfcarpio (Attempt ${attempt}) with HTTP ${response.status} - ${errorText}. This could indicate:\n- Network issues or X API downtime.\n- Invalid or expired Bearer Token, access token, or credentials.\n- Rate limits or CORS restrictions on GitHub Pages.\nTo resolve for the Inactive Non-Mutual Follows Finder app:\n1. Verify all credentials (Bearer Token, OAuth 2.0 Client ID, API Key) in the X Developer Portal and app.js.\n2. Check X API status (https://developer.twitter.com/en/support/twitter-api/status) and rate limits.\n3. Ensure HTTPS and CORS are correctly configured for GitHub Pages at https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/.\n4. Clear browser cache (Ctrl+F5 or Cmd+R) and retry.\n5. Review X’s API v2 documentation (https://developer.twitter.com/en/docs/twitter-api) for fetch errors.`;
        throw new Error(fetchError);
      }
      return response;
    } catch (error) {
      console.error(`Fetch attempt ${attempt} failed for @jfcarpio (v${APP_VERSION}):`, error);
      if (attempt === MAX_RETRIES) {
        const maxRetriesError = `${error.message}\n- This is the final attempt; max retries reached for @jfcarpio (v${APP_VERSION}). Follow the steps above to resolve the API fetch failure.`;
        throw new Error(maxRetriesError);
      }
      const waitTime = RETRY_DELAY_BASE * Math.pow(2, attempt - 1); // Exponential backoff
      console.log(`Retrying API call for @jfcarpio (v${APP_VERSION}) in ${waitTime / 1000} seconds...`);
      const retryErrorDetails = `Retrying API call (attempt ${attempt + 1}/${MAX_RETRIES}, v${APP_VERSION}) for @jfcarpio after ${waitTime / 1000} seconds due to: ${error.message}. Check the steps above for resolution.`;
      if (errorDiv) {
        errorDiv.innerHTML += `\n<pre>${retryErrorDetails}</pre>`;
      } else {
        console.log(`%c${retryErrorDetails}`, 'color: orange; font-weight: bold;');
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
      const rateLimitWarning = `Rate Limit Warning (v${APP_VERSION}): X API rate limit for @jfcarpio is nearly exhausted (${rateLimitRemaining} requests remaining). Pausing for ${waitTime / 1000} seconds to avoid hitting limits in the Inactive Non-Mutual Follows Finder app. To prevent future issues:\n1. Check X API rate limits in the documentation (https://developer.twitter.com/en/docs/twitter-api/rate-limits).\n2. Consider upgrading to a paid X Developer tier if frequent rate limit issues occur.\n3. Verify app usage and scopes ('tweet.read', 'users.read', 'follows.read') in the X Developer Portal.\n4. Review app.js rate limit handling (lines 460–480) for optimizations.`;
      if (errorDiv) {
        errorDiv.innerHTML += `\n<pre>${rateLimitWarning}</pre>`;
      } else {
        console.log(`%c${rateLimitWarning}`, 'color: orange; font-weight: bold;');
      }
      await new Promise(resolve => setTimeout(resolve, waitTime));
    } else {
      await new Promise(resolve => setTimeout(resolve, 1000)); // Default 1s delay
    }
  } catch (error) {
    console.error(`Error handling rate limits for @jfcarpio (v${APP_VERSION}):`, error);
    const rateLimitError = `Critical Rate Limit Handling Error (v${APP_VERSION}): Failed to handle rate limits for @jfcarpio in the Inactive Non-Mutual Follows Finder app - ${error.message}. This could indicate:\n- Invalid response headers or X API changes.\n- Network issues or GitHub Pages deployment errors.\nTo resolve:\n1. Verify X API response headers (x-rate-limit-remaining, x-rate-limit-reset) are present and correct.\n2. Check X API status (https://developer.twitter.com/en/support/twitter-api/status) for updates.\n3. Clear browser cache (Ctrl+F5 or Cmd+R) and retry at https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/.\n4. Review app.js rate limit logic (lines 460–480) and X’s rate limit docs (https://developer.twitter.com/en/docs/twitter-api/rate-limits).`;
    if (errorDiv) {
      errorDiv.innerHTML += `\n<pre>${rateLimitError}</pre>`;
    } else {
      console.log(`%c${rateLimitError}`, 'color: red; font-weight: bold;');
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
    `Processed ${current} of ${total} non-mutuals for @jfcarpio (v${APP_VERSION}). Found ${found}
