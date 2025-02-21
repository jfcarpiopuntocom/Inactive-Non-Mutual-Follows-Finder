// Constants for clarity and maintainability
const X_API_BASE = 'https://api.twitter.com/2';
const CLIENT_ID = 'QlK4UFjcTMT9vHFtUZho90YIp'; // Your X app client ID
const REDIRECT_URI = 'https://jfcarpiopuntocom.github.io/Inactive-Non-Mutual-Follows-Finder/callback'; // Your live GitHub Pages URL
const ACCESS_TOKEN = '11859152-XTKsuXYZkqAd0djHHqRfmnMaiN3n6rcOgMmLjyLY8'; // Your provided X access token
const MAX_RETRIES = 5; // Increased retries for robustness
const RETRY_DELAY_BASE = 5000; // Increased to 5 seconds to prevent rapid looping
const MAX_RETRY_ATTEMPTS = 3; // Limit total retry attempts to prevent infinite loops

let retryCount = 0; // Track total retry attempts

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
    { el: submitCallbackButton, id: 'submitCallback' }
  ];
  const missingElements = requiredElements.filter(({ el }) => el === null).map(({ id }) => id);
  if (missingElements.length > 0) {
    console.error('DOM elements missing for @jfcarpio app:', missingElements);
    const errorMessage = `Error: Missing DOM elements (${missingElements.join(', ')}) for @jfcarpio. Please refresh, check console, ensure index.html matches this version, and clear browser cache.`;
    if (errorDiv) {
      errorDiv.innerHTML = `<pre>${errorMessage}</pre>`;
    } else {
      console.log(`%c${errorMessage}`, 'color: red; font-weight: bold;');
    }
    if (startButton) startButton.disabled = false;
    return;
  }

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
    console.log('Attempting to use access token for @jfcarpio...');
    try {
      accessToken = await validateAndUseAccessToken(ACCESS_TOKEN);
      console.log('Access token validated and used for @jfcarpio:', accessToken);
      progressDiv.innerHTML = `Authenticated as: @jfcarpio (using access token)`;
    } catch (tokenError) {
      console.warn('Access token failed for @jfcarpio:', tokenError.message);
      errorDiv.innerHTML += `<pre>Warning: Access token invalid or expired for @jfcarpio - ${tokenError.message}. Falling back to OAuth 2.0 PKCE authentication.</pre>`;
      console.log('Falling back to OAuth 2.0 PKCE for @jfcarpio...');

      // Step 2: Validate client ID before OAuth flow
      console.log('Validating client ID for @jfcarpio...');
      const isClientIdValid = await validateClientId();
      if (!isClientIdValid) {
        throw new Error('Invalid client ID for @jfcarpio. Please verify your X app credentials in the X Developer Portal and update CLIENT_ID in app.js.');
      }
      console.log('Client ID validated for @jfcarpio.');

      // Step 3: Initiate OAuth 2.0 PKCE authentication flow for @jfcarpio, handling already logged-in state
      console.log('Starting X authentication for @jfcarpio (reconfirming even if already logged in)...');
      authCode = await initiateAuthFlowWithRetries();
      console.log('Authorization code obtained for @jfcarpio:', authCode);

      // Step 4: Exchange code for access token with failsafes
      accessToken = await exchangeCodeForTokenWithRetries(authCode);
      console.log('Successfully authenticated with X for @jfcarpio via OAuth. Access token:', accessToken);
      progressDiv.innerHTML = `Authenticated as: @jfcarpio (reconfirmed via OAuth)`;
    }

    // Step 5: Fetch and verify user ID for @jfcarpio
    console.log('Fetching user ID for @jfcarpio...');
    const userId = await getUserId(accessToken);
    console.log('User ID for @jfcarpio obtained:', userId);

    // Verify X account usage (ensure it’s @jfcarpio, even if already logged in)
    console.log('Verifying X account details for @jfcarpio (reconfirming identity)...');
    const userDetails = await fetchUserDetails(userId, accessToken);
    if (userDetails.username !== 'jfcarpio') {
      throw new Error('This app is configured for @jfcarpio, but the authenticated account does not match. Please log in with @jfcarpio.');
    }
    console.log('Verified X account: @jfcarpio (reconfirmed)');
    progressDiv.innerHTML = `Authenticated as: @${userDetails.username} (reconfirmed)`;

    // Step 6: Fetch follows and followers for @jfcarpio
    progressDiv.innerHTML = 'Fetching follows for @jfcarpio...';
    console.log('Fetching follows for @jfcarpio...');
    const follows = await getAllFollowsWithRetries(userId, accessToken);
    console.log('Follows for @jfcarpio fetched:', follows.length);

    progressDiv.innerHTML = 'Fetching followers for @jfcarpio...';
    console.log('Fetching followers for @jfcarpio...');
    const followers = await getAllFollowersWithRetries(userId, accessToken);
    console.log('Followers for @jfcarpio fetched:', followers.length);

    // Step 7: Identify non-mutuals for @jfcarpio
    console.log('Identifying non-mutuals for @jfcarpio...');
    const followerIds = new Set(followers.map(follower => follower.id));
    const nonMutuals = follows.filter(follow => !followerIds.has(follow.id));
    console.log('Non-mutuals for @jfcarpio identified:', nonMutuals.length);

    // Step 8: Check inactivity for non-mutuals (expanded scope)
    const inactiveNonMutuals = [];
    const fourMonthsAgo = new Date();
    fourMonthsAgo.setMonth(fourMonthsAgo.getMonth() - 4);
    const startTime = fourMonthsAgo.toISOString();

    progressDiv.innerHTML = 'Checking non-mutuals for inactivity for @jfcarpio...';
    console.log('Checking inactivity for non-mutuals of @jfcarpio...');
    for (let i = 0; i < Math.min(nonMutuals.length, 10000) && inactiveNonMutuals.length < 3000; i++) {
      const user = nonMutuals[i];
      try {
        console.log(`Checking user ${user.id} (${user.username}) for @jfcarpio...`);
        const tweets = await getRecentTweetsWithRetries(user.id, startTime, accessToken);
        if (tweets.meta.result_count === 0) {
          inactiveNonMutuals.push(user);
          console.log(`User ${user.id} (${user.username}) is inactive for @jfcarpio.`);
        } else {
          console.log(`User ${user.id} (${user.username}) is active for @jfcarpio.`);
        }
      } catch (error) {
        console.error(`Error checking user ${user.id} (${user.username}) for @jfcarpio:`, error);
        errorDiv.innerHTML += `\n<pre>Warning: Skipped user ${user.username} (ID: ${user.id}) due to error - ${error.message}. Check console for details.</pre>`;
      }
      updateProgress(i + 1, nonMutuals.length, inactiveNonMutuals.length);
      await handleRateLimits();
    }

    // Step 9: Display results professionally for @jfcarpio
    console.log('Displaying results for @jfcarpio...');
    displayResults(inactiveNonMutuals, userId);
  } catch (error) {
    console.error('Error in findInactiveNonMutuals for @jfcarpio:', error);
    const errorMessage = `Critical Error for @jfcarpio: ${error.message}. Check the console for detailed bug report, including stack trace and error context.`;
    if (errorDiv) {
      // Prevent rapid updates by checking if the last message matches
      const currentError = errorDiv.innerHTML.trim();
      if (!currentError.includes(errorMessage)) {
        errorDiv.innerHTML = `<pre>${errorMessage}</pre>`;
      } else {
        console.warn('Duplicate error prevented for @jfcarpio:', errorMessage);
      }
    } else {
      console.log(`%c${errorMessage}`, 'color: red; font-weight: bold;');
    }
    retryButton.style.display = 'block';

    // Limit total retries to prevent infinite loops
    if (retryCount < MAX_RETRY_ATTEMPTS && (error.message.includes('Authentication') || error.message.includes('token') || error.message.includes('access') || error.message.includes('client') || error.message.includes('HTTP'))) {
      retryCount++;
      console.log(`Retry attempt ${retryCount}/${MAX_RETRY_ATTEMPTS} for @jfcarpio...`);
      const waitTime = RETRY_DELAY_BASE * Math.pow(2, retryCount - 1); // Exponential backoff
      setTimeout(() => {
        findInactiveNonMutuals();
      }, waitTime);
    } else {
      console.error('Max retry attempts reached for @jfcarpio. Please check credentials and retry manually.');
      errorDiv.innerHTML += `\n<pre>Max retries reached for @jfcarpio. Please verify your Access Token, API Key, and X app settings in the X Developer Portal, then click "Retry Authentication" or refresh the page.</pre>`;
    }
  } finally {
    startButton.disabled = false;
    startButton.innerText = 'Authenticate with X and Find Inactive Non-Mutuals';
    loadingDiv.style.display = 'none';
    instructionsDiv.style.display = 'none';
  }
}

/**
 * Validates and uses the provided access token for @jfcarpio, falling back if invalid.
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
