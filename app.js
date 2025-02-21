// Constants for clarity and maintainability
const X_API_BASE = 'https://api.twitter.com/2';
const CLIENT_ID = 'QlK4UFjcTMT9vHFtUZho90YIp'; // Your X app client ID (verify in X Developer Portal)
const REDIRECT_URI = 'https://yourgithubusername.github.io/inactive-follows/callback'; // Replace with your GitHub Pages URL

// Main function to find inactive non-mutuals for @jfcarpio
async function findInactiveNonMutuals() {
  const startButton = document.getElementById('startButton');
  const retryButton = document.getElementById('retryButton');
  const progressDiv = document.getElementById('progress');
  const resultsDiv = document.getElementById('results');
  const errorDiv = document.getElementById('error');
  const loadingDiv = document.getElementById('loading');
  const instructionsDiv = document.getElementById('instructions');
  const callbackInput = document.getElementById('callbackUrl');
  const submitCallbackButton = document.getElementById('submitCallback');

  let authCode = null;

  // Reset UI state
  startButton.disabled = true;
  retryButton.style.display = 'none';
  startButton.innerText = 'Authenticating with X...';
  progressDiv.innerHTML = '';
  resultsDiv.innerHTML = '';
  errorDiv.innerHTML = '';
  loadingDiv.style.display = 'block';
  instructionsDiv.style.display = 'block';

  try {
    // Step 1: Initiate OAuth 2.0 PKCE authentication flow for @jfcarpio
    console.log('Starting X authentication for @jfcarpio (handling already logged-in state)...');
    authCode = await initiateAuthFlow();
    console.log('Authorization code obtained for @jfcarpio:', authCode);

    // Step 2: Exchange code for access token with failsafes
    const accessToken = await exchangeCodeForToken(authCode);
    console.log('Successfully authenticated with X for @jfcarpio. Access token:', accessToken);

    // Step 3: Fetch and verify user ID for @jfcarpio
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

    // Step 4: Fetch follows and followers for @jfcarpio
    progressDiv.innerHTML = 'Fetching follows for @jfcarpio...';
    console.log('Fetching follows for @jfcarpio...');
    const follows = await getAllFollows(userId, accessToken);
    console.log('Follows for @jfcarpio fetched:', follows.length);

    progressDiv.innerHTML = 'Fetching followers for @jfcarpio...';
    console.log('Fetching followers for @jfcarpio...');
    const followers = await getAllFollowers(userId, accessToken);
    console.log('Followers for @jfcarpio fetched:', followers.length);

    // Step 5: Identify non-mutuals for @jfcarpio
    console.log('Identifying non-mutuals for @jfcarpio...');
    const followerIds = new Set(followers.map(follower => follower.id));
    const nonMutuals = follows.filter(follow => !followerIds.has(follow.id));
    console.log('Non-mutuals for @jfcarpio identified:', nonMutuals.length);

    // Step 6: Check inactivity for non-mutuals (expanded scope)
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
        const tweets = await getRecentTweets(user.id, startTime, accessToken);
        if (tweets.meta.result_count === 0) {
          inactiveNonMutuals.push(user);
          console.log(`User ${user.id} (${user.username}) is inactive for @jfcarpio.`);
        } else {
          console.log(`User ${user.id} (${user.username}) is active for @jfcarpio.`);
        }
      } catch (error) {
        console.error(`Error checking user ${user.id} (${user.username}) for @jfcarpio:`, error);
        errorDiv.innerHTML += `<p class="error">Warning: Skipped user ${user.username} (ID: ${user.id}) due to error - ${error.message}. Check console for details.</p>`;
      }
      updateProgress(i + 1, nonMutuals.length, inactiveNonMutuals.length);
      await handleRateLimits();
    }

    // Step 7: Display results professionally for @jfcarpio
    console.log('Displaying results for @jfcarpio...');
    displayResults(inactiveNonMutuals, userId);
  } catch (error) {
    console.error('Error in findInactiveNonMutuals for @jfcarpio:', error);
    errorDiv.innerHTML = `<p class="error">Critical Error for @jfcarpio: ${error.message}. Check the console for detailed bug report, including stack trace and error context.</p>`;
    retryButton.style.display = 'block';
    // Retry authentication automatically if it’s an authentication-related error
    if (error.message.includes('Authentication') || error.message.includes('token')) {
      console.log('Attempting to retry authentication automatically...');
      setTimeout(() => findInactiveNonMutuals(), 2000); // Retry after 2 seconds
    }
  } finally {
    startButton.disabled = false;
    startButton.innerText = 'Authenticate with X and Find Inactive Non-Mutuals';
    loadingDiv.style.display = 'none';
    instructionsDiv.style.display = 'none';
  }
}

/**
 * Initiates OAuth 2.0 PKCE authentication flow for @jfcarpio, handling already logged-in state.
 * @returns {Promise<string>} Authorization code
 */
async function initiateAuthFlow() {
  const state = generateRandomString(16); // CSRF protection
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);

  // Use prompt=login to force reconfirmation, even if already logged in
  const authUrl = `${X_API_BASE}/oauth2/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=tweet.read%20users.read%20follows.read&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256&prompt=login`;
  console.log('Redirecting to X for authentication (reconfirming @jfcarpio). Open this URL:', authUrl);

  let authWindow;
  try {
    authWindow = window.open(authUrl, '_blank', 'width=600,height=600');
    if (!authWindow) throw new Error('Popup blocked. Please open this URL manually:', authUrl);
  } catch (error) {
    console.error('Popup error for @jfcarpio:', error);
    errorDiv.innerHTML = `<p class="error">Popup blocked or failed. Please open this URL manually: <a href="${authUrl}" target="_blank">${authUrl}</a>, authorize with @jfcarpio, then paste the callback URL below.</p>`;
    return await getAuthCodeManually(REDIRECT_URI, state);
  }

  return await pollForCallback(authWindow, REDIRECT_URI, state);
}

/**
 * Polls for the callback URL in the authentication window, handling already logged-in state.
 * @param {Window} authWindow - The authentication window
 * @param {string} redirectUri - The redirect URI
 * @param {string} state - CSRF state
 * @returns {Promise<string>} Authorization code
 */
async function pollForCallback(authWindow, redirectUri, state) {
  return new Promise((resolve, reject) => {
    let checkInterval = setInterval(async () => {
      try {
        if (authWindow.closed) {
          clearInterval(checkInterval);
          reject(new Error('Authentication window closed unexpectedly for @jfcarpio. Please retry.'));
          return;
        }
        const url = authWindow.location.href;
        if (url && url.includes(redirectUri)) {
          authWindow.close();
          clearInterval(checkInterval);
          const params = new URLSearchParams(url.split('?')[1]);
          const code = params.get('code');
          const returnedState = params.get('state');
          if (!code) reject(new Error('No authorization code found in callback URL for @jfcarpio'));
          if (returnedState !== state) reject(new Error('CSRF state mismatch detected for @jfcarpio'));
          resolve(code);
        }
      } catch (e) {
        // Ignore cross-origin errors
      }
    }, 500);

    setTimeout(() => {
      clearInterval(checkInterval);
      authWindow.close();
      reject(new Error('Authentication timed out after 5 minutes for @jfcarpio. Please retry.'));
    }, 300000); // 5-minute timeout
  });
}

/**
 * Manual fallback for authentication, handling user input for callback URL.
 * @param {string} redirectUri - The redirect URI
 * @param {string} state - CSRF state
 * @returns {Promise<string>} Authorization code
 */
async function getAuthCodeManually(redirectUri, state) {
  return new Promise((resolve, callbackInput, reject) => {
    submitCallbackButton.onclick = async () => {
      const callbackUrl = callbackInput.value.trim();
      if (!callbackUrl) {
        errorDiv.innerHTML = '<p class="error">Please paste the callback URL from X for @jfcarpio.</p>';
        return;
      }
      try {
        const params = new URLSearchParams(new URL(callbackUrl).search);
        const code = params.get('code');
        const returnedState = params.get('state');
        if (!code) throw new Error('No authorization code found in callback URL for @jfcarpio');
        if (returnedState !== state) throw new Error('CSRF state mismatch detected for @jfcarpio');
        resolve(code);
      } catch (error) {
        console.error('Error parsing callback URL for @jfcarpio:', error);
        errorDiv.innerHTML = `<p class="error">Invalid callback URL for @jfcarpio: ${error.message}. Please ensure you copied the full URL from X after authentication.</p>`;
        reject(error);
      }
    };
  });
}

/**
 * Exchanges authorization code for access token with failsafes for @jfcarpio.
 * @param {string} authCode - The authorization code
 * @returns {Promise<string>} Access token
 */
async function exchangeCodeForToken(authCode) {
  const codeVerifier = sessionStorage.getItem('codeVerifier');
  if (!codeVerifier) throw new Error('Code verifier not found for @jfcarpio. Please restart authentication.');

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const tokenResponse = await fetch(`${X_API_BASE}/oauth2/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=authorization_code&code=${authCode}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&client_id=${CLIENT_ID}&code_verifier=${codeVerifier}`
      });
      if (!tokenResponse.ok) {
        const errorText = await tokenResponse.text();
        throw new Error(`Token exchange failed for @jfcarpio: HTTP ${tokenResponse.status} - ${errorText}`);
      }
      const tokenData = await tokenResponse.json();
      return tokenData.access_token;
    } catch (error) {
      console.error(`Token exchange attempt ${attempt} failed for @jfcarpio:`, error);
      if (attempt === 3) throw error;
      const waitTime = 2000 * attempt; // Exponential backoff
      console.log(`Retrying token exchange for @jfcarpio in ${waitTime / 1000} seconds...`);
      await new Promise(resolve => setTimeout(resolve, waitTime));
      errorDiv.innerHTML = `<p class="error">Retrying token exchange (attempt ${attempt + 1}/3) for @jfcarpio: ${error.message}. Check console for details.</p>`;
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
    const response = await fetch(`${X_API_BASE}/users/me`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!response.ok) throw new Error(`Failed to fetch user ID for @jfcarpio: HTTP ${response.status} - ${response.statusText}`);
    const data = await response.json();
    return data.data.id;
  } catch (error) {
    console.error('Error in getUserId for @jfcarpio:', error);
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
    const response = await fetch(`${X_API_BASE}/users/${userId}?user.fields=username,name`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!response.ok) throw new Error(`Failed to fetch user details for @jfcarpio: HTTP ${response.status} - ${response.statusText}`);
    return await response.json().data;
  } catch (error) {
    console.error('Error in fetchUserDetails for @jfcarpio:', error);
    throw error;
  }
}

/**
 * Fetches all follows with pagination for @jfcarpio.
 * @param {string} userId - The user ID
 * @param {string} accessToken - The access token
 * @returns {Promise<Array>} List of follows
 */
async function getAllFollows(userId, accessToken) {
  let follows = [];
  let nextToken = null;
  do {
    try {
      const url = `${X_API_BASE}/users/${userId}/following?max_results=100${nextToken ? `&pagination_token=${nextToken}` : ''}&user.fields=username`;
      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to fetch follows for @jfcarpio: HTTP ${response.status} - ${errorText}`);
      }
      const data = await response.json();
      follows = follows.concat(data.data || []);
      nextToken = data.meta.next_token;
      await handleRateLimits(response);
    } catch (error) {
      console.error('Error in getAllFollows for @jfcarpio:', error);
      throw error;
    }
  } while (nextToken);
  return follows;
}

/**
 * Fetches all followers with pagination for @jfcarpio.
 * @param {string} userId - The user ID
 * @param {string} accessToken - The access token
 * @returns {Promise<Array>} List of followers
 */
async function getAllFollowers(userId, accessToken) {
  let followers = [];
  let nextToken = null;
  do {
    try {
      const url = `${X_API_BASE}/users/${userId}/followers?max_results=100${nextToken ? `&pagination_token=${nextToken}` : ''}&user.fields=username`;
      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to fetch followers for @jfcarpio: HTTP ${response.status} - ${errorText}`);
      }
      const data = await response.json();
      followers = follows.concat(data.data || []);
      nextToken = data.meta.next_token;
      await handleRateLimits(response);
    } catch (error) {
      console.error('Error in getAllFollowers for @jfcarpio:', error);
      throw error;
    }
  } while (nextToken);
  return followers;
}

/**
 * Fetches recent tweets for a user for @jfcarpio.
 * @param {string} userId - The user ID
 * @param {string} startTime - The start time for tweets
 * @param {string} accessToken - The access token
 * @returns {Promise<Object>} Tweets response
 */
async function getRecentTweets(userId, startTime, accessToken) {
  try {
    const url = `${X_API_BASE}/users/${userId}/tweets?max_results=1&start_time=${startTime}&tweet.fields=created_at`;
    const response = await fetch(url, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to fetch tweets for user ${userId} for @jfcarpio: HTTP ${response.status} - ${errorText}`);
    }
    return await response.json();
  } catch (error) {
    console.error(`Error in getRecentTweets for user ${userId} for @jfcarpio:`, error);
    throw error;
  }
}

/**
 * Handles rate limits for X API calls for @jfcarpio.
 * @param {Response} response - The fetch response
 */
async function handleRateLimits(response) {
  try {
    const rateLimitRemaining = response.headers.get('x-rate-limit-remaining');
    const rateLimitReset = response.headers.get('x-rate-limit-reset');
    if (rateLimitRemaining && parseInt(rateLimitRemaining) <= 5) {
      const resetTime = new Date(parseInt(rateLimitReset) * 1000);
      const waitTime = Math.max(0, resetTime - Date.now() + 1000); // Add 1s buffer
      console.log(`Rate limit nearing exhaustion for @jfcarpio. Waiting ${waitTime / 1000} seconds...`);
      await new Promise(resolve => setTimeout(resolve, waitTime));
    } else {
      await new Promise(resolve => setTimeout(resolve, 1000)); // Default 1s delay
    }
  } catch (error) {
    console.error('Error in handleRateLimits for @jfcarpio:', error);
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
    `Processed ${current} of ${total} non-mutuals for @jfcarpio. Found ${found} inactive users.`;
}

/**
 * Displays results in a professional table for @jfcarpio.
 * @param {Array} users - List of inactive non-mutuals
 * @param {string} userId - The user ID
 */
function displayResults(users, userId) {
  const resultsDiv = document.getElementById('results');
  if (users.length === 0) {
    resultsDiv.innerHTML = '<p class="no-results">No inactive non-mutuals found for @jfcarpio (ID: ' + userId + ').</p>';
  } else {
    resultsDiv.innerHTML = `
      <h2>Inactive Non-Mutual Follows for @jfcarpio</h2>
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
  test('initiateAuthFlow should handle already logged-in state and return auth code', async () => {
    // Mock window.open, location.href, and X API responses
  });
  test('exchangeCodeForToken should retry on failure and succeed with PKCE', async () => {
    // Mock fetch with rate limit errors and X API responses
  });
  test('handleRateLimits should dynamically adjust based on X rate limits', async () => {
    // Mock response headers with various rate limit scenarios
  });
*/

// Event listener for @jfcarpio
document.getElementById('startButton').addEventListener('click', findInactiveNonMutuals);
