// Main function to find inactive non-mutuals for @jfcarpio
async function findInactiveNonMutuals() {
  const startButton = document.getElementById('startButton');
  const progressDiv = document.getElementById('progress');
  const resultsDiv = document.getElementById('results');
  const errorDiv = document.getElementById('error');
  const loadingDiv = document.getElementById('loading');
  const instructionsDiv = document.getElementById('instructions');
  const callbackInput = document.getElementById('callbackUrl');
  const submitCallbackButton = document.getElementById('submitCallback');

  let authCode = null;

  // Reset UI
  startButton.disabled = true;
  startButton.innerText = 'Authenticating with X...';
  progressDiv.innerHTML = '';
  resultsDiv.innerHTML = '';
  errorDiv.innerHTML = '';
  loadingDiv.style.display = 'block';
  instructionsDiv.style.display = 'block';

  try {
    // Step 1: Authenticate with X using OAuth 2.0 PKCE for @jfcarpio
    console.log('Starting X authentication for @jfcarpio...');
    authCode = await initiateAuthFlow();
    console.log('Authorization code obtained for @jfcarpio:', authCode);

    // Step 2: Exchange code for access token
    const accessToken = await exchangeCodeForToken(authCode);
    console.log('Successfully authenticated with X for @jfcarpio. Access token:', accessToken);

    // Step 3: Fetch your user ID (for @jfcarpio)
    console.log('Fetching user ID for @jfcarpio...');
    const userId = await getUserId(accessToken);
    console.log('User ID for @jfcarpio obtained:', userId);

    // Verify X account usage (ensure it’s @jfcarpio)
    console.log('Verifying X account details for @jfcarpio...');
    const userDetails = await fetchUserDetails(userId, accessToken);
    if (userDetails.username !== 'jfcarpio') {
      throw new Error('This app is configured for @jfcarpio, but the authenticated account does not match. Please log in with @jfcarpio.');
    }
    console.log('Verified X account: @jfcarpio');
    progressDiv.innerHTML = `Authenticated as: @${userDetails.username}`;

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
        // Skip problematic users with a warning
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
    // Retry authentication if it failed
    if (error.message.includes('Authentication') || error.message.includes('token')) {
      console.log('Attempting to retry authentication...');
      startButton.disabled = false;
      startButton.innerText = 'Retry Authentication with X';
      return;
    }
  } finally {
    startButton.disabled = false;
    startButton.innerText = 'Authenticate with X and Find Inactive Non-Mutuals';
    loadingDiv.style.display = 'none';
    instructionsDiv.style.display = 'none';
  }
}

// Initiate OAuth 2.0 PKCE authentication flow for @jfcarpio
async function initiateAuthFlow() {
  const clientId = 'QlK4UFjcTMT9vHFtUZho90YIp'; // Your X app client ID
  const redirectUri = 'https://yourgithubusername.github.io/inactive-follows/callback'; // Replace with your GitHub Pages URL
  const state = generateRandomString(16); // CSRF protection
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);

  // Build authorization URL
  const authUrl = `https://twitter.com/i/oauth2/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=tweet.read%20users.read%20follows.read&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256`;
  console.log('Redirecting to X for authentication. Open this URL:', authUrl);

  // Open in a new window with fallback
  let authWindow;
  try {
    authWindow = window.open(authUrl, '_blank', 'width=600,height=600');
    if (!authWindow) throw new Error('Popup blocked. Please open this URL manually:', authUrl);
  } catch (error) {
    console.error('Popup error:', error);
    errorDiv.innerHTML = `<p class="error">Popup blocked or failed. Please open this URL manually: <a href="${authUrl}" target="_blank">${authUrl}</a>, authorize, then paste the callback URL below.</p>`;
    return await getAuthCodeManually(redirectUri, state);
  }

  // Poll for callback (handle CORS and browser restrictions)
  return await new Promise((resolve, reject) => {
    let checkInterval = setInterval(async () => {
      try {
        if (authWindow.closed) {
          clearInterval(checkInterval);
          reject(new Error('Authentication window closed unexpectedly. Please retry.'));
          return;
        }
        const url = authWindow.location.href;
        if (url && url.includes(redirectUri)) {
          authWindow.close();
          clearInterval(checkInterval);
          const params = new URLSearchParams(url.split('?')[1]);
          const code = params.get('code');
          const returnedState = params.get('state');
          if (!code) reject(new Error('No authorization code found in callback URL'));
          if (returnedState !== state) reject(new Error('CSRF state mismatch detected'));
          resolve(code);
        }
      } catch (e) {
        // Ignore cross-origin errors
      }
    }, 500);

    setTimeout(() => {
      clearInterval(checkInterval);
      authWindow.close();
      reject(new Error('Authentication timed out after 5 minutes. Please retry.'));
    }, 300000); // 5-minute timeout
  });
}

// Manual fallback for authentication (user copies callback URL)
async function getAuthCodeManually(redirectUri, state) {
  return new Promise((resolve, reject) => {
    submitCallbackButton.onclick = async () => {
      const callbackUrl = callbackInput.value.trim();
      if (!callbackUrl) {
        errorDiv.innerHTML = '<p class="error">Please paste the callback URL from X.</p>';
        return;
      }
      try {
        const params = new URLSearchParams(new URL(callbackUrl).search);
        const code = params.get('code');
        const returnedState = params.get('state');
        if (!code) throw new Error('No authorization code found in callback URL');
        if (returnedState !== state) throw new Error('CSRF state mismatch detected');
        resolve(code);
      } catch (error) {
        console.error('Error parsing callback URL:', error);
        errorDiv.innerHTML = `<p class="error">Invalid callback URL: ${error.message}. Please ensure you copied the full URL from X after authentication.</p>`;
        reject(error);
      }
    };
  });
}

// Exchange authorization code for access token for @jfcarpio
async function exchangeCodeForToken(authCode) {
  const clientId = 'QlK4UFjcTMT9vHFtUZho90YIp'; // Your X app client ID
  const redirectUri = 'https://yourgithubusername.github.io/inactive-follows/callback'; // Replace with your GitHub Pages URL

  // Get code verifier from storage (simulated here, should use secure storage)
  const codeVerifier = sessionStorage.getItem('codeVerifier');
  if (!codeVerifier) throw new Error('Code verifier not found. Please restart authentication.');

  // Exchange code for token with retry logic
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const tokenResponse = await fetch('https://api.twitter.com/2/oauth2/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=authorization_code&code=${authCode}&redirect_uri=${encodeURIComponent(redirectUri)}&client_id=${clientId}&code_verifier=${codeVerifier}`
      });
      if (!tokenResponse.ok) {
        const errorText = await tokenResponse.text();
        throw new Error(`Token exchange failed: HTTP ${tokenResponse.status} - ${errorText}`);
      }
      const tokenData = await tokenResponse.json();
      return tokenData.access_token;
    } catch (error) {
      console.error(`Token exchange attempt ${attempt} failed for @jfcarpio:`, error);
      if (attempt === 3) throw error;
      await new Promise(resolve => setTimeout(resolve, 2000 * attempt)); // Exponential backoff
      errorDiv.innerHTML = `<p class="error">Retrying token exchange (attempt ${attempt + 1}/3) for @jfcarpio: ${error.message}. Check console for details.</p>`;
    }
  }
}

// Fetch your user ID from the X API for @jfcarpio
async function getUserId(accessToken) {
  try {
    const response = await fetch('https://api.twitter.com/2/users/me', {
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

// Fetch user details to verify @jfcarpio
async function fetchUserDetails(userId, accessToken) {
  try {
    const response = await fetch(`https://api.twitter.com/2/users/${userId}?user.fields=username,name`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!response.ok) throw new Error(`Failed to fetch user details for @jfcarpio: HTTP ${response.status} - ${response.statusText}`);
    return await response.json().data;
  } catch (error) {
    console.error('Error in fetchUserDetails for @jfcarpio:', error);
    throw error;
  }
}

// Fetch all follows with pagination for @jfcarpio
async function getAllFollows(userId, accessToken) {
  let follows = [];
  let nextToken = null;
  do {
    try {
      const url = `https://api.twitter.com/2/users/${userId}/following?max_results=100${nextToken ? `&pagination_token=${nextToken}` : ''}&user.fields=username`;
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

// Fetch all followers with pagination for @jfcarpio
async function getAllFollowers(userId, accessToken) {
  let followers = [];
  let nextToken = null;
  do {
    try {
      const url = `https://api.twitter.com/2/users/${userId}/followers?max_results=100${nextToken ? `&pagination_token=${nextToken}` : ''}&user.fields=username`;
      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to fetch followers for @jfcarpio: HTTP ${response.status} - ${errorText}`);
      }
      const data = await response.json();
      followers = followers.concat(data.data || []);
      nextToken = data.meta.next_token;
      await handleRateLimits(response);
    } catch (error) {
      console.error('Error in getAllFollowers for @jfcarpio:', error);
      throw error;
    }
  } while (nextToken);
  return followers;
}

// Fetch recent tweets for a user for @jfcarpio
async function getRecentTweets(userId, startTime, accessToken) {
  try {
    const url = `https://api.twitter.com/2/users/${userId}/tweets?max_results=1&start_time=${startTime}&tweet.fields=created_at`;
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

// Enhanced rate limit handling for @jfcarpio
async function handleRateLimits(response) {
  try {
    const rateLimitRemaining = response.headers.get('x-rate-limit-remaining');
    const rateLimitReset = response.headers.get('x-rate-limit-reset');
    if (rateLimitRemaining && parseInt(rateLimitRemaining) <= 5) {
      const resetTime = new Date(parseInt(rateLimitReset) * 1000);
      const waitTime = Math.max(0, resetTime - Date.now() + 1000); // Add 1s buffer
      console.log(`Rate limit nearing exhaustion. Waiting ${waitTime / 1000} seconds...`);
      await new Promise(resolve => setTimeout(resolve, waitTime));
    } else {
      await new Promise(resolve => setTimeout(resolve, 1000)); // Default 1s delay
    }
  } catch (error) {
    console.error('Error in handleRateLimits for @jfcarpio:', error);
    throw error;
  }
}

// Update progress UI for @jfcarpio
function updateProgress(current, total, found) {
  document.getElementById('progress').innerText = 
    `Processed ${current} of ${total} non-mutuals for @jfcarpio. Found ${found} inactive users.`;
}

// Display results in a professional table for @jfcarpio
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

// Generate random string for CSRF protection or PKCE
function generateRandomString(length) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, x => x.toString(36)).join('').slice(0, length);
}

// Generate PKCE code verifier
function generateCodeVerifier() {
  const verifier = generateRandomString(43); // Minimum length per RFC 7636
  sessionStorage.setItem('codeVerifier', verifier); // Store securely in session storage
  return verifier;
}

// Generate PKCE code challenge
async function generateCodeChallenge(codeVerifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Test cases (commented for now, implement in a testing framework)
/*
  test('initiateAuthFlow should return auth code on successful X redirect', async () => {
    // Mock window.open and location.href
  });
  test('exchangeCodeForToken should retry on failure and succeed', async () => {
    // Mock fetch with rate limit errors
  });
  test('handleRateLimits should wait appropriately on rate limits', async () => {
    // Mock response headers
  });
*/

// Event listener for @jfcarpio
document.getElementById('startButton').addEventListener('click', findInactiveNonMutuals);
