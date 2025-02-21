// Main function to find inactive non-mutuals for @jfcarpio
async function findInactiveNonMutuals() {
  const startButton = document.getElementById('startButton');
  const progressDiv = document.getElementById('progress');
  const resultsDiv = document.getElementById('results');
  const errorDiv = document.getElementById('error');
  const loadingDiv = document.getElementById('loading');

  try {
    // Reset UI
    startButton.disabled = true;
    startButton.innerText = 'Authenticating with X...';
    progressDiv.innerHTML = '';
    resultsDiv.innerHTML = '';
    errorDiv.innerHTML = '';
    loadingDiv.style.display = 'block';

    // Step 1: Authenticate with X using OAuth 2.0 PKCE for @jfcarpio
    console.log('Starting X authentication for @jfcarpio...');
    const accessToken = await getAccessToken();
    console.log('Successfully authenticated with X for @jfcarpio. Access token:', accessToken);

    // Step 2: Fetch your user ID (for @jfcarpio)
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

    // Step 3: Fetch follows and followers for @jfcarpio
    progressDiv.innerHTML = 'Fetching follows for @jfcarpio...';
    console.log('Fetching follows for @jfcarpio...');
    const follows = await getAllFollows(userId, accessToken);
    console.log('Follows for @jfcarpio fetched:', follows.length);

    progressDiv.innerHTML = 'Fetching followers for @jfcarpio...';
    console.log('Fetching followers for @jfcarpio...');
    const followers = await getAllFollowers(userId, accessToken);
    console.log('Followers for @jfcarpio fetched:', followers.length);

    // Step 4: Identify non-mutuals for @jfcarpio
    console.log('Identifying non-mutuals for @jfcarpio...');
    const followerIds = new Set(followers.map(follower => follower.id));
    const nonMutuals = follows.filter(follow => !followerIds.has(follow.id));
    console.log('Non-mutuals for @jfcarpio identified:', nonMutuals.length);

    // Step 5: Check inactivity for non-mutuals (expanded scope)
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
        // Skip problematic users
      }
      updateProgress(i + 1, nonMutuals.length, inactiveNonMutuals.length);
      await handleRateLimits();
    }

    // Step 6: Display results professionally for @jfcarpio
    console.log('Displaying results for @jfcarpio...');
    displayResults(inactiveNonMutuals, userId);
  } catch (error) {
    console.error('Error in findInactiveNonMutuals for @jfcarpio:', error);
    errorDiv.innerHTML = `<p class="error">Error for @jfcarpio: ${error.message}. Check the console for detailed bug report, including stack trace and error context.</p>`;
  } finally {
    startButton.disabled = false;
    startButton.innerText = 'Authenticate with X and Find Inactive Non-Mutuals';
    loadingDiv.style.display = 'none';
  }
}

// Authenticate with X using OAuth 2.0 PKCE for @jfcarpio
async function getAccessToken() {
  try {
    // Generate code verifier and challenge for PKCE
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    // X app credentials (replace with your values from X Developer Portal)
    const clientId = 'QlK4UFjcTMT9vHFtUZho90YIp'; // Your provided API key (verify if this is the client ID)
    const redirectUri = 'https://yourgithubusername.github.io/inactive-follows/callback'; // Replace with your GitHub Pages URL

    // Redirect to X authorization URL
    const authUrl = `https://twitter.com/i/oauth2/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=tweet.read%20users.read%20follows.read&state=state&code_challenge=${codeChallenge}&code_challenge_method=S256`;
    console.log('Redirecting to X for authentication. Open this URL in your browser:', authUrl);

    // Open the auth URL in a new window
    const authWindow = window.open(authUrl, '_blank', 'width=600,height=600');
    if (!authWindow) throw new Error('Failed to open authentication window. Please allow popups or open the URL manually.');

    // Wait for the callback (simplified for GitHub Pages—user must copy the URL)
    let authCode = await new Promise((resolve, reject) => {
      const checkCallback = setInterval(() => {
        try {
          const url = authWindow.location.href;
          if (url && url.includes(redirectUri)) {
            authWindow.close();
            clearInterval(checkCallback);
            const params = new URLSearchParams(url.split('?')[1]);
            const code = params.get('code');
            if (code) resolve(code);
            else reject(new Error('No authorization code found in callback URL'));
          }
        } catch (e) {
          // Ignore errors from accessing window.location (cross-origin)
        }
      }, 500);
      setTimeout(() => {
        clearInterval(checkCallback);
        reject(new Error('Authentication timed out. Please try again.'));
      }, 300000); // 5-minute timeout
    });

    // Exchange code for token
    const tokenResponse = await fetch('https://api.twitter.com/2/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `grant_type=authorization_code&code=${authCode}&redirect_uri=${encodeURIComponent(redirectUri)}&client_id=${clientId}&code_verifier=${codeVerifier}`
    });
    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      throw new Error(`Failed to get access token for @jfcarpio: HTTP ${tokenResponse.status} - ${errorText}`);
    }
    const tokenData = await tokenResponse.json();
    return tokenData.access_token;
  } catch (error) {
    console.error('Error in getAccessToken for @jfcarpio:', error);
    throw new Error(`Authentication failed for @jfcarpio: ${error.message}`);
  }
}

// Helper functions for PKCE
function generateCodeVerifier() {
  const array = new Uint32Array(56);
  crypto.getRandomValues(array);
  return Array.from(array, x => x.toString(36)).join('');
}

async function generateCodeChallenge(codeVerifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
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
      if (!response.ok) throw new Error(`Failed to fetch follows for @jfcarpio: HTTP ${response.status} - ${response.statusText}`);
      const data = await response.json();
      follows = follows.concat(data.data || []);
      nextToken = data.meta.next_token;
      await handleRateLimits();
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
      if (!response.ok) throw new Error(`Failed to fetch followers for @jfcarpio: HTTP ${response.status} - ${response.statusText}`);
      const data = await response.json();
      followers = followers.concat(data.data || []);
      nextToken = data.meta.next_token;
      await handleRateLimits();
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
    if (!response.ok) throw new Error(`Failed to fetch tweets for user ${userId} for @jfcarpio: HTTP ${response.status} - ${response.statusText}`);
    return await response.json();
  } catch (error) {
    console.error(`Error in getRecentTweets for user ${userId} for @jfcarpio:`, error);
    throw error;
  }
}

// Rate limit handling for @jfcarpio
async function handleRateLimits() {
  try {
    await new Promise(resolve => setTimeout(resolve, 1000)); // Basic 1-second delay
    // In production, parse x-rate-limit-remaining and x-rate-limit-reset headers
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

// Event listener for @jfcarpio
document.getElementById('startButton').addEventListener('click', findInactiveNonMutuals);