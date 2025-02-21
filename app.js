// Constants for clarity and maintainability
const X_API_BASE = 'https://api.twitter.com/2';
const ACCESS_TOKEN = '11859152-XTKsuXYZkqAd0djHHqRfmnMaiN3n6rcOgMmLjyLY8'; // Your provided X access token
const MAX_RETRIES = 5; // Increased retries for robustness
const RETRY_DELAY_BASE = 2000; // 2 seconds initial delay for exponential backoff

// Main function to find inactive non-mutuals for @jfcarpio using access token with enhanced failsafes
async function findInactiveNonMutuals() {
  const startButton = document.getElementById('startButton');
  const progressDiv = document.getElementById('progress');
  const resultsDiv = document.getElementById('results');
  const errorDiv = document.getElementById('error');
  const loadingDiv = document.getElementById('loading');

  // Ensure button and DOM elements exist (double-check)
  if (!startButton || !progressDiv || !resultsDiv || !errorDiv || !loadingDiv) {
    console.error('DOM elements missing for @jfcarpio app. Check index.html.');
    errorDiv.innerHTML = '<p class="error">Error: App initialization failed. Please refresh and check console for details.</p>';
    startButton.disabled = false;
    return;
  }

  // Reset UI state
  startButton.disabled = true;
  startButton.innerText = 'Loading...';
  progressDiv.innerHTML = '';
  resultsDiv.innerHTML = '';
  errorDiv.innerHTML = '';
  loadingDiv.style.display = 'block';

  try {
    // Step 1: Verify access token belongs to @jfcarpio with enhanced validation
    console.log('Verifying access token for @jfcarpio...');
    const userDetails = await fetchUserDetailsWithRetries(ACCESS_TOKEN);
    if (userDetails.username !== 'jfcarpio') {
      throw new Error('This access token does not belong to @jfcarpio. Please provide the correct token for your X account or regenerate via the X Developer Portal.');
    }
    console.log('Verified access token belongs to @jfcarpio:', userDetails.username);
    progressDiv.innerHTML = `Authenticated as: @${userDetails.username} (using access token)`;

    // Step 2: Fetch user ID for @jfcarpio
    console.log('Fetching user ID for @jfcarpio...');
    const userId = userDetails.id;
    console.log('User ID for @jfcarpio obtained:', userId);

    // Step 3: Fetch follows and followers for @jfcarpio
    progressDiv.innerHTML = 'Fetching follows for @jfcarpio...';
    console.log('Fetching follows for @jfcarpio...');
    const follows = await getAllFollowsWithRetries(userId, ACCESS_TOKEN);
    console.log('Follows for @jfcarpio fetched:', follows.length);

    progressDiv.innerHTML = 'Fetching followers for @jfcarpio...';
    console.log('Fetching followers for @jfcarpio...');
    const followers = await getAllFollowersWithRetries(userId, ACCESS_TOKEN);
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
        const tweets = await getRecentTweetsWithRetries(user.id, startTime, ACCESS_TOKEN);
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

    // Step 6: Display results professionally for @jfcarpio
    console.log('Displaying results for @jfcarpio...');
    displayResults(inactiveNonMutuals, userId);
  } catch (error) {
    console.error('Error in findInactiveNonMutuals for @jfcarpio:', error);
    errorDiv.innerHTML = `<p class="error">Critical Error for @jfcarpio: ${error.message}. Check the console for detailed bug report, including stack trace and error context.</p>`;
    // Retry automatically if it’s a token, API, or network-related error
    if (error.message.includes('token') || error.message.includes('access') || error.message.includes('HTTP') || error.message.includes('network')) {
      console.log('Attempting to retry automatically for @jfcarpio...');
      setTimeout(() => findInactiveNonMutuals(), RETRY_DELAY_BASE); // Retry after 2 seconds
    }
  } finally {
    startButton.disabled = false;
    startButton.innerText = 'Find Inactive Non-Mutuals';
    loadingDiv.style.display = 'none';
  }
}

/**
 * Fetches user details to verify @jfcarpio using the access token with retries.
 * @param {string} accessToken - The access token
 * @returns {Promise<Object>} User details
 */
async function fetchUserDetailsWithRetries(accessToken) {
  return await fetchWithRetry(`${X_API_BASE}/users/me?user.fields=username,name`, {
    headers: { Authorization: `Bearer ${accessToken}` }
  }).then(response => response.json().data);
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
      console.error('Error in getAllFollows for @jfcarpio:', error);
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
      console.error('Error in getAllFollowers for @jfcarpio:', error);
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
        throw new Error(`API call failed for @jfcarpio: HTTP ${response.status} - ${errorText}`);
      }
      return response;
    } catch (error) {
      console.error(`Fetch attempt ${attempt} failed for @jfcarpio:`, error);
      if (attempt === MAX_RETRIES) throw error;
      const waitTime = RETRY_DELAY_BASE * Math.pow(2, attempt - 1); // Exponential backoff
      console.log(`Retrying API call for @jfcarpio in ${waitTime / 1000} seconds...`);
      errorDiv.innerHTML = `<p class="error">Retrying API call (attempt ${attempt + 1}/${MAX_RETRIES}) for @jfcarpio: ${error.message}. Check console for details.</p>`;
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

// Test cases (commented for future implementation)
/*
  test('findInactiveNonMutuals should use access token and fetch data reliably for @jfcarpio', async () => {
    // Mock fetch with X API responses for @jfcarpio, including rate limits and errors
  });
  test('fetchWithRetry should handle multiple failures and succeed for @jfcarpio', async () => {
    // Mock fetch with various error scenarios and retries
  });
  test('handleRateLimits should adjust delays based on X rate limits for @jfcarpio', async () => {
    // Mock response headers with different rate limit scenarios
  });
*/

// Ensure event listener attaches after DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  const startButton = document.getElementById('startButton');
  if (startButton) {
    startButton.addEventListener('click', findInactiveNonMutuals);
    console.log('Event listener attached successfully for @jfcarpio.');
  } else {
    console.error('Start button not found for @jfcarpio. Check index.html.');
    document.getElementById('error').innerHTML = '<p class="error">Error: Button not found. Please refresh and check console for details.</p>';
  }
});
