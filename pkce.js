// openpixie, Oauth pkce for openrouter

// Function to generate a random string for code_verifier
function generateRandomString(length) {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  let randomString = '';
  const array = new Uint8Array(length);
  window.crypto.getRandomValues(array);
  for (let i = 0; i < length; i++) {
    randomString += charset[array[i] % charset.length];
  }
  return randomString;
}

// Function to generate a SHA-256 code challenge
async function sha256CodeChallenge(input) {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode.apply(null, new Uint8Array(hash)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Function to redirect the user to the authentication URL
async function redirectToAuth(callbackUrl) {
  const codeVerifier = generateRandomString(128);
  localStorage.setItem('code_verifier', codeVerifier);
  const codeChallenge = await sha256CodeChallenge(codeVerifier);
  const authUrl = `https://openrouter.ai/auth?callback_url=${encodeURIComponent(callbackUrl)}&code_challenge=${codeChallenge}&code_challenge_method=S256`;
  window.location.href = authUrl;
}

// Function to handle the authentication code and request the API key
async function handleAuthCode(authCode, codeVerifier) {
  try {
    const response = await fetch('https://openrouter.ai/api/v1/auth/keys', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        code: authCode,
        code_verifier: codeVerifier,
        code_challenge_method: 'S256'
      })
    });
    const data = await response.json();
    localStorage.removeItem('code_verifier');
    return data.api_key; // Return the API key
  } catch (error) {
    alert('Error: ' + error);
    localStorage.removeItem('code_verifier');
    return null; // Return null if there's an error
  }
}

// Function to check for auth code and handle the flow
async function checkAuthFlow() {
  const urlParams = new URLSearchParams(window.location.search);
  const authCode = urlParams.get('code');
  const codeVerifier = localStorage.getItem('code_verifier');
  const callbackUrl = window.location.origin + window.location.pathname;

  if (!authCode) {
    await redirectToAuth(callbackUrl);
    return null; // Return null since we're redirecting
  } else {
    return await handleAuthCode(authCode, codeVerifier);
  }
}
