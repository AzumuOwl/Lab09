// API Configuration
let API_BASE = localStorage.getItem('apiUrl') || 'http://localhost:8000';
let accessToken = localStorage.getItem('accessToken') || '';
let refreshTokenValue = localStorage.getItem('refreshToken') || '';
let jwtUpdateInterval = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('apiUrl').value = API_BASE;
    checkServerStatus();
    updateTokenDisplay();
    if (accessToken) {
        getProfile();
        decodeAndDisplayJWT(accessToken);
    }
    setInterval(checkServerStatus, 30000);
});

// Update API Base URL
function updateApiBase() {
    const newUrl = document.getElementById('apiUrl').value.trim();
    if (newUrl) {
        API_BASE = newUrl.replace(/\/$/, ''); // Remove trailing slash
        localStorage.setItem('apiUrl', API_BASE);
        checkServerStatus();
        console.log('API URL updated to:', API_BASE);
    }
}

// Check server status
async function checkServerStatus() {
    try {
        const res = await fetch(`${API_BASE}/health`, {
            method: 'GET',
            mode: 'cors'
        });
        const data = await res.json();
        document.getElementById('serverStatus').classList.add('active');
        document.getElementById('serverStatusText').textContent = 'Connected';
    } catch (e) {
        document.getElementById('serverStatus').classList.remove('active');
        document.getElementById('serverStatusText').textContent = 'Disconnected';
        console.error('Server check failed:', e.message);
    }
}

// Update token display
function updateTokenDisplay() {
    const tokenDisplay = document.getElementById('tokenDisplay');
    const jwtSection = document.getElementById('jwtSection');
    const authStatus = document.getElementById('authStatus');
    const authStatusText = document.getElementById('authStatusText');

    if (accessToken) {
        tokenDisplay.style.display = 'block';
        jwtSection.style.display = 'block';
        document.getElementById('accessTokenDisplay').textContent = accessToken;
        document.getElementById('refreshTokenDisplay').textContent = refreshTokenValue || '-';
        authStatus.classList.add('active');
        authStatusText.textContent = 'Logged in';
        decodeAndDisplayJWT(accessToken);
    } else {
        tokenDisplay.style.display = 'none';
        jwtSection.style.display = 'none';
        authStatus.classList.remove('active');
        authStatusText.textContent = 'Not logged in';
        document.getElementById('currentUser').textContent = '-';
        if (jwtUpdateInterval) {
            clearInterval(jwtUpdateInterval);
            jwtUpdateInterval = null;
        }
    }
}

// Save tokens
function saveTokens(access, refresh) {
    accessToken = access;
    refreshTokenValue = refresh;
    localStorage.setItem('accessToken', access);
    if (refresh) localStorage.setItem('refreshToken', refresh);
    updateTokenDisplay();
}

// Clear tokens
function clearTokens() {
    accessToken = '';
    refreshTokenValue = '';
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    updateTokenDisplay();
    document.getElementById('currentUser').textContent = '-';
}

// Show response
function showResponse(elementId, data, isError = false) {
    const el = document.getElementById(elementId);
    el.textContent = JSON.stringify(data, null, 2);
    el.className = `response-box show ${isError ? 'error' : 'success'}`;
}

// API call helper
async function apiCall(endpoint, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };

    if (accessToken && !options.noAuth) {
        headers['Authorization'] = `Bearer ${accessToken}`;
    }

    const res = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers,
        mode: 'cors'
    });

    const data = await res.json();
    return { ok: res.ok, status: res.status, data };
}

// =====================
// JWT Decoder Functions
// =====================

function base64UrlDecode(str) {
    // Replace URL-safe characters
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    // Pad with = if needed
    while (str.length % 4) {
        str += '=';
    }
    try {
        return decodeURIComponent(atob(str).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
    } catch (e) {
        return atob(str);
    }
}

function decodeJWT(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) {
            throw new Error('Invalid JWT format');
        }

        const header = JSON.parse(base64UrlDecode(parts[0]));
        const payload = JSON.parse(base64UrlDecode(parts[1]));
        const signature = parts[2];

        return { header, payload, signature, parts };
    } catch (e) {
        console.error('Failed to decode JWT:', e);
        return null;
    }
}

function formatTimestamp(timestamp) {
    if (!timestamp) return '-';
    const date = new Date(timestamp * 1000);
    return date.toLocaleString('th-TH', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

function getTimeRemaining(expTimestamp) {
    if (!expTimestamp) return '-';
    const now = Math.floor(Date.now() / 1000);
    const diff = expTimestamp - now;

    if (diff <= 0) {
        return '❌ EXPIRED';
    }

    const minutes = Math.floor(diff / 60);
    const seconds = diff % 60;

    if (minutes > 60) {
        const hours = Math.floor(minutes / 60);
        const remainingMins = minutes % 60;
        return `${hours}h ${remainingMins}m ${seconds}s`;
    }

    return `${minutes}m ${seconds}s`;
}

function decodeAndDisplayJWT(token) {
    const decoded = decodeJWT(token);
    if (!decoded) return;

    const { header, payload, signature, parts } = decoded;

    // Display JWT parts
    document.getElementById('jwtHeader').textContent = JSON.stringify(header, null, 2);
    document.getElementById('jwtPayload').textContent = JSON.stringify(payload, null, 2);
    document.getElementById('jwtSignature').textContent = signature.substring(0, 20) + '...';

    // Display decoded info
    document.getElementById('jwtType').textContent = payload.type || header.typ || 'JWT';
    document.getElementById('jwtSub').textContent = payload.sub || '-';
    document.getElementById('jwtIat').textContent = formatTimestamp(payload.iat);
    document.getElementById('jwtExp').textContent = formatTimestamp(payload.exp);

    // Update time remaining
    function updateRemaining() {
        document.getElementById('jwtRemaining').textContent = getTimeRemaining(payload.exp);
    }
    updateRemaining();

    // Clear previous interval and set new one
    if (jwtUpdateInterval) {
        clearInterval(jwtUpdateInterval);
    }
    jwtUpdateInterval = setInterval(updateRemaining, 1000);
}

// =====================
// Bcrypt Demo Functions
// =====================

function demonstrateBcrypt() {
    const password = document.getElementById('bcryptInput').value;
    if (!password) {
        alert('กรุณาใส่ password');
        return;
    }

    // Simulate bcrypt hash generation (actual hashing happens on server)
    // This is a demonstration of what bcrypt produces
    const simulatedHash = generateSimulatedBcryptHash(password);

    document.getElementById('bcryptHash').textContent = simulatedHash;

    // Parse the bcrypt hash anatomy
    parseBcryptHash(simulatedHash);

    document.getElementById('bcryptResult').style.display = 'block';
}

function generateSimulatedBcryptHash(password) {
    // Bcrypt hash format: $2b$cost$salt(22chars)hash(31chars)
    // This simulates what bcrypt produces - actual implementation uses crypto
    const cost = '12';
    const saltChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./';

    let salt = '';
    for (let i = 0; i < 22; i++) {
        salt += saltChars.charAt(Math.floor(Math.random() * saltChars.length));
    }

    let hash = '';
    for (let i = 0; i < 31; i++) {
        hash += saltChars.charAt(Math.floor(Math.random() * saltChars.length));
    }

    return `$2b$${cost}$${salt}${hash}`;
}

function parseBcryptHash(hash) {
    // Bcrypt format: $2b$12$salttttttttttttttttttthashhhhhhhhhhhhhhhhhhhhhhhhhhhhh
    // $2b$ = algorithm identifier (4 chars)
    // 12 = cost factor (2 chars)
    // $ = separator (1 char)
    // next 22 chars = salt
    // remaining 31 chars = hash

    const parts = hash.split('$');
    // parts[0] = "" (before first $)
    // parts[1] = "2b" (algorithm)
    // parts[2] = "12" (cost)
    // parts[3] = salt + hash (53 chars total)

    if (parts.length >= 4) {
        const algo = `$${parts[1]}$`;
        const cost = parts[2];
        const saltAndHash = parts[3];
        const salt = saltAndHash.substring(0, 22);
        const hashPart = saltAndHash.substring(22);

        document.getElementById('bcryptAlgo').textContent = algo;
        document.getElementById('bcryptCost').textContent = cost;
        document.getElementById('bcryptSalt').textContent = salt;
        document.getElementById('bcryptHashPart').textContent = hashPart;
    }
}

// =====================
// Auth API Functions
// =====================

// Register
document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
        const { ok, data } = await apiCall('/auth/register', {
            method: 'POST',
            noAuth: true,
            body: JSON.stringify({
                email: document.getElementById('regEmail').value,
                username: document.getElementById('regUsername').value,
                password: document.getElementById('regPassword').value
            })
        });
        showResponse('registerResponse', data, !ok);
        if (ok) {
            // Auto-fill login form
            document.getElementById('loginEmail').value = document.getElementById('regEmail').value;
            document.getElementById('loginPassword').value = document.getElementById('regPassword').value;

            // Demo bcrypt with the registered password
            document.getElementById('bcryptInput').value = document.getElementById('regPassword').value;
            demonstrateBcrypt();
        }
    } catch (e) {
        showResponse('registerResponse', { error: e.message }, true);
    }
});

// Login
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
        const { ok, data } = await apiCall('/auth/login', {
            method: 'POST',
            noAuth: true,
            body: JSON.stringify({
                email: document.getElementById('loginEmail').value,
                password: document.getElementById('loginPassword').value
            })
        });
        showResponse('loginResponse', data, !ok);
        if (ok) {
            saveTokens(data.access_token, data.refresh_token);
            getProfile(); // Auto-fetch profile
        }
    } catch (e) {
        showResponse('loginResponse', { error: e.message }, true);
    }
});

// Get Profile
async function getProfile() {
    if (!accessToken) {
        showResponse('profileResponse', { error: 'Not logged in. Please login first.' }, true);
        return;
    }
    try {
        const { ok, data } = await apiCall('/users/me');
        showResponse('profileResponse', data, !ok);
        if (ok) {
            document.getElementById('currentUser').textContent = data.username;
        }
    } catch (e) {
        showResponse('profileResponse', { error: e.message }, true);
    }
}

// Update Profile
document.getElementById('updateForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!accessToken) {
        showResponse('updateResponse', { error: 'Not logged in. Please login first.' }, true);
        return;
    }
    try {
        const { ok, data } = await apiCall('/users/me', {
            method: 'PATCH',
            body: JSON.stringify({
                username: document.getElementById('newUsername').value
            })
        });
        showResponse('updateResponse', data, !ok);
        if (ok) {
            document.getElementById('currentUser').textContent = data.username;
        }
    } catch (e) {
        showResponse('updateResponse', { error: e.message }, true);
    }
});

// Refresh Token
async function refreshToken() {
    if (!refreshTokenValue) {
        showResponse('refreshResponse', { error: 'No refresh token available. Please login first.' }, true);
        return;
    }
    try {
        const { ok, data } = await apiCall('/auth/refresh', {
            method: 'POST',
            noAuth: true,
            body: JSON.stringify({ refresh_token: refreshTokenValue })
        });
        showResponse('refreshResponse', data, !ok);
        if (ok) {
            saveTokens(data.access_token, refreshTokenValue);
        }
    } catch (e) {
        showResponse('refreshResponse', { error: e.message }, true);
    }
}

// Logout
async function logout() {
    if (!refreshTokenValue) {
        showResponse('logoutResponse', { error: 'No refresh token available' }, true);
        return;
    }
    try {
        const { ok, data } = await apiCall('/auth/logout', {
            method: 'POST',
            body: JSON.stringify({ refresh_token: refreshTokenValue })
        });
        showResponse('logoutResponse', data, !ok);
        if (ok) {
            clearTokens();
        }
    } catch (e) {
        showResponse('logoutResponse', { error: e.message }, true);
    }
}

// Logout All
async function logoutAll() {
    if (!accessToken) {
        showResponse('logoutResponse', { error: 'Not logged in' }, true);
        return;
    }
    try {
        const { ok, data } = await apiCall('/auth/logout-all', {
            method: 'POST'
        });
        showResponse('logoutResponse', data, !ok);
        if (ok) {
            clearTokens();
        }
    } catch (e) {
        showResponse('logoutResponse', { error: e.message }, true);
    }
}

// Deactivate Account
async function deactivateAccount() {
    if (!accessToken) {
        showResponse('deactivateResponse', { error: 'Not logged in' }, true);
        return;
    }
    if (!confirm('Are you sure you want to deactivate your account? This action cannot be easily undone.')) {
        return;
    }
    try {
        const { ok, data } = await apiCall('/users/me', {
            method: 'DELETE'
        });
        showResponse('deactivateResponse', data, !ok);
        if (ok) {
            clearTokens();
        }
    } catch (e) {
        showResponse('deactivateResponse', { error: e.message }, true);
    }
}

// Health Check
async function healthCheck() {
    try {
        const { ok, data } = await apiCall('/health', { noAuth: true });
        showResponse('healthResponse', data, !ok);
    } catch (e) {
        showResponse('healthResponse', { error: e.message }, true);
    }
}
