const API_URL = "http://localhost:8000";

// ===== LOGIN =====
const loginForm = document.getElementById("loginForm");
if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();

        const res = await fetch(`${API_URL}/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                email: email.value,
                password: password.value
            })
        });

        const data = await res.json();
        if (res.ok) {
            localStorage.setItem("access_token", data.access_token);
            window.location.href = "home.html";
        } else {
            response.innerText = data.detail || "Login failed";
        }
    });
}

// ===== REGISTER =====
const registerForm = document.getElementById("registerForm");
if (registerForm) {
    registerForm.addEventListener("submit", async (e) => {
        e.preventDefault();

        const res = await fetch(`${API_URL}/auth/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                email: email.value,
                username: username.value,
                password: password.value
            })
        });

        const data = await res.json();
        response.innerText = JSON.stringify(data, null, 2);
    });
}

// ===== PROFILE =====
async function getProfile() {
    const token = localStorage.getItem("access_token");
    const res = await fetch(`${API_URL}/users/me`, {
        headers: {
            Authorization: `Bearer ${token}`
        }
    });

    const data = await res.json();
    document.getElementById("username").innerText = data.username;
    document.getElementById("response").innerText =
        JSON.stringify(data, null, 2);
}

// ===== LOGOUT =====
function logout() {
    localStorage.removeItem("access_token");
    window.location.href = "index.html";
}
