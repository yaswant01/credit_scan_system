document.getElementById("registerForm").addEventListener("submit", async function(event) {
    event.preventDefault();

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const confirmPassword = document.getElementById("confirm-password").value;

    // Clear previous notifications
    hideNotification();

    // Validate inputs
    if (!username || !password || !confirmPassword) {
        showNotification("All fields are required", "error");
        return;
    }

    if (password !== confirmPassword) {
        showNotification("Passwords do not match", "error");
        return;
    }

    if (password.length < 6) {
        showNotification("Password must be at least 6 characters long", "error");
        return;
    }

    try {
        const response = await fetch("http://127.0.0.1:5000/auth/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            showNotification("Registration successful! Redirecting to login...", "success");
            setTimeout(() => {
                window.location.href = "login.html";
            }, 2000);
        } else {
            showNotification(data.error || "Registration failed", "error");
        }
    } catch (error) {
        console.error("Registration error:", error);
        showNotification("Error during registration. Please try again.", "error");
    }
});

function showNotification(message, type = 'info') {
    const notif = document.getElementById('notification');
    notif.textContent = message;
    notif.className = `notification ${type}`;
    notif.style.display = 'block';
}

function hideNotification() {
    const notif = document.getElementById('notification');
    notif.style.display = 'none';
} 