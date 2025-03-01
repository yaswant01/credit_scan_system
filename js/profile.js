document.addEventListener("DOMContentLoaded", async function() {
    // Check if user is logged in
    const user = JSON.parse(localStorage.getItem("user"));
    if (!user) {
        window.location.href = "login.html";
        return;
    }

    async function updateProfile() {
        try {
            const response = await fetch("http://127.0.0.1:5000/user/profile", {
                credentials: "include",
                headers: {
                    'Accept': 'application/json'
                }
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || "Failed to fetch profile");
            }

            const profileData = await response.json();

            // Update display
            document.getElementById("username").textContent = profileData.username;
            document.getElementById("credits").textContent = profileData.credits;

            // Update credit color based on amount
            const creditsDisplay = document.getElementById("credits");
            if (profileData.credits <= 0) {
                creditsDisplay.style.color = 'red';
            } else if (profileData.credits < 5) {
                creditsDisplay.style.color = 'orange';
            } else {
                creditsDisplay.style.color = 'green';
            }
        } catch (error) {
            console.error("Error loading profile:", error);
            showNotification("Error loading profile data", "error");
        }
    }

    // Initial profile load
    await updateProfile();

    // Handle logout
    document.getElementById("logoutBtn").addEventListener("click", async function() {
        try {
            const response = await fetch("http://127.0.0.1:5000/auth/logout", {
                method: "POST",
                credentials: "include"
            });

            if (response.ok) {
                localStorage.removeItem("user");
                window.location.href = "login.html";
            }
        } catch (error) {
            console.error("Logout error:", error);
            showNotification("Error during logout", "error");
        }
    });
});

// Add notification helper
function showNotification(message, type = 'info') {
    const notif = document.createElement('div');
    notif.className = `notification ${type}`;
    notif.textContent = message;
    
    document.body.appendChild(notif);
    
    setTimeout(() => {
        notif.remove();
    }, 3000);
}
