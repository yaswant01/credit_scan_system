document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('loginForm');
    const roleSelect = document.getElementById('roleSelect');
    const selectHeader = roleSelect.querySelector('.select-header');
    const optionsList = roleSelect.querySelector('.options-list');
    const selectedOption = selectHeader.querySelector('.selected-option');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');

    // Test server connection
    fetch("http://127.0.0.1:5000/", {
        method: "GET",
        credentials: 'include'
    }).catch(error => {
        showNotification("Server connection failed. Please check if the backend is running.", "error");
    });

    // Toggle password visibility
    document.querySelector('.toggle-password').addEventListener('click', function() {
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        this.querySelector('i').className = `fas fa-${type === 'password' ? 'eye' : 'eye-slash'}`;
    });

    // Role selector functionality
    selectHeader.addEventListener('click', () => {
        roleSelect.classList.toggle('open');
    });

    // Close role selector when clicking outside
    document.addEventListener('click', (e) => {
        if (!roleSelect.contains(e.target)) {
            roleSelect.classList.remove('open');
        }
    });

    // Handle role selection
    optionsList.querySelectorAll('.option').forEach(option => {
        option.addEventListener('click', () => {
            const username = option.dataset.username;
            const password = option.dataset.password;
            const role = option.dataset.role;
            
            selectedOption.textContent = option.textContent.trim();
            usernameInput.value = username;
            passwordInput.value = password;
            // Store selected role
            roleSelect.dataset.selectedRole = role;
            
            roleSelect.classList.remove('open');
        });
    });

    // Handle form submission
    loginForm.addEventListener('submit', async function(event) {
        event.preventDefault();
        
        const submitBtn = this.querySelector('button[type="submit"]');
        submitBtn.classList.add('loading');
        submitBtn.disabled = true;

        try {
            const selectedRole = roleSelect.dataset.selectedRole;
            const enteredUsername = usernameInput.value;
            const enteredPassword = passwordInput.value;

            const response = await fetch("http://127.0.0.1:5000/auth/login", {
                method: "POST",
                credentials: 'include',
                headers: { 
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    username: enteredUsername,
                    password: enteredPassword,
                    expected_role: selectedRole // Send expected role to backend
                })
            });

            const data = await response.json();

            if (response.ok) {
                // Verify role matches
                if (data.role !== selectedRole) {
                    showNotification("Invalid credentials for selected role", "error");
                    return;
                }

                // Store user data
                localStorage.setItem("user", JSON.stringify(data));
                
                // Show only the redirect overlay
                const overlay = createRedirectOverlay();
                setTimeout(() => overlay.classList.add('show'), 10);
                
                // Redirect after animation
                setTimeout(() => {
                    window.location.href = data.role === 'admin' ? 'admin.html' : 'profile.html';
                }, 1500);
            } else {
                showNotification(data.error || "Login failed", "error");
            }
        } catch (error) {
            console.error('Login error:', error);
            showNotification("Connection error. Please check if the server is running.", "error");
        } finally {
            submitBtn.classList.remove('loading');
            submitBtn.disabled = false;
        }
    });
});

function createNotificationContainer() {
    const container = document.createElement('div');
    container.className = 'notification-container';
    document.body.appendChild(container);
    return container;
}

function createRedirectOverlay() {
    const overlay = document.createElement('div');
    overlay.className = 'redirect-overlay';
    overlay.innerHTML = `
        <div class="redirect-spinner"></div>
        <div class="redirect-message">
            <h3>Login Successful!</h3>
            <p>Redirecting to dashboard...</p>
        </div>
    `;
    document.body.appendChild(overlay);
    return overlay;
}

function showNotification(message, type = 'info') {
    const container = document.querySelector('.notification-container') || createNotificationContainer();
    
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    // Add appropriate icon based on type
    let icon = 'info-circle';
    if (type === 'success') icon = 'check-circle';
    if (type === 'error') icon = 'exclamation-circle';
    
    notification.innerHTML = `
        <i class="fas fa-${icon}"></i>
        <span>${message}</span>
    `;
    
    container.appendChild(notification);
    
    // Trigger animation
    setTimeout(() => notification.classList.add('show'), 10);
    
    // Remove notification after delay
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}
