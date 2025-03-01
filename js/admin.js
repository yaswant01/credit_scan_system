document.addEventListener('DOMContentLoaded', async function() {
    const user = JSON.parse(localStorage.getItem('user'));
    if (!user || user.role !== 'admin') {
        window.location.href = 'login.html';
        return;
    }

    // Load credit requests
    await loadCreditRequests();
    // Load user list
    loadUsers();

    // Logout handler
    document.getElementById('logoutBtn').addEventListener('click', async function() {
        try {
            await fetch('http://127.0.0.1:5000/auth/logout', {
                method: 'POST',
                credentials: 'include'
            });
            localStorage.removeItem('user');
            window.location.href = 'login.html';
        } catch (error) {
            console.error('Logout error:', error);
        }
    });

    // Add refresh functionality
    const refreshBtn = document.querySelector('.refresh-btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', loadCreditRequests);
    }
});

async function loadCreditRequests() {
    try {
        const response = await fetch('http://127.0.0.1:5000/admin/credit-requests', {
            credentials: 'include'
        });
        
        if (!response.ok) {
            throw new Error('Failed to load credit requests');
        }

        const data = await response.json();
        const requestsDiv = document.getElementById('creditRequests');

        if (!data.requests || data.requests.length === 0) {
            requestsDiv.innerHTML = '<p class="no-requests">No pending credit requests</p>';
            return;
        }

        requestsDiv.innerHTML = data.requests.map(request => `
            <div class="request-item">
                <div class="request-info">
                    <h3>Request from ${request.username}</h3>
                    <p>Amount: ${request.amount} credits</p>
                    <p>Requested on: ${new Date(request.request_date).toLocaleDateString()}</p>
                </div>
                <div class="request-actions">
                    <button onclick="handleRequest(${request.id}, 'approve')" class="btn primary-btn">
                        <i class="fas fa-check"></i> Approve
                    </button>
                    <button onclick="handleRequest(${request.id}, 'deny')" class="btn danger-btn">
                        <i class="fas fa-times"></i> Deny
                    </button>
                </div>
            </div>
        `).join('');

    } catch (error) {
        console.error('Error loading requests:', error);
        document.getElementById('creditRequests').innerHTML = `
            <div class="error-message">
                <p>Error loading credit requests. Please try again.</p>
                <button onclick="loadCreditRequests()" class="btn primary-btn">Retry</button>
            </div>
        `;
    }
}

async function loadUsers() {
    try {
        const response = await fetch('http://127.0.0.1:5000/admin/users', {
            credentials: 'include'
        });
        const data = await response.json();

        const usersDiv = document.getElementById('userList');
        if (!response.ok) {
            usersDiv.innerHTML = '<p class="error">Error loading users: ' + (data.error || 'Unknown error') + '</p>';
            return;
        }

        if (data.users.length === 0) {
            usersDiv.innerHTML = '<p>No users found</p>';
            return;
        }

        usersDiv.innerHTML = data.users.map(user => `
            <div class="user-item">
                <div class="user-info">
                    <h3>${user.username}</h3>
                    <p class="user-role">Role: ${user.role}</p>
                    <p class="user-credits">Credits: ${user.credits}</p>
                </div>
                <div class="user-actions">
                    <input type="number" 
                           id="credits-${user.id}" 
                           min="0" 
                           value="${user.credits}"
                           class="credit-input">
                    <button onclick="updateCredits(${user.id})" 
                            class="btn secondary-btn">
                        Update Credits
                    </button>
                    ${user.role !== 'admin' ? `
                        <button onclick="deleteUser(${user.id}, '${user.username}')" 
                                class="btn danger-btn">
                            Delete User
                        </button>
                    ` : ''}
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading users:', error);
        document.getElementById('userList').innerHTML = 
            '<p class="error">Error loading users. Please try again.</p>';
    }
}

async function handleRequest(requestId, action) {
    try {
        const response = await fetch(`http://127.0.0.1:5000/admin/credit-requests/${requestId}`, {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ action })
        });

        if (!response.ok) {
            throw new Error('Failed to process request');
        }

        // Show success notification
        showNotification(`Request ${action}ed successfully`, 'success');
        
        // Reload the requests
        await loadCreditRequests();
        
        // Reload user list if it exists (to update credit counts)
        if (typeof loadUsers === 'function') {
            await loadUsers();
        }

    } catch (error) {
        console.error('Error handling request:', error);
        showNotification(`Failed to ${action} request`, 'error');
    }
}

async function updateCredits(userId) {
    const newCredits = document.getElementById(`credits-${userId}`).value;
    try {
        const response = await fetch('http://127.0.0.1:5000/admin/update-credits', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ userId, credits: newCredits })
        });

        if (response.ok) {
            loadUsers(); // Reload the user list
        }
    } catch (error) {
        console.error('Error updating credits:', error);
    }
}

async function deleteUser(userId, username) {
    if (!confirm(`Are you sure you want to delete user "${username}"? This cannot be undone.`)) {
        return;
    }
    
    try {
        const response = await fetch(`http://127.0.0.1:5000/admin/users/${userId}`, {
            method: 'DELETE',
            credentials: 'include'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            loadUsers(); // Reload the user list
            showNotification('User deleted successfully', 'success');
        } else {
            showNotification(data.error || 'Failed to delete user', 'error');
        }
    } catch (error) {
        console.error('Error deleting user:', error);
        showNotification('Error deleting user', 'error');
    }
}

// Add this helper function for notifications
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

// Add a helper function to format dates
function formatDateTime(dateStr) {
    const date = new Date(dateStr);
    return new Intl.DateTimeFormat('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true
    }).format(date);
} 