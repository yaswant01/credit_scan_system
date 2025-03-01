document.addEventListener('DOMContentLoaded', async function() {
    const user = JSON.parse(localStorage.getItem('user'));
    if (!user || user.role !== 'admin') {
        window.location.href = 'login.html';
        return;
    }

    // Initialize chart instances as null
    window.charts = {
        dailyScans: null,
        topUsers: null,
        topics: null
    };

    await loadAnalytics();

    // Add refresh button functionality
    document.getElementById('refreshBtn').addEventListener('click', async function() {
        this.disabled = true;
        try {
            await loadAnalytics();
            showNotification('Analytics refreshed successfully', 'success');
        } catch (error) {
            showNotification('Failed to refresh analytics', 'error');
        } finally {
            this.disabled = false;
        }
    });
});

async function loadAnalytics() {
    try {
        const response = await fetch('http://127.0.0.1:5000/admin/analytics', {
            credentials: 'include'
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        
        // Update quick stats
        document.getElementById('totalUsers').textContent = data.credit_stats.length;
        document.getElementById('totalScans').textContent = data.daily_scans.reduce((acc, curr) => acc + curr.scan_count, 0);
        document.getElementById('activeUsers').textContent = data.daily_scans.filter(scan => 
            new Date(scan.scan_date).toDateString() === new Date().toDateString()
        ).length;
        
        // Update pending requests count using the new field
        document.getElementById('pendingRequests').textContent = data.pending_requests;

        // Create charts
        createDailyScansChart(data.daily_scans);
        createTopUsersChart(data.top_users);
        createTopicsChart(data.common_topics);
        
        // Display credit statistics
        displayCreditStats(data.credit_stats);

    } catch (error) {
        console.error('Error loading analytics:', error);
        // Show user-friendly error message on the dashboard
        const containers = [
            'dailyScansChart',
            'topUsersChart',
            'topicsChart',
            'creditStats'
        ];
        
        containers.forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                element.innerHTML = `
                    <div class="error-message">
                        <p>Unable to load analytics data. Please try again later.</p>
                        <button onclick="loadAnalytics()">Retry</button>
                    </div>
                `;
            }
        });
        
        // Update quick stats with error state
        ['totalUsers', 'totalScans', 'activeUsers', 'pendingRequests'].forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = 'Error';
            }
        });
    }
}

function displayAnalytics(analyticsData) {
    const container = document.getElementById('analytics-container');
    container.innerHTML = ''; // Clear previous content
    
    analyticsData.forEach(item => {
        const card = document.createElement('div');
        card.className = 'analytics-card';
        card.innerHTML = `
            <h3>${item.title}</h3>
            <p class="analytics-value">${item.value}</p>
            <p class="analytics-date">${new Date(item.timestamp).toLocaleDateString()}</p>
        `;
        container.appendChild(card);
    });
}

function createDailyScansChart(data) {
    const ctx = document.getElementById('dailyScansChart').getContext('2d');
    
    // Destroy existing chart if it exists
    if (window.charts.dailyScans) {
        window.charts.dailyScans.destroy();
    }

    // Process data for chart
    const dates = [...new Set(data.map(d => d.scan_date))].sort();
    const scansPerDate = dates.map(date => {
        return data.filter(d => d.scan_date === date)
            .reduce((sum, curr) => sum + curr.scan_count, 0);
    });

    window.charts.dailyScans = new Chart(ctx, {
        type: 'line',
        data: {
            labels: dates,
            datasets: [{
                label: 'Daily Scans',
                data: scansPerDate,
                borderColor: '#007bff',
                tension: 0.1,
                fill: false
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });
}

function createTopUsersChart(data) {
    const ctx = document.getElementById('topUsersChart').getContext('2d');
    
    // Destroy existing chart if it exists
    if (window.charts.topUsers) {
        window.charts.topUsers.destroy();
    }

    window.charts.topUsers = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.map(u => u.username),
            datasets: [{
                label: 'Total Scans',
                data: data.map(u => u.total_scans),
                backgroundColor: '#28a745'
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });
}

function createTopicsChart(data) {
    const ctx = document.getElementById('topicsChart').getContext('2d');
    
    // Destroy existing chart if it exists
    if (window.charts.topics) {
        window.charts.topics.destroy();
    }

    window.charts.topics = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.map(t => t.word),
            datasets: [{
                data: data.map(t => t.count),
                backgroundColor: [
                    '#007bff', '#28a745', '#dc3545', '#ffc107', '#17a2b8',
                    '#6610f2', '#fd7e14', '#20c997', '#e83e8c', '#6f42c1'
                ]
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'right'
                }
            }
        }
    });
}

function displayCreditStats(data) {
    const statsDiv = document.getElementById('creditStats');
    statsDiv.innerHTML = data.map(user => `
        <div class="stat-card">
            <h3>${user.username}</h3>
            <p>Current Credits: ${user.current_credits || 0}</p>
            <p>Documents Scanned: ${user.documents_scanned || 0}</p>
            <p>Credit Requests: ${user.credit_requests || 0}</p>
        </div>
    `).join('');
}

function showNotification(message, type = 'info') {
    const notif = document.createElement('div');
    notif.className = `notification ${type}`;
    notif.textContent = message;
    
    document.body.appendChild(notif);
    
    setTimeout(() => {
        notif.remove();
    }, 3000);
}

// Add chart type toggle functionality
function toggleChartType(chartId) {
    // Implementation for changing chart types
    // You can add this functionality later
    console.log('Toggle chart type for:', chartId);
}

// Add view toggle functionality
function toggleView(viewId) {
    // Implementation for toggling different views
    // You can add this functionality later
    console.log('Toggle view for:', viewId);
}

// Add this new function to show requests details
function showRequestsDetails(requests) {
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h2>Pending Credit Requests</h2>
                <button class="close-btn">&times;</button>
            </div>
            <div class="modal-body">
                ${requests.map(req => `
                    <div class="request-item">
                        <p><strong>User:</strong> ${req.username}</p>
                        <p><strong>Amount:</strong> ${req.amount} credits</p>
                        <p><strong>Date:</strong> ${new Date(req.request_date).toLocaleString()}</p>
                    </div>
                `).join('')}
            </div>
        </div>
    `;

    document.body.appendChild(modal);

    // Close modal when clicking close button or outside
    modal.querySelector('.close-btn').onclick = () => modal.remove();
    modal.onclick = (e) => {
        if (e.target === modal) modal.remove();
    };
}

// Add PDF export function
async function exportAnalyticsPDF() {
    try {
        const response = await fetch('http://127.0.0.1:5000/admin/analytics', {
            credentials: 'include'
        });
        
        const data = await response.json();
        
        // Create PDF document
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        
        // Add title
        doc.setFontSize(20);
        doc.text('Analytics Report', 15, 15);
        doc.setFontSize(12);
        doc.text(`Generated on: ${new Date().toLocaleString()}`, 15, 25);
        
        // Add Quick Stats
        doc.setFontSize(16);
        doc.text('Quick Statistics', 15, 40);
        doc.setFontSize(12);
        doc.text([
            `Total Users: ${data.credit_stats.length}`,
            `Total Scans: ${data.daily_scans.reduce((acc, curr) => acc + curr.scan_count, 0)}`,
            `Active Users Today: ${data.daily_scans.filter(scan => 
                new Date(scan.scan_date).toDateString() === new Date().toDateString()
            ).length}`
        ], 15, 50);

        // Add Top Users Table
        doc.setFontSize(16);
        doc.text('Top Users by Scan Count', 15, 80);
        doc.autoTable({
            startY: 85,
            head: [['Username', 'Total Scans']],
            body: data.top_users.map(user => [
                user.username,
                user.total_scans
            ])
        });

        // Add Credit Statistics
        doc.addPage();
        doc.setFontSize(16);
        doc.text('Credit Usage Statistics', 15, 15);
        doc.autoTable({
            startY: 20,
            head: [['Username', 'Current Credits', 'Documents Scanned', 'Credit Requests']],
            body: data.credit_stats.map(stat => [
                stat.username,
                stat.current_credits,
                stat.documents_scanned,
                stat.credit_requests
            ])
        });

        // Add Common Topics
        doc.setFontSize(16);
        doc.text('Common Document Topics', 15, doc.autoTable.previous.finalY + 20);
        doc.autoTable({
            startY: doc.autoTable.previous.finalY + 25,
            head: [['Topic', 'Frequency']],
            body: data.common_topics.map(topic => [
                topic.word,
                topic.count
            ])
        });

        // Save the PDF
        doc.save(`analytics_report_${new Date().toISOString().split('T')[0]}.pdf`);
        showNotification('PDF report generated successfully', 'success');
        
    } catch (error) {
        console.error('Error generating PDF:', error);
        showNotification('Failed to generate PDF report', 'error');
    }
}

// Add event listener for PDF export button
document.getElementById('exportPdfBtn').addEventListener('click', exportAnalyticsPDF); 