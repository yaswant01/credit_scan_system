document.addEventListener('DOMContentLoaded', async function() {
    // Check if session is valid
    try {
        const sessionCheck = await fetch('http://127.0.0.1:5000/auth/check', {
            credentials: 'include'
        });
        
        if (!sessionCheck.ok) {
            localStorage.removeItem('user');
            window.location.href = 'login.html';
            return;
        }
    } catch (error) {
        console.error('Session check error:', error);
        window.location.href = 'login.html';
        return;
    }

    // Check if user is logged in
    const user = JSON.parse(localStorage.getItem('user'));
    if (!user) {
        window.location.href = 'login.html';
        return;
    }

    // Display initial credits
    const creditsDisplay = document.getElementById('credits');
    creditsDisplay.textContent = user.credits;
    updateCreditsDisplay(user.credits);

    // Load initial document history
    await loadDocumentHistory();

    // Handle file upload
    document.getElementById('uploadForm').addEventListener('submit', async function(event) {
        event.preventDefault();
        
        const fileInput = document.getElementById('document');
        const submitButton = event.submitter;
        const statusDiv = document.getElementById('uploadStatus');
        
        // Disable submit button while processing
        submitButton.disabled = true;
        statusDiv.textContent = 'Processing...';
        statusDiv.style.color = 'blue';
        
        try {
            const file = fileInput.files[0];
            if (!file) {
                throw new Error('Please select a file');
            }

            // Create FormData and append file
            const formData = new FormData();
            formData.append('document', file);
            formData.append('algorithm', document.getElementById('algorithm').value);
            
            const response = await fetch('http://127.0.0.1:5000/scan/upload', {
                method: 'POST',
                credentials: 'include',
                body: formData
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Upload failed');
            }

            const data = await response.json();
            
            // Update status and credits
            statusDiv.textContent = 'Upload successful!';
            statusDiv.style.color = 'green';
            
            // Update credits if provided in response
            if (data.credits_remaining !== undefined) {
                creditsDisplay.textContent = data.credits_remaining;
                updateCreditsDisplay(data.credits_remaining);
            }
            
            // Clear file input
            fileInput.value = '';

            // Display similar documents
            if (data.similar_documents && data.similar_documents.length > 0) {
                displaySimilarDocuments(data.similar_documents);
            } else {
                document.getElementById('similarDocs').innerHTML = '<p>No similar documents found</p>';
            }

            // Reload document history
            await loadDocumentHistory();
            
            showNotification('Document uploaded successfully', 'success');
        } catch (error) {
            console.error('Upload error:', error);
            statusDiv.textContent = error.message || 'Error uploading file';
            statusDiv.style.color = 'red';
            showNotification(error.message || 'Error uploading file', 'error');
        } finally {
            submitButton.disabled = false;
        }
    });

    // Handle credit request
    document.getElementById('requestCredits').addEventListener('click', async function() {
        const statusDiv = document.getElementById('uploadStatus');
        try {
            const response = await fetch('http://127.0.0.1:5000/credits/request', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ amount: 20 })
            });

            const data = await response.json();

            if (response.ok) {
                statusDiv.textContent = 'Credit request submitted successfully! Admin will review your request.';
                statusDiv.style.color = 'green';
            } else {
                statusDiv.textContent = data.error || 'Failed to request credits';
                statusDiv.style.color = 'red';
            }
        } catch (error) {
            console.error('Credit request error:', error);
            statusDiv.textContent = 'Error requesting credits';
            statusDiv.style.color = 'red';
        }
    });

    // Handle clear history
    document.getElementById('clearHistoryBtn').addEventListener('click', async function() {
        if (!confirm('Are you sure you want to clear your document history? This cannot be undone.')) {
            return;
        }

        try {
            const response = await fetch('http://127.0.0.1:5000/documents/clear', {
                method: 'DELETE',
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error('Failed to clear history');
            }

            await loadDocumentHistory();
            showNotification('Document history cleared successfully', 'success');
        } catch (error) {
            console.error('Error clearing history:', error);
            showNotification('Error clearing document history', 'error');
        }
    });

    // Handle export buttons
    document.getElementById('exportHistoryBtn').addEventListener('click', exportDocumentHistory);
    document.getElementById('exportPdfBtn').addEventListener('click', exportDocumentPDF);
});

async function loadDocumentHistory() {
    const historyDiv = document.getElementById('documentHistory');
    if (!historyDiv) return;
    
    try {
        const response = await fetch('http://127.0.0.1:5000/documents/history', {
            credentials: 'include',
            headers: {
                'Accept': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error('Failed to load document history');
        }

        const data = await response.json();

        if (!data.documents || data.documents.length === 0) {
            historyDiv.innerHTML = '<p class="no-documents">No documents uploaded yet.</p>';
            return;
        }

        historyDiv.innerHTML = data.documents.map(doc => `
            <div class="document-item" data-id="${doc.id}">
                <div class="document-header">
                    <h3><i class="fas fa-file-alt"></i> ${doc.filename}</h3>
                    <div class="document-actions">
                        <button class="btn view-similar-btn" onclick="viewSimilarDocuments(${doc.id})">
                            <i class="fas fa-clone"></i> View Similar
                        </button>
                        <button class="btn danger-btn" onclick="deleteDocument(${doc.id}, this)">
                            <i class="fas fa-trash"></i> Delete
                        </button>
                    </div>
                </div>
                <div class="document-info">
                    <p><i class="fas fa-calendar"></i> Uploaded: ${new Date(doc.upload_date).toLocaleString()}</p>
                    <p class="document-preview"><i class="fas fa-file-text"></i> Preview: ${doc.preview || 'No preview available'}</p>
                </div>
                <div class="similar-documents-container" id="similar-${doc.id}"></div>
            </div>
        `).join('');

    } catch (error) {
        console.error('Error loading document history:', error);
        historyDiv.innerHTML = '<p class="error">Error loading document history. Please try again.</p>';
        showNotification('Error loading document history', 'error');
    }
}

// Add function to view similar documents
async function viewSimilarDocuments(docId) {
    const container = document.getElementById(`similar-${docId}`);
    if (!container) return;

    try {
        const response = await fetch(`http://127.0.0.1:5000/documents/${docId}/similar`, {
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error('Failed to fetch similar documents');
        }

        const data = await response.json();
        
        if (!data.similar_documents || data.similar_documents.length === 0) {
            container.innerHTML = '<p class="no-similar">No similar documents found</p>';
            return;
        }

        container.innerHTML = `
            <div class="similar-documents">
                <h4>Similar Documents:</h4>
                ${data.similar_documents.map(doc => `
                    <div class="similar-document">
                        <span class="similarity-score ${getSimilarityClass(doc.similarity)}">
                            ${doc.similarity}%
                        </span>
                        <span class="similar-filename">${doc.filename}</span>
                    </div>
                `).join('')}
            </div>
        `;
    } catch (error) {
        console.error('Error fetching similar documents:', error);
        container.innerHTML = '<p class="error">Error loading similar documents</p>';
        showNotification('Error loading similar documents', 'error');
    }
}

// Add helper function for similarity class
function getSimilarityClass(similarity) {
    if (similarity >= 80) return 'high-similarity';
    if (similarity >= 50) return 'medium-similarity';
    return 'low-similarity';
}

async function deleteDocument(docId, buttonElement) {
    if (!confirm('Are you sure you want to delete this document?')) {
        return;
    }

    try {
        const response = await fetch(`http://127.0.0.1:5000/documents/${docId}`, {
            method: 'DELETE',
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error('Failed to delete document');
        }

        // Remove the document item from the UI
        const docItem = buttonElement.closest('.document-item');
        docItem.remove();

        showNotification('Document deleted successfully', 'success');

        // Check if no documents left
        const historyDiv = document.getElementById('documentHistory');
        if (!historyDiv.querySelector('.document-item')) {
            historyDiv.innerHTML = '<p>No documents uploaded yet.</p>';
        }
    } catch (error) {
        console.error('Error deleting document:', error);
        showNotification('Error deleting document', 'error');
    }
}

function updateCreditsDisplay(credits) {
    const creditsDisplay = document.getElementById('credits');
    if (!creditsDisplay) return;
    
    creditsDisplay.textContent = credits;
    
    if (credits <= 0) {
        creditsDisplay.style.color = 'red';
    } else if (credits < 5) {
        creditsDisplay.style.color = 'orange';
    } else {
        creditsDisplay.style.color = 'green';
    }
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

function validateFileInput(file) {
    if (!file) {
        throw new Error('Please select a file');
    }
    
    // Check file size (5MB limit)
    const maxSize = 5 * 1024 * 1024; // 5MB in bytes
    if (file.size > maxSize) {
        throw new Error('File size must be less than 5MB');
    }
    
    // Check file type
    if (!file.name.toLowerCase().endsWith('.txt')) {
        throw new Error('Only .txt files are allowed');
    }
}

// Add this function to handle export
async function exportDocumentHistory() {
    try {
        const response = await fetch('http://127.0.0.1:5000/documents/export', {
            credentials: 'include'
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Failed to fetch document history');
        }

        // Create user info section
        const userInfo = [
            ['User Information'],
            ['Username', data.user_info.username || 'N/A'],
            ['Role', data.user_info.role || 'N/A'],
            ['Current Credits', data.user_info.current_credits || 0],
            ['Total Documents', data.user_info.total_documents || 0],
            ['Last Reset', data.user_info.last_reset || 'Never'],
            [''],  // Empty line for spacing
        ];

        // Create credit history section (only if there's data)
        const creditHistory = data.credit_history && data.credit_history.length > 0 ? [
            ['Credit Transaction History'],
            ['Date', 'Type', 'Amount'],
            ...data.credit_history.map(trans => [
                trans.date || 'N/A',
                trans.type || 'N/A',
                trans.amount || 0
            ]),
            [''],  // Empty line for spacing
        ] : [['No Credit History Available'], ['']];

        // Create document history section
        const documentHistory = data.documents && data.documents.length > 0 ? [
            ['Document History'],
            ['Filename', 'Upload Date', 'Content', 'Similar Documents', 'ID'],
            ...data.documents.map(doc => {
                // Format similar documents as a string
                const similarDocsStr = doc.similar_documents.length > 0 
                    ? doc.similar_documents
                        .map(sd => `${sd.filename} (${sd.similarity}% match)`)
                        .join('; ')
                    : 'None';
                
                return [
                    doc.filename || 'N/A',
                    doc.upload_date || 'N/A',
                    (doc.content || '').replace(/\.{3}$/, ''),
                    similarDocsStr,
                    doc.id || 'N/A'
                ];
            })
        ] : [['No Documents Available']];

        // Combine all sections
        const csvRows = [
            [`Document Scanner - Export Report (${data.export_date || new Date().toISOString()})`],
            [''],
            ...userInfo,
            ...creditHistory,
            ...documentHistory
        ];

        // Convert to CSV with error handling
        const csvContent = csvRows.map(row => 
            row.map(cell => 
                `"${String(cell || '').replace(/"/g, '""')}"`
            ).join(',')
        ).join('\n');

        // Create and trigger download
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `document_scanner_report_${data.user_info.username || 'user'}_${new Date().toISOString().split('T')[0]}.csv`;
        
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        showNotification('Export completed successfully', 'success');
    } catch (error) {
        console.error('Export error:', error);
        showNotification('Failed to export data. Please try again.', 'error');
    }
}

// Add PDF export function
async function exportDocumentPDF() {
    try {
        const response = await fetch('http://127.0.0.1:5000/documents/export', {
            credentials: 'include'
        });
        
        const data = await response.json();
        
        // Create PDF document
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        
        // Add title and user info
        doc.setFontSize(20);
        doc.text('Document Scan Report', 15, 15);
        doc.setFontSize(12);
        doc.text(`Generated for: ${data.user_info.username}`, 15, 25);
        doc.text(`Role: ${data.user_info.role}`, 15, 32);
        doc.text(`Current Credits: ${data.user_info.current_credits}`, 15, 39);
        doc.text(`Total Documents: ${data.user_info.total_documents}`, 15, 46);
        
        // Add Credit History
        doc.setFontSize(16);
        doc.text('Credit Transaction History', 15, 60);
        doc.autoTable({
            startY: 65,
            head: [['Date', 'Type', 'Amount']],
            body: data.credit_history.map(trans => [
                trans.date,
                trans.type,
                trans.amount
            ])
        });
        
        // Add Document History
        doc.addPage();
        doc.setFontSize(16);
        doc.text('Document History', 15, 15);
        doc.autoTable({
            startY: 20,
            head: [['Filename', 'Upload Date', 'Similar Documents']],
            body: data.documents.map(doc => [
                doc.filename,
                doc.upload_date,
                doc.similar_documents.map(sd => 
                    `${sd.filename} (${sd.similarity}% match)`
                ).join('; ') || 'None'
            ])
        });
        
        // Save the PDF
        doc.save(`document_report_${data.user_info.username}_${new Date().toISOString().split('T')[0]}.pdf`);
        showNotification('PDF report generated successfully', 'success');
        
    } catch (error) {
        console.error('Error generating PDF:', error);
        showNotification('Failed to generate PDF report', 'error');
    }
}

// Add this function to display similar documents
function displaySimilarDocuments(documents) {
    const similarDocsDiv = document.getElementById('similarDocs');
    if (!documents || documents.length === 0) {
        similarDocsDiv.innerHTML = '<p class="no-similar">No similar documents found</p>';
        return;
    }

    similarDocsDiv.innerHTML = `
        <div class="similar-docs-section">
            <h3><i class="fas fa-clone"></i> Similar Documents Found</h3>
            <div class="similar-docs-list">
                ${documents.map(doc => `
                    <div class="similar-doc-item">
                        <div class="similarity-info">
                            <span class="similarity-score ${getSimilarityClass(doc.similarity)}">
                                ${doc.similarity}% Match
                            </span>
                            <span class="algorithm-used">
                                ${doc.algorithm || 'Cosine'} Similarity
                            </span>
                        </div>
                        <div class="doc-details">
                            <h4>${doc.filename}</h4>
                            <p class="preview">${doc.preview}</p>
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}

// Add these styles to your CSS
const styles = `
.similar-docs-section {
    margin-top: 20px;
    padding: 20px;
    background: #f8f9fa;
    border-radius: 8px;
    border: 1px solid var(--border-color);
}

.similar-docs-list {
    margin-top: 15px;
}

.similar-doc-item {
    padding: 15px;
    border: 1px solid #dee2e6;
    border-radius: 6px;
    margin-bottom: 10px;
    background: white;
}

.similarity-info {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 10px;
}

.similarity-score {
    padding: 4px 8px;
    border-radius: 4px;
    font-weight: bold;
}

.high-similarity {
    background: #d4edda;
    color: #155724;
}

.medium-similarity {
    background: #fff3cd;
    color: #856404;
}

.low-similarity {
    background: #f8d7da;
    color: #721c24;
}

.algorithm-used {
    color: #6c757d;
    font-size: 0.9em;
}

.doc-details h4 {
    margin: 0 0 5px 0;
    color: #2c3e50;
}

.preview {
    color: #6c757d;
    font-size: 0.9em;
    margin: 0;
}

.no-similar {
    text-align: center;
    padding: 15px;
    color: #6c757d;
    background: white;
    border-radius: 4px;
}`;

// Add the styles to the document
const styleSheet = document.createElement("style");
styleSheet.textContent = styles;
document.head.appendChild(styleSheet);