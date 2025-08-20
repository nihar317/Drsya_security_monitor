class DrsyaContentScript {
    constructor() {
        this.init();
    }
    
    init() {
        // Only run on DRSYA dashboard pages
        if (window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1') {
            return;
        }
        
        if (!window.location.pathname.startsWith('/') && !window.location.port === '5000') {
            return;
        }
        
        console.log('DRSYA Content Script loaded');
        
        // Enhance dashboard with extension integration
        this.enhanceDashboard();
        
        // Listen for dashboard updates
        this.monitorDashboardChanges();
    }
    
    enhanceDashboard() {
        // Add extension status indicator
        const header = document.querySelector('.header-right');
        if (header) {
            const extensionStatus = document.createElement('div');
            extensionStatus.className = 'status-badge status-active';
            extensionStatus.innerHTML = `
                <div class="status-dot"></div>
                <span>Extension Connected</span>
            `;
            extensionStatus.style.marginLeft = '10px';
            header.appendChild(extensionStatus);
        }
        
        // Add quick extension controls
        this.addExtensionControls();
    }
    
    addExtensionControls() {
        const dashboard = document.querySelector('.dashboard-content');
        if (dashboard) {
            const extControls = document.createElement('div');
            extControls.className = 'extension-controls';
            extControls.innerHTML = `
                <div style="background: var(--bg-secondary); border: 1px solid var(--border-color); 
                           border-radius: 12px; padding: 15px; margin-bottom: 20px;">
                    <div style="font-size: 14px; font-weight: 600; margin-bottom: 10px; color: var(--accent-purple);">
                        🧩 Extension Integration
                    </div>
                    <div style="font-size: 12px; color: var(--text-secondary);">
                        Browser extension is connected and monitoring threat updates in real-time.
                        Badge will update automatically with current threat count.
                    </div>
                </div>
            `;
            
            const firstChild = dashboard.firstElementChild;
            if (firstChild) {
                dashboard.insertBefore(extControls, firstChild);
            }
        }
    }
    
    monitorDashboardChanges() {
        // Listen for threat updates
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'childList' || mutation.type === 'characterData') {
                    // Dashboard content changed, notify extension
                    this.notifyExtension();
                }
            });
        });
        
        const threatsTable = document.getElementById('threats-tbody');
        if (threatsTable) {
            observer.observe(threatsTable, {
                childList: true,
                subtree: true,
                characterData: true
            });
        }
    }
    
    notifyExtension() {
        // Send update signal to background script
        chrome.runtime.sendMessage({
            action: 'dashboardUpdate',
            timestamp: Date.now()
        });
    }
}

// Initialize content script
new DrsyaContentScript();

// popup.html
const popupHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DRSYA Security Monitor</title>
    <link rel="stylesheet" href="popup.css">
</head>
<body>
    <div class="popup-container">
        <div class="header">
            <div class="brand">
                <span class="brand-icon">🛡️</span>
                <span class="brand-text">DRSYA</span>
            </div>
            <div class="status-indicator" id="status-indicator">
                <div class="status-dot" id="status-dot"></div>
                <span class="status-text" id="status-text">Checking...</span>
            </div>
        </div>
        
        <div class="content">
            <div class="threat-summary" id="threat-summary">
                <div class="threat-card">
                    <div class="threat-number total" id="total-threats">-</div>
                    <div class="threat-label">Total</div>
                </div>
                <div class="threat-card">
                    <div class="threat-number high" id="high-threats">-</div>
                    <div class="threat-label">High</div>
                </div>
                <div class="threat-card">
                    <div class="threat-number medium" id="medium-threats">-</div>
                    <div class="threat-label">Medium</div>
                </div>
                <div class="threat-card">
                    <div class="threat-number low" id="low-threats">-</div>
                    <div class="threat-label">Low</div>
                </div>
            </div>
            
            <div class="system-info" id="system-info">
                <div class="info-row">
                    <span class="info-label">Mode:</span>
                    <span class="info-value" id="mode-value">-</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Last Scan:</span>
                    <span class="info-value" id="scan-value">-</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Uptime:</span>
                    <span class="info-value" id="uptime-value">-</span>
                </div>
            </div>
            
            <div class="actions">
                <button class="action-btn scan-btn" id="scan-btn">
                    <span class="btn-icon">🔍</span>
                    <span class="btn-text">Quick Scan</span>
                </button>
                <button class="action-btn dashboard-btn" id="dashboard-btn">
                    <span class="btn-icon">🌐</span>
                    <span class="btn-text">Open Dashboard</span>
                </button>
            </div>
        </div>
        
        <div class="footer">
            <div class="footer-text">
                <span id="last-update">Last update: Never</span>
            </div>
        </div>
    </div>
    
    <script src="popup.js"></script>
</body>
</html>`;
