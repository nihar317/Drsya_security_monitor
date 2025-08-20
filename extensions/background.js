{
  "manifest_version": 3,
  "name": "DRSYA Security Monitor",
  "version": "2.0",
  "description": "Real-time threat monitoring from DRSYA Security Monitor",
  "permissions": [
    "storage"
  ],
  "host_permissions": [
    "http://localhost:5000/*"
  ],
  "background": {
    "service_worker": "background.js"
  },
  "action": {
    "default_popup": "popup.html",
    "default_title": "DRSYA Security Monitor"
  }
}

---SEPARATOR---

// background.js
class DrsyaBackground {
    constructor() {
        this.apiBase = 'http://localhost:5000/api';
        this.updateThreatData();
        
        // Set up periodic updates
        setInterval(() => {
            this.updateThreatData();
        }, 10000); // Every 10 seconds
    }
    
    async updateThreatData() {
        try {
            const response = await fetch(`${this.apiBase}/threats`);
            
            if (response.ok) {
                const data = await response.json();
                
                if (data.success) {
                    const threatCount = data.data.summary.total;
                    const isActive = data.data.status.active;
                    
                    // Update badge
                    if (isActive) {
                        chrome.action.setBadgeText({ text: threatCount.toString() });
                        chrome.action.setBadgeBackgroundColor({ 
                            color: this.getThreatColor(threatCount) 
                        });
                    } else {
                        chrome.action.setBadgeText({ text: 'OFF' });
                        chrome.action.setBadgeBackgroundColor({ color: '#666666' });
                    }
                    
                    // Store data for popup
                    chrome.storage.local.set({
                        drsyaData: data.data,
                        lastUpdate: Date.now()
                    });
                } else {
                    throw new Error('API error');
                }
            } else {
                throw new Error(`HTTP ${response.status}`);
            }
        } catch (error) {
            console.log('DRSYA API not available');
            chrome.action.setBadgeText({ text: 'OFF' });
            chrome.action.setBadgeBackgroundColor({ color: '#666666' });
        }
    }
    
    getThreatColor(count) {
        if (count === 0) return '#3fb950'; // Green
        if (count <= 3) return '#d29922';  // Orange
        return '#f85149'; // Red
    }
}

// Initialize
new DrsyaBackground();
