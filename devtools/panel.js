let port = browser.runtime.connect({ name: 'devtools-panel' });
let inspectedTabId = browser.devtools.inspectedWindow.tabId;
let requests = [];
let selectedRequest = null;

// Send the inspected tab ID to background script
port.postMessage({ type: 'setInspectedTab', tabId: inspectedTabId });
let currentRequestView = 'raw';
let currentResponseView = 'raw';
let currentModifiedView = 'raw';
let currentTab = 'request';
let interceptedRequest = null;
let interceptQueue = [];
let hiddenTypes = new Set();
let interceptSettings = {
    methods: ['POST', 'PUT', 'PATCH', 'DELETE'],
    includeGET: false,
    urlPatterns: [],
    excludePatterns: [],
    excludeExtensions: ['css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'ico', 'svg', 'woff', 'woff2', 'ttf', 'eot'],
    interceptResponses: false
};
let interceptedResponse = null;
let responseQueue = [];
let interceptHeadersEdited = false;
let currentSortColumn = null;
let currentSortDirection = 'asc';
let requestCounter = 0;
let highlightRules = [];
let matchReplaceRules = [];

// Use devtools.network API to catch service worker responses that bypass webRequest API
let pendingHarEntries = []; // Buffer for HAR events that haven't matched yet

function updateRequestFromHar(request, harEntry) {
    const statusCode = harEntry.response?.status;
    const statusText = harEntry.response?.statusText || '';
    
    request.statusCode = statusCode;
    request.statusLine = `HTTP/1.1 ${statusCode} ${statusText}`;
    request.completed = true;
    
    // Extract request headers from HAR
    if (harEntry.request?.headers && (!request.requestHeaders || Object.keys(request.requestHeaders).length === 0)) {
        request.requestHeaders = {};
        for (const header of harEntry.request.headers) {
            request.requestHeaders[header.name] = header.value;
        }
    }
    
    // Extract request body from HAR (for POST/PUT requests)
    if (harEntry.request?.postData && !request.requestBody) {
        request.requestBody = harEntry.request.postData.text || '';
        if (harEntry.request.postData.params && !request.requestBody) {
            // URL-encoded form data
            request.requestBody = harEntry.request.postData.params
                .map(p => `${encodeURIComponent(p.name)}=${encodeURIComponent(p.value || '')}`)
                .join('&');
        }
    }
    
    // Extract request size
    if (harEntry.request?.bodySize > 0 && !request.requestSize) {
        request.requestSize = harEntry.request.bodySize;
    }
    
    // Extract response headers from HAR
    if (harEntry.response?.headers && (!request.responseHeaders || Object.keys(request.responseHeaders).length === 0)) {
        request.responseHeaders = {};
        for (const header of harEntry.response.headers) {
            request.responseHeaders[header.name] = header.value;
        }
    }
    
    // Extract response size
    if (harEntry.response?.bodySize > 0) {
        request.responseSize = harEntry.response.bodySize;
    } else if (harEntry.response?.content?.size > 0) {
        request.responseSize = harEntry.response.content.size;
    }
    
    // Try to get response body from HAR content.text first (available in getHAR results)
    if (harEntry.response?.content?.text && !request.responseBody) {
        request.responseBody = harEntry.response.content.text;
    }
    
    // Try to get response body via getContent() if available (only works on event listener entries)
    if (typeof harEntry.getContent === 'function' && !request.responseBody) {
        harEntry.getContent((content, encoding) => {
            if (content) {
                request.responseBody = content;
                // Re-render if this request is selected
                if (selectedRequest && selectedRequest.id === request.id) {
                    displayRequestDetails(request);
                }
            }
        });
    }
}

function tryMatchHarEntry(harEntry) {
    const url = harEntry.request?.url;
    if (!url) return false;
    
    // Find matching request by URL - search from newest to oldest
    for (let i = requests.length - 1; i >= 0; i--) {
        const r = requests[i];
        if (r.url === url && (r.statusCode === null || r.statusCode === undefined)) {
            updateRequestFromHar(r, harEntry);
            return true;
        }
    }
    return false;
}

function processPendingHarEntries() {
    if (pendingHarEntries.length === 0) return;
    
    const stillPending = [];
    let matched = false;
    for (const harEntry of pendingHarEntries) {
        if (!tryMatchHarEntry(harEntry)) {
            // Keep entries that are less than 5 seconds old
            if (Date.now() - harEntry._timestamp < 5000) {
                stillPending.push(harEntry);
            }
        } else {
            matched = true;
        }
    }
    pendingHarEntries = stillPending;
    
    if (matched) {
        renderRequestList();
    }
}

if (browser.devtools && browser.devtools.network) {
    // Listen for request completions from devtools.network API
    browser.devtools.network.onRequestFinished.addListener((harEntry) => {
        const url = harEntry.request?.url;
        const statusCode = harEntry.response?.status;
        
        if (!url || statusCode === undefined) return;
        
        // Try to match immediately
        if (!tryMatchHarEntry(harEntry)) {
            // Buffer for later matching (request might not be in our list yet)
            harEntry._timestamp = Date.now();
            pendingHarEntries.push(harEntry);
        }
        
        renderRequestList();
        if (selectedRequest) {
            const updated = requests.find(r => r.id === selectedRequest.id);
            if (updated) displayRequestDetails(updated);
        }
    });
    
    // Periodically try to match buffered HAR entries
    setInterval(processPendingHarEntries, 500);
    
    // Poll getHAR periodically to catch any completions missed by the event listener
    setInterval(() => {
        browser.devtools.network.getHAR().then(harLog => {
            if (!harLog || !harLog.entries) return;
            
            let updated = false;
            for (const entry of harLog.entries) {
                const url = entry.request?.url;
                const statusCode = entry.response?.status;
                if (!url || !statusCode) continue;
                
                // Find a pending request with this URL
                for (let i = requests.length - 1; i >= 0; i--) {
                    const r = requests[i];
                    if (r.url === url && (r.statusCode === null || r.statusCode === undefined)) {
                        updateRequestFromHar(r, entry);
                        updated = true;
                        break;
                    }
                }
            }
            
            if (updated) {
                renderRequestList();
            }
        }).catch(() => {});
    }, 1000);
}

// Security Scanner State
let securityFindings = []; // All findings from all requests
let libraryFindings = []; // Vulnerable library findings
let unseenFindingsCount = 0; // Number of unseen findings (for badge)
let requestFindings = new Map(); // Map of requestId -> findings
let requestLibraryFindings = new Map(); // Map of requestId -> library findings

// Theme Management
let currentTheme = 'auto'; // 'auto', 'light', or 'dark'
let browserPrefersDark = window.matchMedia('(prefers-color-scheme: dark)');

// Column Resizing
let isResizing = false;
let currentResizer = null;
let currentColumn = null;
let startX = 0;
let startWidth = 0;

// Default column widths (in pixels)
const defaultColumnWidths = {
    number: 60,
    method: 100,
    host: 200,
    url: 250,
    status: 90,
    reqSize: 100,
    resSize: 100,
    type: 100
};

// Minimum column widths (in pixels)
const minColumnWidths = {
    number: 40,
    method: 80,
    host: 120,
    url: 150,
    status: 70,
    reqSize: 80,
    resSize: 80,
    type: 80
};

// Initialize theme and column resizing on load
initializeTheme();
initializeColumnResizing();

function initializeTheme() {
    // Load saved theme preference
    browser.storage.local.get('theme').then(result => {
        if (result.theme) {
            currentTheme = result.theme;
        }
        applyTheme();
        updateThemeButton();
    }).catch(() => {
        // If storage fails, use default
        applyTheme();
        updateThemeButton();
    });
    
    // Listen for browser theme changes (only when in auto mode)
    browserPrefersDark.addEventListener('change', (e) => {
        if (currentTheme === 'auto') {
            applyTheme();
        }
    });
}

function applyTheme() {
    const shouldUseDarkMode = currentTheme === 'dark' || 
                             (currentTheme === 'auto' && browserPrefersDark.matches);
    
    if (shouldUseDarkMode) {
        document.body.classList.add('dark-mode');
    } else {
        document.body.classList.remove('dark-mode');
    }
}

function updateThemeButton() {
    const themeBtn = document.getElementById('themeToggleBtn');
    const themeIcon = themeBtn.querySelector('.theme-icon');
    
    // Update icon based on current theme
    if (currentTheme === 'auto') {
        themeIcon.textContent = '🔄';
        themeBtn.title = 'Theme: Auto (following browser)';
    } else if (currentTheme === 'light') {
        themeIcon.textContent = '☀️';
        themeBtn.title = 'Theme: Light';
    } else {
        themeIcon.textContent = '🌙';
        themeBtn.title = 'Theme: Dark';
    }
}

function toggleTheme() {
    // Cycle through: auto → light → dark → auto
    if (currentTheme === 'auto') {
        currentTheme = 'light';
    } else if (currentTheme === 'light') {
        currentTheme = 'dark';
    } else {
        currentTheme = 'auto';
    }
    
    // Save preference
    browser.storage.local.set({ theme: currentTheme }).catch(err => {
        console.error('Failed to save theme preference:', err);
    });
    
    applyTheme();
    updateThemeButton();
}

// Column Resizing Functions
function initializeColumnResizing() {
    // Load saved column widths
    applyColumnWidths();
    
    // Load highlight rules
    const savedRules = localStorage.getItem('highlightRules');
    if (savedRules) {
        try {
            highlightRules = JSON.parse(savedRules);
        } catch (e) {
            console.error('Failed to parse highlight rules:', e);
        }
    }

    // Load Match & Replace rules
    const savedMRRules = localStorage.getItem('matchReplaceRules');
    if (savedMRRules) {
        try {
            matchReplaceRules = JSON.parse(savedMRRules);
            // Sync with background
            port.postMessage({
                type: 'updateMatchReplaceRules',
                rules: matchReplaceRules
            });
        } catch (e) {
            console.error('Failed to parse match & replace rules:', e);
        }
    }
    
    // Get all column resizers
    const resizers = document.querySelectorAll('.column-resizer');
    
    resizers.forEach(resizer => {
        // Mouse down on resizer
        resizer.addEventListener('mousedown', (e) => {
            e.preventDefault();
            e.stopPropagation();
            
            isResizing = true;
            currentResizer = resizer;
            currentColumn = resizer.parentElement;
            startX = e.pageX;
            startWidth = currentColumn.offsetWidth;
            
            document.body.classList.add('column-resizing');
        });
        
        // Double-click to auto-fit
        resizer.addEventListener('dblclick', (e) => {
            e.preventDefault();
            e.stopPropagation();
            
            const th = resizer.parentElement;
            const columnName = th.dataset.column;
            autoFitColumn(columnName);
        });
    });
    
    // Mouse move - resize column
    document.addEventListener('mousemove', (e) => {
        if (!isResizing) return;
        
        const width = startWidth + (e.pageX - startX);
        const columnName = currentColumn.dataset.column;
        const minWidth = minColumnWidths[columnName] || 50;
        
        if (width >= minWidth) {
            currentColumn.style.width = width + 'px';
        }
    });
    
    // Mouse up - stop resizing
    document.addEventListener('mouseup', () => {
        if (isResizing) {
            isResizing = false;
            document.body.classList.remove('column-resizing');
            
            // Save the new widths
            saveColumnWidths();
            
            currentResizer = null;
            currentColumn = null;
        }
    });
}

function applyColumnWidths() {
    const savedWidths = localStorage.getItem('columnWidths');
    let widths = defaultColumnWidths;
    
    if (savedWidths) {
        try {
            widths = JSON.parse(savedWidths);
        } catch (e) {
            console.error('Failed to parse saved column widths:', e);
        }
    }
    
    // Apply widths to all columns
    Object.keys(widths).forEach(columnName => {
        const th = document.querySelector(`th[data-column="${columnName}"]`);
        if (th) {
            th.style.width = widths[columnName] + 'px';
        }
    });
}

function saveColumnWidths() {
    const widths = {};
    const headers = document.querySelectorAll('#requestTable th[data-column]');
    
    headers.forEach(th => {
        const columnName = th.dataset.column;
        widths[columnName] = th.offsetWidth;
    });
    
    localStorage.setItem('columnWidths', JSON.stringify(widths));
}

function autoFitColumn(columnName) {
    const th = document.querySelector(`th[data-column="${columnName}"]`);
    if (!th) return;
    
    // Get all cells in this column
    const columnIndex = Array.from(th.parentElement.children).indexOf(th);
    const cells = document.querySelectorAll(`#requestTable tr td:nth-child(${columnIndex + 1})`);
    
    // Calculate maximum content width
    let maxWidth = minColumnWidths[columnName] || 50;
    
    // Measure header text
    const headerText = th.textContent.replace('▲', '').replace('▼', '').trim();
    const headerWidth = measureTextWidth(headerText, '12px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, sans-serif') + 30; // Add padding
    maxWidth = Math.max(maxWidth, headerWidth);
    
    // Measure visible cell content
    cells.forEach(cell => {
        const text = cell.textContent;
        const width = measureTextWidth(text, '12px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, sans-serif') + 20; // Add padding
        maxWidth = Math.max(maxWidth, width);
    });
    
    // Cap at reasonable maximum
    maxWidth = Math.min(maxWidth, 500);
    
    // Apply the width
    th.style.width = maxWidth + 'px';
    
    // Save the new widths
    saveColumnWidths();
}

function measureTextWidth(text, font) {
    const canvas = measureTextWidth.canvas || (measureTextWidth.canvas = document.createElement('canvas'));
    const context = canvas.getContext('2d');
    context.font = font;
    const metrics = context.measureText(text);
    return metrics.width;
}

const captureToggle = document.getElementById('captureToggle');
const interceptToggle = document.getElementById('interceptToggle');
const clearBtn = document.getElementById('clearBtn');
const filterBtn = document.getElementById('filterBtn');
const filterPanel = document.getElementById('filterPanel');
const searchInput = document.getElementById('searchInput');
const requestList = document.getElementById('requestList');
const requestContent = document.getElementById('requestContent');
const modifiedContent = document.getElementById('modifiedContent');
const responseContent = document.getElementById('responseContent');
const interceptModal = document.getElementById('interceptModal');
const copyCurlBtn = document.getElementById('copyCurlBtn');
const repeaterBtn = document.getElementById('repeaterBtn');
const repeaterModal = document.getElementById('repeaterModal');
const closeRepeaterBtn = document.getElementById('closeRepeaterBtn');
const sendRepeaterBtn = document.getElementById('sendRepeaterBtn');
const clearRepeaterBtn = document.getElementById('clearRepeaterBtn');
const interceptSettingsBtn = document.getElementById('interceptSettingsBtn');
const interceptSettingsModal = document.getElementById('interceptSettingsModal');
const closeInterceptSettingsBtn = document.getElementById('closeInterceptSettingsBtn');
const saveInterceptSettingsBtn = document.getElementById('saveInterceptSettingsBtn');
const resetInterceptSettingsBtn = document.getElementById('resetInterceptSettingsBtn');
const responseInterceptModal = document.getElementById('responseInterceptModal');
const forwardResponseBtn = document.getElementById('forwardResponseBtn');
const dropResponseBtn = document.getElementById('dropResponseBtn');
const disableInterceptBtn = document.getElementById('disableInterceptBtn');
const disableInterceptResponseBtn = document.getElementById('disableInterceptResponseBtn');
const requestSearchInput = document.getElementById('requestSearchInput');
const modifiedSearchInput = document.getElementById('modifiedSearchInput');
const responseSearchInput = document.getElementById('responseSearchInput');
const requestSearchCount = document.getElementById('requestSearchCount');
const modifiedSearchCount = document.getElementById('modifiedSearchCount');
const responseSearchCount = document.getElementById('responseSearchCount');
const themeToggleBtn = document.getElementById('themeToggleBtn');
const copyRequestBtn = document.getElementById('copyRequestBtn');
const copyResponseBtn = document.getElementById('copyResponseBtn');
const responsePreviewBtn = document.getElementById('responsePreviewBtn');
const highlightRulesBtn = document.getElementById('highlightRulesBtn');
const highlightRulesModal = document.getElementById('highlightRulesModal');
const closeHighlightRulesBtn = document.getElementById('closeHighlightRulesBtn');
const addHighlightRuleBtn = document.getElementById('addHighlightRuleBtn');
const saveHighlightRulesBtn = document.getElementById('saveHighlightRulesBtn');
const clearHighlightRulesBtn = document.getElementById('clearHighlightRulesBtn');
const highlightRulesList = document.getElementById('highlightRulesList');

const matchReplaceBtn = document.getElementById('matchReplaceBtn');
const matchReplaceModal = document.getElementById('matchReplaceModal');
const closeMatchReplaceBtn = document.getElementById('closeMatchReplaceBtn');
const addMatchReplaceRuleBtn = document.getElementById('addMatchReplaceRuleBtn');
const saveMatchReplaceRulesBtn = document.getElementById('saveMatchReplaceRulesBtn');
const clearMatchReplaceRulesBtn = document.getElementById('clearMatchReplaceRulesBtn');
const matchReplaceRulesList = document.getElementById('matchReplaceRulesList');

// Security Scanner Elements
const securityBtn = document.getElementById('securityBtn');
const securityBadge = document.getElementById('securityBadge');
const securityModal = document.getElementById('securityModal');
const closeSecurityBtn = document.getElementById('closeSecurityBtn');
const securityFindingsList = document.getElementById('securityFindingsList');
const securitySearchInput = document.getElementById('securitySearchInput');
const securityCategoryFilter = document.getElementById('securityCategoryFilter');
const securitySeverityFilter = document.getElementById('securitySeverityFilter');
const clearSecurityFindingsBtn = document.getElementById('clearSecurityFindingsBtn');
const exportAllSecurityBtn = document.getElementById('exportAllSecurityBtn');
const securityTabBtn = document.getElementById('securityTabBtn');
const securityTabBadge = document.getElementById('securityTabBadge');
const securityTabContent = document.getElementById('securityTabContent');
const exportSecurityFindingsBtn = document.getElementById('exportSecurityFindingsBtn');

let currentRepeaterTab = 'headers';
let lastRepeaterResponse = null;

// Highlight Rules Event Listeners
highlightRulesBtn.addEventListener('click', () => {
    renderHighlightRules();
    highlightRulesModal.classList.add('show');
});

closeHighlightRulesBtn.addEventListener('click', () => {
    highlightRulesModal.classList.remove('show');
});

addHighlightRuleBtn.addEventListener('click', () => {
    const pattern = document.getElementById('newRulePattern').value.trim();
    const color = document.getElementById('newRuleColor').value;
    const type = document.getElementById('newRuleType').value;
    
    if (!pattern) {
        alert('Please enter a pattern');
        return;
    }
    
    if (type === 'regex') {
        try {
            new RegExp(pattern);
        } catch (e) {
            alert('Invalid regex pattern: ' + e.message);
            return;
        }
    }
    
    highlightRules.push({ pattern, color, type, enabled: true });
    document.getElementById('newRulePattern').value = '';
    renderHighlightRules();
    saveHighlightRules();
});

// Match & Replace Event Listeners
matchReplaceBtn.addEventListener('click', () => {
    renderMatchReplaceRules();
    matchReplaceModal.classList.add('show');
});

closeMatchReplaceBtn.addEventListener('click', () => {
    matchReplaceModal.classList.remove('show');
});

addMatchReplaceRuleBtn.addEventListener('click', () => {
    const matchPattern = document.getElementById('mrMatchPattern').value.trim();
    const replaceValue = document.getElementById('mrReplaceValue').value;
    const target = document.getElementById('mrTarget').value;
    const matchType = document.getElementById('mrMatchType').value;
    
    if (!matchPattern) {
        alert('Please enter a match pattern');
        return;
    }
    
    // Check both settings object and DOM element to be safe
    const earlyInterceptEnabled = interceptSettings.useEarlyInterception || document.getElementById('useEarlyInterception').checked;
    
    if (target === 'body' && !earlyInterceptEnabled) {
        alert('Notice: Body modification requires the request to be cancelled and resent. The original page might see the request as cancelled, but the server will receive the modified request.');
    }
    
    if (matchType === 'regex') {
        try {
            new RegExp(matchPattern);
        } catch (e) {
            alert('Invalid regex pattern: ' + e.message);
            return;
        }
    }
    
    matchReplaceRules.push({ 
        matchPattern, 
        replaceValue, 
        target,
        matchType,
        enabled: true,
        id: Date.now().toString()
    });
    
    // Clear form
    document.getElementById('mrMatchPattern').value = '';
    document.getElementById('mrReplaceValue').value = '';
    
    renderMatchReplaceRules();
});

saveMatchReplaceRulesBtn.addEventListener('click', () => {
    saveMatchReplaceRules();
    matchReplaceModal.classList.remove('show');
});

clearMatchReplaceRulesBtn.addEventListener('click', () => {
    if (clearMatchReplaceRulesBtn.textContent === 'Confirm?') {
        matchReplaceRules = [];
        renderMatchReplaceRules();
        saveMatchReplaceRules();
        clearMatchReplaceRulesBtn.textContent = 'Clear All';
        clearMatchReplaceRulesBtn.classList.remove('confirm-state');
    } else {
        const originalText = clearMatchReplaceRulesBtn.textContent;
        clearMatchReplaceRulesBtn.textContent = 'Confirm?';
        clearMatchReplaceRulesBtn.classList.add('confirm-state');
        
        setTimeout(() => {
            if (clearMatchReplaceRulesBtn.textContent === 'Confirm?') {
                clearMatchReplaceRulesBtn.textContent = originalText;
                clearMatchReplaceRulesBtn.classList.remove('confirm-state');
            }
        }, 3000);
    }
});

function renderMatchReplaceRules() {
    matchReplaceRulesList.innerHTML = '';
    
    if (matchReplaceRules.length === 0) {
        matchReplaceRulesList.innerHTML = '<div style="padding:10px;color:#888;">No rules defined</div>';
        return;
    }
    
    matchReplaceRules.forEach((rule, index) => {
        const item = document.createElement('div');
        item.className = 'rule-item';
        item.style.flexDirection = 'column';
        item.style.alignItems = 'flex-start';
        
        const header = document.createElement('div');
        header.style.display = 'flex';
        header.style.width = '100%';
        header.style.justifyContent = 'space-between';
        header.style.marginBottom = '5px';
        
        const title = document.createElement('span');
        const typeLabel = rule.matchType ? `[${rule.matchType}] ` : '[regex] ';
        title.innerHTML = `<strong>${rule.target.toUpperCase()}</strong>: <small>${typeLabel}</small><code>${escapeHTML(rule.matchPattern)}</code> → <code>${escapeHTML(rule.replaceValue)}</code>`;
        
        const controls = document.createElement('div');
        
        const toggleCheck = document.createElement('input');
        toggleCheck.type = 'checkbox';
        toggleCheck.checked = rule.enabled;
        toggleCheck.style.marginRight = '10px';
        toggleCheck.onchange = () => {
            rule.enabled = toggleCheck.checked;
            saveMatchReplaceRules();
        };
        
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'rule-delete-btn';
        deleteBtn.innerHTML = '&times;';
        deleteBtn.onclick = () => {
            matchReplaceRules.splice(index, 1);
            renderMatchReplaceRules();
        };
        
        controls.appendChild(toggleCheck);
        controls.appendChild(deleteBtn);
        
        header.appendChild(title);
        header.appendChild(controls);
        
        item.appendChild(header);
        matchReplaceRulesList.appendChild(item);
    });
}

function saveMatchReplaceRules() {
    localStorage.setItem('matchReplaceRules', JSON.stringify(matchReplaceRules));
    port.postMessage({
        type: 'updateMatchReplaceRules',
        rules: matchReplaceRules
    });
}

saveHighlightRulesBtn.addEventListener('click', () => {
    saveHighlightRules();
    highlightRulesModal.classList.remove('show');
    renderRequestList();
});

clearHighlightRulesBtn.addEventListener('click', () => {
    if (clearHighlightRulesBtn.textContent === 'Confirm?') {
        highlightRules = [];
        renderHighlightRules();
        saveHighlightRules();
        renderRequestList();
        clearHighlightRulesBtn.textContent = 'Clear All';
        clearHighlightRulesBtn.classList.remove('confirm-state');
    } else {
        const originalText = clearHighlightRulesBtn.textContent;
        clearHighlightRulesBtn.textContent = 'Confirm?';
        clearHighlightRulesBtn.classList.add('confirm-state');
        
        setTimeout(() => {
            if (clearHighlightRulesBtn.textContent === 'Confirm?') {
                clearHighlightRulesBtn.textContent = originalText;
                clearHighlightRulesBtn.classList.remove('confirm-state');
            }
        }, 3000);
    }
});

function renderHighlightRules() {
    highlightRulesList.innerHTML = '';
    
    if (highlightRules.length === 0) {
        highlightRulesList.innerHTML = '<div style="padding:10px;color:#888;">No rules defined</div>';
        return;
    }
    
    highlightRules.forEach((rule, index) => {
        const item = document.createElement('div');
        item.className = 'rule-item';
        
        const colorPreview = document.createElement('div');
        colorPreview.className = 'rule-color-preview';
        colorPreview.style.backgroundColor = rule.color;
        
        const patternText = document.createElement('span');
        patternText.className = 'rule-pattern';
        const typeLabel = rule.type ? `[${rule.type}] ` : '[regex] ';
        patternText.textContent = typeLabel + rule.pattern;
        
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'rule-delete-btn';
        deleteBtn.innerHTML = '&times;';
        deleteBtn.onclick = () => {
            highlightRules.splice(index, 1);
            renderHighlightRules();
            saveHighlightRules();
        };
        
        item.appendChild(colorPreview);
        item.appendChild(patternText);
        item.appendChild(deleteBtn);
        
        highlightRulesList.appendChild(item);
    });
}

function saveHighlightRules() {
    localStorage.setItem('highlightRules', JSON.stringify(highlightRules));
}

// ==========================================
// SECURITY SCANNER EVENT LISTENERS
// ==========================================

// Open Security Modal
securityBtn.addEventListener('click', () => {
    // Mark all findings as seen
    unseenFindingsCount = 0;
    updateSecurityBadge();
    
    // Render and show modal
    renderSecurityModal();
    securityModal.classList.add('show');
});

// Close Security Modal
closeSecurityBtn.addEventListener('click', () => {
    securityModal.classList.remove('show');
});

// Security Search
securitySearchInput.addEventListener('input', () => {
    renderSecurityFindingsList();
});

// Security Category Filter
securityCategoryFilter.addEventListener('change', () => {
    renderSecurityFindingsList();
});

// Security Severity Filter
securitySeverityFilter.addEventListener('change', () => {
    renderSecurityFindingsList();
});

// Clear All Security Findings
clearSecurityFindingsBtn.addEventListener('click', () => {
    if (clearSecurityFindingsBtn.textContent === 'Confirm?') {
        securityFindings = [];
        libraryFindings = [];
        requestFindings.clear();
        requestLibraryFindings.clear();
        unseenFindingsCount = 0;
        updateSecurityBadge();
        renderSecurityModal();
        renderRequestList(); // Update request list to remove security indicators
        clearSecurityFindingsBtn.textContent = 'Clear All';
        clearSecurityFindingsBtn.classList.remove('confirm-state');
        // Also notify background to clear
        port.postMessage({ type: 'clearSecurityFindings' });
        port.postMessage({ type: 'clearLibraryFindings' });
    } else {
        clearSecurityFindingsBtn.textContent = 'Confirm?';
        clearSecurityFindingsBtn.classList.add('confirm-state');
        
        setTimeout(() => {
            if (clearSecurityFindingsBtn.textContent === 'Confirm?') {
                clearSecurityFindingsBtn.textContent = 'Clear All';
                clearSecurityFindingsBtn.classList.remove('confirm-state');
            }
        }, 3000);
    }
});

// Export All Security Findings
exportAllSecurityBtn.addEventListener('click', () => {
    const allFindings = {
        securityFindings: securityFindings,
        libraryFindings: libraryFindings,
        exportedAt: new Date().toISOString()
    };
    const blob = new Blob([JSON.stringify(allFindings, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'all-security-findings.json';
    a.click();
    URL.revokeObjectURL(url);
});

// Export Security Findings for Selected Request
exportSecurityFindingsBtn.addEventListener('click', () => {
    if (selectedRequest && requestFindings.has(selectedRequest.id)) {
        const findings = requestFindings.get(selectedRequest.id);
        exportSecurityFindings([findings], `security-findings-${selectedRequest.id}.json`);
    }
});

// ==========================================
// SECURITY SCANNER FUNCTIONS
// ==========================================

/**
 * Scan a request's response body for security issues
 */
function scanRequestForSecurity(request) {
    if (!request.responseBody || !SecurityScanner) {
        return null;
    }
    
    // Check if content type is scannable
    const contentType = Object.entries(request.responseHeaders || {})
        .find(([key]) => key.toLowerCase() === 'content-type')?.[1] || '';
    
    if (!SecurityScanner.isScannable(contentType)) {
        return null;
    }
    
    // Scan the content
    const results = SecurityScanner.scan(request.responseBody, request.url);
    
    if (results) {
        results.requestId = request.id;
        results.requestNumber = request.requestNumber;
    }
    
    return results;
}

/**
 * Process security scan results for a request
 */
function processSecurityResults(request, results) {
    if (!results) return;
    
    // Store findings
    requestFindings.set(request.id, results);
    securityFindings.push(results);
    
    // Count significant findings for the badge
    const significantCount = 
        results.apiKeys.length +
        results.credentials.length;
    
    if (significantCount > 0) {
        unseenFindingsCount += significantCount;
        updateSecurityBadge();
    }
    
    // Mark request as having findings
    request.hasSecurityFindings = true;
    request.securityFindingsCount = results.totalFindings;
}

/**
 * Update the security badge count
 */
function updateSecurityBadge() {
    if (unseenFindingsCount > 0) {
        securityBadge.textContent = unseenFindingsCount > 99 ? '99+' : unseenFindingsCount;
        securityBadge.style.display = 'flex';
    } else {
        securityBadge.style.display = 'none';
    }
}

/**
 * Render the security modal with all findings
 */
function renderSecurityModal() {
    // Update summary counts
    let apiKeyCount = 0, credentialCount = 0, emailCount = 0, endpointCount = 0, pathCount = 0, libraryCount = 0;
    
    securityFindings.forEach(finding => {
        // Handle findings from both panel scanner and background scanner
        // Background scanner only provides apiKeys and credentials
        apiKeyCount += (finding.apiKeys || []).length;
        credentialCount += (finding.credentials || []).length;
        emailCount += (finding.emails || []).length;
        endpointCount += (finding.apiEndpoints || []).length;
        pathCount += (finding.paths || []).length;
    });
    
    // Count unique vulnerable library+version combinations
    const uniqueLibs = new Set();
    libraryFindings.forEach(finding => {
        (finding.libraries || []).forEach(lib => {
            uniqueLibs.add(`${lib.library}@${lib.version}`);
        });
    });
    libraryCount = uniqueLibs.size;
    
    document.getElementById('summaryApiKeys').textContent = apiKeyCount;
    document.getElementById('summaryCredentials').textContent = credentialCount;
    document.getElementById('summaryLibraries').textContent = libraryCount;
    document.getElementById('summaryEmails').textContent = emailCount;
    document.getElementById('summaryEndpoints').textContent = endpointCount;
    document.getElementById('summaryPaths').textContent = pathCount;
    
    // Update modal badge
    const totalSignificant = apiKeyCount + credentialCount + libraryCount;
    document.getElementById('securityModalBadge').textContent = totalSignificant;
    
    // Render the findings list
    renderSecurityFindingsList();
}

/**
 * Render the security findings list with filters
 */
function renderSecurityFindingsList() {
    const searchTerm = securitySearchInput.value.toLowerCase();
    const categoryFilter = securityCategoryFilter.value;
    const severityFilter = securitySeverityFilter.value;
    
    securityFindingsList.innerHTML = '';
    
    const hasSecurityFindings = securityFindings.length > 0;
    const hasLibraryFindings = libraryFindings.length > 0;
    
    if (!hasSecurityFindings && !hasLibraryFindings) {
        securityFindingsList.innerHTML = `
            <div class="security-no-findings">
                <p>No security findings yet. Start browsing with capture enabled to scan response bodies.</p>
            </div>
        `;
        return;
    }
    
    // Group findings by URL
    const groupedFindings = new Map();
    
    // Process security findings
    if (categoryFilter !== 'vulnerableLibraries') {
        securityFindings.forEach(finding => {
            const url = finding.url;
            if (!groupedFindings.has(url)) {
                groupedFindings.set(url, {
                    url: url,
                    requestId: finding.requestId,
                    requestNumber: finding.requestNumber,
                    items: []
                });
            }
            
            const group = groupedFindings.get(url);
            
            // Add items based on category filter
            const categories = categoryFilter === 'all' 
                ? ['apiKeys', 'credentials', 'emails', 'apiEndpoints', 'parameters', 'paths']
                : [categoryFilter];
            
            categories.forEach(cat => {
                if (finding[cat]) {
                    finding[cat].forEach(item => {
                        // Apply severity filter
                        if (severityFilter !== 'all' && item.severity !== severityFilter) {
                            return;
                        }
                        
                        // Apply search filter
                        if (searchTerm) {
                            const searchable = `${item.type} ${item.match} ${item.context || ''}`.toLowerCase();
                            if (!searchable.includes(searchTerm)) {
                                return;
                            }
                        }
                        
                        group.items.push({
                            ...item,
                            requestId: finding.requestId
                        });
                    });
                }
            });
        });
    }
    
    // Process library findings - merge same library+version vulnerabilities
    if (categoryFilter === 'all' || categoryFilter === 'vulnerableLibraries') {
        // First, collect all vulnerabilities per library+version
        const libraryVulnMap = new Map(); // key: "url|library|version" -> { vulns: [], ... }
        
        libraryFindings.forEach(finding => {
            const url = finding.url;
            
            (finding.libraries || []).forEach(lib => {
                const key = `${url}|${lib.library}|${lib.version}`;
                
                if (!libraryVulnMap.has(key)) {
                    libraryVulnMap.set(key, {
                        url: url,
                        library: lib.library,
                        version: lib.version,
                        detectedVia: lib.detectedVia,
                        requestId: finding.requestId,
                        vulnerabilities: []
                    });
                }
                
                const entry = libraryVulnMap.get(key);
                (lib.vulnerabilities || []).forEach(vuln => {
                    // Avoid duplicate vulnerabilities
                    const vulnKey = vuln.summary + (vuln.cve?.join(',') || '');
                    if (!entry.vulnerabilities.some(v => (v.summary + (v.cve?.join(',') || '')) === vulnKey)) {
                        entry.vulnerabilities.push(vuln);
                    }
                });
            });
        });
        
        // Now add merged entries to groups
        libraryVulnMap.forEach((libEntry, key) => {
            const url = libEntry.url;
            
            if (!groupedFindings.has(url)) {
                groupedFindings.set(url, {
                    url: url,
                    requestId: libEntry.requestId,
                    items: []
                });
            }
            
            const group = groupedFindings.get(url);
            
            // Filter vulnerabilities by severity
            let filteredVulns = libEntry.vulnerabilities;
            if (severityFilter !== 'all') {
                filteredVulns = filteredVulns.filter(v => v.severity === severityFilter);
            }
            
            // Apply search filter
            if (searchTerm) {
                const searchable = `${libEntry.library} ${libEntry.version} ${filteredVulns.map(v => v.summary + ' ' + (v.cve?.join(' ') || '')).join(' ')}`.toLowerCase();
                if (!searchable.includes(searchTerm)) {
                    return;
                }
            }
            
            if (filteredVulns.length === 0) return;
            
            // Determine highest severity for merged entry
            const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
            const highestSeverity = filteredVulns.reduce((highest, v) => {
                return severityOrder[v.severity] > severityOrder[highest] ? v.severity : highest;
            }, 'info');
            
            group.items.push({
                type: `Vulnerable Library: ${libEntry.library}`,
                match: `${libEntry.library}@${libEntry.version}`,
                severity: highestSeverity,
                isMerged: filteredVulns.length > 1,
                mergedCount: filteredVulns.length,
                isLibrary: true,
                library: libEntry.library,
                version: libEntry.version,
                detectedVia: libEntry.detectedVia,
                vulnerabilities: filteredVulns, // All vulnerabilities for this lib
                requestId: libEntry.requestId
            });
        });
    }
    
    // Render grouped findings
    let hasItems = false;
    
    groupedFindings.forEach((group, url) => {
        if (group.items.length === 0) return;
        hasItems = true;
        
        const groupEl = document.createElement('div');
        groupEl.className = 'finding-group';
        
        // Group header
        const headerEl = document.createElement('div');
        headerEl.className = 'finding-group-header';
        headerEl.innerHTML = `
            <span class="finding-group-url" title="${escapeHTML(url)}">${escapeHTML(url)}</span>
            <span class="finding-group-count">${group.items.length}</span>
        `;
        
        // Group items container
        const itemsEl = document.createElement('div');
        itemsEl.className = 'finding-group-items';
        
        group.items.forEach((item, index) => {
            const itemEl = item.isLibrary 
                ? createLibraryFindingElement(item, `${group.requestId}-lib-${index}`)
                : createFindingItemElement(item, `${group.requestId}-${index}`);
            itemsEl.appendChild(itemEl);
        });
        
        groupEl.appendChild(headerEl);
        groupEl.appendChild(itemsEl);
        securityFindingsList.appendChild(groupEl);
    });
    
    if (!hasItems) {
        securityFindingsList.innerHTML = `
            <div class="security-no-findings">
                <p>No findings match the current filters.</p>
            </div>
        `;
    }
}

/**
 * Create a library vulnerability finding element (merged)
 */
function createLibraryFindingElement(item, id) {
    const el = document.createElement('div');
    el.className = 'finding-item library-finding';
    el.id = `finding-${id}`;
    
    const severity = item.severity || 'medium';
    const vulns = item.vulnerabilities || [item.vulnerability]; // Support both merged and single
    
    // Create header with merged badge if applicable
    const header = document.createElement('div');
    header.className = 'finding-header';
    header.innerHTML = `
        <span class="finding-severity ${severity}">${severity}</span>
        ${item.isMerged ? `<span class="finding-merged-badge">MERGED ×${item.mergedCount}</span>` : ''}
        <span class="finding-type library-type">
            <span class="library-icon">📦</span>
            ${escapeHTML(item.library)} @ ${escapeHTML(item.version)}
        </span>
        <span class="finding-detected-via">${item.detectedVia}</span>
        <span class="finding-toggle">▼</span>
    `;
    
    // Create body with all vulnerability details
    const body = document.createElement('div');
    body.className = 'finding-body library-body';
    body.id = `finding-body-${id}`;
    
    // Build vulnerability cards for each vulnerability
    const vulnCards = vulns.map((vuln, idx) => {
        const cveLinks = (vuln.cve || []).map(cve => 
            `<a href="https://nvd.nist.gov/vuln/detail/${cve}" target="_blank" class="cve-link">${escapeHTML(cve)}</a>`
        ).join(' ');
        
        const cweList = (vuln.cwe || []).map(cwe => 
            `<span class="cwe-tag">${escapeHTML(cwe)}</span>`
        ).join(' ');
        
        let infoLinks = '';
        try {
            infoLinks = (vuln.info || []).slice(0, 3).map(url => 
                `<a href="${escapeHTML(url)}" target="_blank" class="info-link" title="${escapeHTML(url)}">${escapeHTML(new URL(url).hostname)}</a>`
            ).join(' ');
        } catch (e) {
            // Invalid URL, skip
        }
        
        return `
            <div class="vuln-card ${vuln.severity || 'medium'}">
                <div class="vuln-card-header">
                    <span class="vuln-card-severity ${vuln.severity || 'medium'}">${vuln.severity || 'medium'}</span>
                    ${cveLinks || '<span class="no-cve">No CVE</span>'}
                </div>
                <div class="vuln-summary">${escapeHTML(vuln.summary || 'No description available')}</div>
                <div class="vuln-details">
                    ${cweList ? `<div class="vuln-cwes">${cweList}</div>` : ''}
                    ${vuln.below ? `<div class="vuln-version"><strong>Affected:</strong> &lt; ${escapeHTML(vuln.below)}${vuln.atOrAbove ? ` (≥ ${escapeHTML(vuln.atOrAbove)})` : ''}</div>` : ''}
                    ${infoLinks ? `<div class="vuln-info">${infoLinks}</div>` : ''}
                </div>
            </div>
        `;
    }).join('');
    
    body.innerHTML = `<div class="vuln-cards">${vulnCards}</div>`;
    
    // Add click event listener to header
    header.addEventListener('click', () => {
        const toggle = header.querySelector('.finding-toggle');
        if (body.classList.contains('expanded')) {
            body.classList.remove('expanded');
            toggle.textContent = '▼';
        } else {
            body.classList.add('expanded');
            toggle.textContent = '▲';
        }
    });
    
    el.appendChild(header);
    el.appendChild(body);
    return el;
}

/**
 * Create a finding item element
 */
function createFindingItemElement(item, id) {
    const el = document.createElement('div');
    el.className = 'finding-item';
    el.id = `finding-${id}`;
    
    const severity = item.severity || 'info';
    
    // Create header
    const header = document.createElement('div');
    header.className = 'finding-header';
    header.innerHTML = `
        <span class="finding-severity ${severity}">${severity}</span>
        <span class="finding-type">${escapeHTML(item.type)}</span>
        <span class="finding-toggle">▼</span>
    `;
    
    // Create body
    const body = document.createElement('div');
    body.className = 'finding-body';
    body.id = `finding-body-${id}`;
    body.innerHTML = `
        <div class="finding-match">${escapeHTML(item.match)}</div>
        ${item.context ? `<div class="finding-context">${escapeHTML(item.context)}</div>` : ''}
        <div class="finding-meta">
            ${item.line ? `<span>Line: ${item.line}</span>` : ''}
            ${item.extractedValue && item.extractedValue !== item.match ? `<span>Value: ${escapeHTML(item.extractedValue.substring(0, 50))}${item.extractedValue.length > 50 ? '...' : ''}</span>` : ''}
        </div>
    `;
    
    // Add click event listener to header
    header.addEventListener('click', () => {
        const toggle = header.querySelector('.finding-toggle');
        if (body.classList.contains('expanded')) {
            body.classList.remove('expanded');
            toggle.textContent = '▼';
        } else {
            body.classList.add('expanded');
            toggle.textContent = '▲';
        }
    });
    
    el.appendChild(header);
    el.appendChild(body);
    
    return el;
}


/**
 * Export security findings to JSON file
 */
function exportSecurityFindings(findings, filename) {
    const data = JSON.stringify(findings, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Display security findings for a specific request in the Security tab
 */
function displayRequestSecurityFindings(request) {
    const securityTabContent = document.getElementById('securityTabContent');
    
    if (!request || !requestFindings.has(request.id)) {
        securityTabContent.innerHTML = `
            <div class="security-no-findings">
                <p>No security findings for this request.</p>
            </div>
        `;
        securityTabBtn.style.display = 'none';
        return;
    }
    
    const findings = requestFindings.get(request.id);
    
    // Show the security tab
    securityTabBtn.style.display = 'inline-flex';
    
    // Update tab badge
    const totalCount = findings.apiKeys.length + findings.credentials.length + 
                       findings.emails.length +
                       findings.apiEndpoints.length + findings.paths.length;
    
    if (totalCount > 0) {
        securityTabBadge.textContent = totalCount;
        securityTabBadge.style.display = 'inline-flex';
    } else {
        securityTabBadge.style.display = 'none';
    }
    
    // Render findings
    securityTabContent.innerHTML = '';
    
    const categories = [
        { key: 'apiKeys', label: 'API Keys', severity: 'critical' },
        { key: 'credentials', label: 'Credentials', severity: 'critical' },
        { key: 'emails', label: 'Emails', severity: 'info' },
        { key: 'apiEndpoints', label: 'API Endpoints', severity: 'info' },
        { key: 'parameters', label: 'Parameters', severity: 'info' },
        { key: 'paths', label: 'Paths', severity: 'info' }
    ];
    
    categories.forEach(cat => {
        const items = findings[cat.key];
        if (!items || items.length === 0) return;
        
        const section = document.createElement('div');
        section.className = 'finding-group';
        
        const header = document.createElement('div');
        header.className = 'finding-group-header';
        header.innerHTML = `
            <span class="finding-group-url">${cat.label}</span>
            <span class="finding-group-count">${items.length}</span>
        `;
        
        const itemsContainer = document.createElement('div');
        itemsContainer.className = 'finding-group-items';
        
        items.forEach((item, index) => {
            const itemEl = createFindingItemElement(item, `tab-${cat.key}-${index}`);
            itemsContainer.appendChild(itemEl);
        });
        
        section.appendChild(header);
        section.appendChild(itemsContainer);
        securityTabContent.appendChild(section);
    });
}

captureToggle.addEventListener('change', () => {
    // If capture is turned off, also turn off intercept
    if (!captureToggle.checked && interceptToggle.checked) {
        interceptToggle.checked = false;
        port.postMessage({ type: 'toggleIntercept', enabled: false });
    }
    port.postMessage({ type: 'toggleCapture', enabled: captureToggle.checked });
});

interceptToggle.addEventListener('change', () => {
    // If intercept is turned on, also turn on capture
    if (interceptToggle.checked && !captureToggle.checked) {
        captureToggle.checked = true;
        port.postMessage({ type: 'toggleCapture', enabled: true });
    }
    port.postMessage({ type: 'toggleIntercept', enabled: interceptToggle.checked });
});

clearBtn.addEventListener('click', () => {
    requests = [];
    requestCounter = 0;
    renderRequestList();
    clearRequestDetails();
    port.postMessage({ type: 'clearRequests' });
});

filterBtn.addEventListener('click', () => {
    const isVisible = filterPanel.style.display !== 'none';
    filterPanel.style.display = isVisible ? 'none' : 'block';
    filterBtn.textContent = isVisible ? 'Filters ▼' : 'Filters ▲';
});

themeToggleBtn.addEventListener('click', () => {
    toggleTheme();
});

document.querySelectorAll('.filter-checkbox input').forEach(checkbox => {
    checkbox.addEventListener('change', () => {
        const type = checkbox.dataset.type;
        if (checkbox.checked) {
            hiddenTypes.add(type);
        } else {
            hiddenTypes.delete(type);
        }
        localStorage.setItem('hiddenTypes', JSON.stringify(Array.from(hiddenTypes)));
        renderRequestList();
    });
});

const savedHiddenTypes = localStorage.getItem('hiddenTypes');
if (savedHiddenTypes) {
    hiddenTypes = new Set(JSON.parse(savedHiddenTypes));
    hiddenTypes.forEach(type => {
        const checkbox = document.querySelector(`input[data-type="${type}"]`);
        if (checkbox) checkbox.checked = true;
    });
}

searchInput.addEventListener('input', () => {
    renderRequestList();
});

// Add sorting functionality to table headers
document.querySelectorAll('#requestTable th[data-column]').forEach(th => {
    th.addEventListener('click', () => {
        const column = th.dataset.column;
        if (currentSortColumn === column) {
            currentSortDirection = currentSortDirection === 'asc' ? 'desc' : 'asc';
        } else {
            currentSortColumn = column;
            currentSortDirection = 'asc';
        }
        updateSortIndicators();
        renderRequestList();
    });
});

// Add search functionality for request/response/modified content
requestSearchInput.addEventListener('input', () => {
    const searchTerm = requestSearchInput.value;
    highlightContent('requestContent', searchTerm, requestSearchCount);
});

modifiedSearchInput.addEventListener('input', () => {
    const searchTerm = modifiedSearchInput.value;
    highlightContent('modifiedContent', searchTerm, modifiedSearchCount);
});

responseSearchInput.addEventListener('input', () => {
    const searchTerm = responseSearchInput.value;
    highlightContent('responseContent', searchTerm, responseSearchCount);
});

document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const tab = btn.dataset.tab;
        currentTab = tab;
        
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        document.getElementById('requestTab').style.display = tab === 'request' ? 'flex' : 'none';
        document.getElementById('modifiedTab').style.display = tab === 'modified' ? 'flex' : 'none';
        document.getElementById('responseTab').style.display = tab === 'response' ? 'flex' : 'none';
        document.getElementById('securityTab').style.display = tab === 'security' ? 'flex' : 'none';
        
        if (selectedRequest) {
            displayRequestDetails(selectedRequest);
        }
    });
});

document.querySelectorAll('#requestTab .view-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const view = btn.dataset.view;
        currentRequestView = view;
        
        btn.parentElement.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        if (selectedRequest) {
            displayRequestDetails(selectedRequest);
        }
    });
});

document.querySelectorAll('#modifiedTab .view-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const view = btn.dataset.view;
        currentModifiedView = view;
        
        btn.parentElement.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        if (selectedRequest) {
            displayRequestDetails(selectedRequest);
        }
    });
});

document.querySelectorAll('#responseTab .view-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const view = btn.dataset.view;
        currentResponseView = view;
        
        btn.parentElement.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        if (selectedRequest) {
            displayRequestDetails(selectedRequest);
        }
    });
});

copyCurlBtn.addEventListener('click', () => {
    if (selectedRequest) {
        const curl = generateCurl(selectedRequest);
        navigator.clipboard.writeText(curl).then(() => {
            copyCurlBtn.textContent = 'Copied!';
            setTimeout(() => {
                copyCurlBtn.textContent = 'Copy as cURL';
            }, 2000);
        });
    }
});

copyRequestBtn.addEventListener('click', () => {
    if (selectedRequest) {
        const rawContent = formatRequestContent(selectedRequest, 'raw');
        navigator.clipboard.writeText(rawContent).then(() => {
            copyRequestBtn.textContent = 'Copied!';
            setTimeout(() => {
                copyRequestBtn.textContent = 'Copy';
            }, 2000);
        });
    }
});

copyResponseBtn.addEventListener('click', () => {
    if (selectedRequest) {
        const rawContent = formatResponseContent(selectedRequest, 'raw');
        navigator.clipboard.writeText(rawContent.content).then(() => {
            copyResponseBtn.textContent = 'Copied!';
            setTimeout(() => {
                copyResponseBtn.textContent = 'Copy';
            }, 2000);
        });
    }
});

repeaterBtn.addEventListener('click', () => {
    if (selectedRequest) {
        showRepeaterModal(selectedRequest);
    }
});

// Modified request tab buttons
document.getElementById('copyModifiedCurlBtn').addEventListener('click', () => {
    if (selectedRequest && selectedRequest.wasModified) {
        const curl = generateModifiedCurl(selectedRequest);
        navigator.clipboard.writeText(curl).then(() => {
            const btn = document.getElementById('copyModifiedCurlBtn');
            btn.textContent = 'Copied!';
            setTimeout(() => {
                btn.textContent = 'Copy as cURL';
            }, 2000);
        });
    }
});

document.getElementById('modifiedRepeaterBtn').addEventListener('click', () => {
    if (selectedRequest && selectedRequest.wasModified) {
        showModifiedRepeaterModal(selectedRequest);
    }
});

closeRepeaterBtn.addEventListener('click', () => {
    repeaterModal.classList.remove('show');
});

sendRepeaterBtn.addEventListener('click', () => {
    sendRepeaterRequest();
});

clearRepeaterBtn.addEventListener('click', () => {
    document.getElementById('repeaterStatus').textContent = 'No response yet';
    document.getElementById('repeaterStatus').className = 'response-status';
    document.getElementById('repeaterResponseContent').textContent = '';
    lastRepeaterResponse = null;
});

document.querySelectorAll('.response-tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const tab = btn.dataset.tab;
        currentRepeaterTab = tab;
        
        document.querySelectorAll('.response-tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        if (lastRepeaterResponse) {
            displayRepeaterResponse(lastRepeaterResponse);
        }
    });
});

document.getElementById('forwardBtn').addEventListener('click', () => {
    if (interceptedRequest) {
        const modifiedRequest = {
            method: document.getElementById('interceptMethod').value,
            url: document.getElementById('interceptUrl').value,
            headers: parseHeaders(document.getElementById('interceptHeaders').value),
            body: document.getElementById('interceptBody').value
        };
        
        port.postMessage({
            type: 'forwardRequest',
            requestId: interceptedRequest.id,
            modifiedRequest: modifiedRequest
        });
        
        closeInterceptModal();
    }
});

document.getElementById('dropBtn').addEventListener('click', () => {
    if (interceptedRequest) {
        port.postMessage({
            type: 'dropRequest',
            requestId: interceptedRequest.id
        });
        
        closeInterceptModal();
    }
});

// Intercept Settings Event Listeners
interceptSettingsBtn.addEventListener('click', () => {
    showInterceptSettingsModal();
});

closeInterceptSettingsBtn.addEventListener('click', () => {
    interceptSettingsModal.classList.remove('show');
});

saveInterceptSettingsBtn.addEventListener('click', () => {
    saveInterceptSettings();
});

resetInterceptSettingsBtn.addEventListener('click', () => {
    resetInterceptSettings();
});

// GET checkbox warning
document.getElementById('interceptGET').addEventListener('change', (e) => {
    const getWarning = document.getElementById('getWarning');
    getWarning.style.display = e.target.checked ? 'block' : 'none';
});

// Response interception checkbox warning
document.getElementById('interceptResponses').addEventListener('change', (e) => {
    const responseWarning = document.getElementById('responseWarning');
    responseWarning.style.display = e.target.checked ? 'block' : 'none';
});


document.getElementById('useEarlyInterception').addEventListener('change', (e) => {
    const warning = document.getElementById('earlyInterceptionWarning');
    warning.style.display = e.target.checked ? 'block' : 'none';
});


forwardResponseBtn.addEventListener('click', () => {
    if (interceptedResponse) {
        const modifiedResponse = {
            statusCode: parseInt(document.getElementById('responseStatusCode').value),
            statusText: document.getElementById('responseStatusText').value,
            headers: parseHeaders(document.getElementById('responseHeaders').value),
            body: document.getElementById('responseBody').value
        };
        
        port.postMessage({
            type: 'forwardResponse',
            requestId: interceptedResponse.requestId,
            modifiedResponse: modifiedResponse
        });
        
        closeResponseInterceptModal();
    }
});

dropResponseBtn.addEventListener('click', () => {
    if (interceptedResponse) {
        port.postMessage({
            type: 'dropResponse',
            requestId: interceptedResponse.requestId
        });
        
        closeResponseInterceptModal();
    }
});

// Disable Intercept event listeners
disableInterceptBtn.addEventListener('click', () => {
    if (interceptedRequest) {
        port.postMessage({
            type: 'disableIntercept',
            currentRequestId: interceptedRequest.id,
            currentType: 'request'
        });
        
        closeInterceptModal();
    }
});

disableInterceptResponseBtn.addEventListener('click', () => {
    if (interceptedResponse) {
        port.postMessage({
            type: 'disableIntercept',
            currentRequestId: interceptedResponse.requestId,
            currentType: 'response'
        });
        
        closeResponseInterceptModal();
    }
});

// Track manual edits in intercept headers textarea so we don't overwrite user input
document.getElementById('interceptHeaders').addEventListener('input', () => {
    interceptHeadersEdited = true;
});

port.onMessage.addListener((msg) => {
    switch (msg.type) {
        case 'initialState':
            captureToggle.checked = msg.captureEnabled;
            interceptToggle.checked = msg.interceptEnabled;
            if (msg.interceptSettings) {
                interceptSettings = msg.interceptSettings;
                updateInterceptSettingsUI();
            }
            requests = msg.requests;
            // Assign request numbers to existing requests if they don't have them
            requests.forEach((req, index) => {
                if (!req.requestNumber) {
                    requestCounter++;
                    req.requestNumber = requestCounter;
                } else {
                    requestCounter = Math.max(requestCounter, req.requestNumber);
                }
            });
            // Load security findings from background (captured while DevTools was closed)
            if (msg.securityFindings && msg.securityFindings.length > 0) {
                msg.securityFindings.forEach(finding => {
                    if (!securityFindings.some(f => f.url === finding.url && f.timestamp === finding.timestamp)) {
                        securityFindings.push(finding);
                    }
                });
                unseenFindingsCount = msg.securityFindings.reduce((acc, f) => acc + f.totalFindings, 0);
            }
            // Load library findings from background
            if (msg.libraryFindings && msg.libraryFindings.length > 0) {
                msg.libraryFindings.forEach(finding => {
                    if (!libraryFindings.some(f => f.url === finding.url && f.timestamp === finding.timestamp)) {
                        libraryFindings.push(finding);
                    }
                });
                unseenFindingsCount += msg.libraryFindings.reduce((acc, f) => acc + f.totalFindings, 0);
            }
            updateSecurityBadge();
            renderSecurityFindingsList();
            renderRequestList();
            break;
            
        case 'captureStateChanged':
            captureToggle.checked = msg.enabled;
            break;
            
        case 'interceptStateChanged':
            interceptToggle.checked = msg.enabled;
            break;
            
        case 'newRequest':
            requestCounter++;
            msg.request.requestNumber = requestCounter;
            requests.push(msg.request);
            if (requests.length > 100) {
                requests.shift();
            }
            renderRequestList();
            if (!selectedRequest && requests.length === 1) {
                selectedRequest = msg.request;
                displayRequestDetails(selectedRequest);
            }
            break;
            
        case 'updateRequest':
            const index = requests.findIndex(r => r.id === msg.request.id);
            if (index !== -1) {
                // Preserve the request number when updating
                msg.request.requestNumber = requests[index].requestNumber;
                
                // Preserve security findings if already scanned
                if (requests[index].hasSecurityFindings) {
                    msg.request.hasSecurityFindings = requests[index].hasSecurityFindings;
                    msg.request.securityFindingsCount = requests[index].securityFindingsCount;
                }
                
                requests[index] = msg.request;
                
                // Scan response body for security issues if not already scanned
                if (msg.request.responseBody && !requestFindings.has(msg.request.id) && captureToggle.checked) {
                    const scanResults = scanRequestForSecurity(msg.request);
                    if (scanResults) {
                        processSecurityResults(msg.request, scanResults);
                    }
                }
                
                renderRequestList();
                if (selectedRequest && selectedRequest.id === msg.request.id) {
                    selectedRequest = msg.request;
                    displayRequestDetails(selectedRequest);
                }
            }
            break;
            
        case 'interceptRequest':
            interceptQueue.push(msg.request);
            if (!interceptedRequest) {
                processNextIntercept();
            }
            updateQueueCounts();
            break;
            
        case 'interceptResponse':
            responseQueue.push(msg.response);
            if (!interceptedResponse) {
                processNextResponseIntercept();
            }
            updateQueueCounts();
            break;
            
        case 'interceptSettingsChanged':
            interceptSettings = msg.settings;
            updateInterceptSettingsUI();
            break;
            
        case 'interceptSettingsResponse':
            interceptSettings = msg.settings;
            updateInterceptSettingsUI();
            break;
            
        case 'requestsCleared':
            requests = [];
            requestCounter = 0;
            // Also clear security and library findings
            securityFindings = [];
            libraryFindings = [];
            requestFindings.clear();
            requestLibraryFindings.clear();
            unseenFindingsCount = 0;
            updateSecurityBadge();
            renderRequestList();
            clearRequestDetails();
            break;
            
        case 'securityFinding':
            // New security finding from background scanner
            if (msg.finding && !securityFindings.some(f => f.url === msg.finding.url && f.timestamp === msg.finding.timestamp)) {
                securityFindings.push(msg.finding);
                unseenFindingsCount += msg.finding.totalFindings;
                updateSecurityBadge();
                renderSecurityFindingsList();
            }
            break;
            
        case 'securityFindingsCleared':
            securityFindings = [];
            requestFindings.clear();
            unseenFindingsCount = 0;
            updateSecurityBadge();
            renderSecurityFindingsList();
            break;
            
        case 'securityFindingsResponse':
            // Response to getSecurityFindings request
            if (msg.findings && msg.findings.length > 0) {
                msg.findings.forEach(finding => {
                    if (!securityFindings.some(f => f.url === finding.url && f.timestamp === finding.timestamp)) {
                        securityFindings.push(finding);
                    }
                });
                unseenFindingsCount = msg.findings.reduce((acc, f) => acc + f.totalFindings, 0);
                updateSecurityBadge();
                renderSecurityFindingsList();
            }
            break;
            
        case 'libraryFinding':
            // New vulnerable library finding from background scanner
            if (msg.finding && !libraryFindings.some(f => f.url === msg.finding.url && f.timestamp === msg.finding.timestamp)) {
                libraryFindings.push(msg.finding);
                unseenFindingsCount += msg.finding.totalFindings;
                updateSecurityBadge();
                renderSecurityFindingsList();
            }
            break;
            
        case 'libraryFindingsCleared':
            libraryFindings = [];
            requestLibraryFindings.clear();
            updateSecurityBadge();
            renderSecurityFindingsList();
            break;
            
        case 'libraryFindingsResponse':
            // Response to getLibraryFindings request
            if (msg.findings && msg.findings.length > 0) {
                msg.findings.forEach(finding => {
                    if (!libraryFindings.some(f => f.url === finding.url && f.timestamp === finding.timestamp)) {
                        libraryFindings.push(finding);
                    }
                });
                updateSecurityBadge();
                renderSecurityFindingsList();
            }
            break;
            
        case 'repeaterResponse':
            lastRepeaterResponse = msg.response;
            const statusClass = msg.response.status >= 200 && msg.response.status < 300 ? 'success' : 'error';
            document.getElementById('repeaterStatus').textContent = 
                `${msg.response.status} ${msg.response.statusText} (${msg.response.duration}ms)`;
            document.getElementById('repeaterStatus').className = `response-status ${statusClass}`;
            displayRepeaterResponse(msg.response);
            break;
            
        case 'repeaterError':
            document.getElementById('repeaterStatus').textContent = `Error: ${msg.error}`;
            document.getElementById('repeaterStatus').className = 'response-status error';
            document.getElementById('repeaterResponseContent').textContent = msg.error;
            break;
            
        case 'interceptSettingsChanged':
            interceptSettings = msg.settings;
            updateInterceptSettingsUI();
            break;
            
        case 'interceptSettingsResponse':
            interceptSettings = msg.settings;
            updateInterceptSettingsUI();
            break;
            
        case 'sendToDecoder':
            showDecoderModal(msg.text);
            break;
    }
});

function processNextIntercept() {
    if (interceptQueue.length > 0) {
        const nextRequest = interceptQueue.shift();
        interceptedRequest = nextRequest;
        showInterceptModal(nextRequest);
    }
    updateQueueCounts();
}

function processNextResponseIntercept() {
    if (responseQueue.length > 0) {
        const nextResponse = responseQueue.shift();
        interceptedResponse = nextResponse;
        showResponseInterceptModal(nextResponse);
    }
    updateQueueCounts();
}

function updateQueueCounts() {
    const requestCount = document.getElementById('interceptQueueCount');
    const responseCount = document.getElementById('responseQueueCount');
    
    if (requestCount) {
        requestCount.textContent = interceptQueue.length > 0 ? `+${interceptQueue.length} pending` : '';
        requestCount.classList.toggle('visible', interceptQueue.length > 0);
    }
    
    if (responseCount) {
        responseCount.textContent = responseQueue.length > 0 ? `+${responseQueue.length} pending` : '';
        responseCount.classList.toggle('visible', responseQueue.length > 0);
    }
}

function updateSortIndicators() {
    document.querySelectorAll('#requestTable th[data-column]').forEach(th => {
        th.classList.remove('sort-asc', 'sort-desc');
        if (th.dataset.column === currentSortColumn) {
            th.classList.add(currentSortDirection === 'asc' ? 'sort-asc' : 'sort-desc');
        }
    });
}

function sortRequests(requests) {
    if (!currentSortColumn) return requests;
    
    return [...requests].sort((a, b) => {
        let aVal, bVal;
        
        switch (currentSortColumn) {
            case 'number':
                aVal = a.requestNumber || 0;
                bVal = b.requestNumber || 0;
                break;
            case 'method':
                aVal = a.method || '';
                bVal = b.method || '';
                break;
            case 'host':
                try {
                    aVal = new URL(a.url).hostname;
                } catch {
                    aVal = '';
                }
                try {
                    bVal = new URL(b.url).hostname;
                } catch {
                    bVal = '';
                }
                break;
            case 'url':
                try {
                    aVal = new URL(a.url).pathname;
                } catch {
                    aVal = a.url || '';
                }
                try {
                    bVal = new URL(b.url).pathname;
                } catch {
                    bVal = b.url || '';
                }
                break;
            case 'status':
                aVal = a.statusCode || 0;
                bVal = b.statusCode || 0;
                break;
            case 'reqSize':
                aVal = calculateRequestSize(a);
                bVal = calculateRequestSize(b);
                break;
            case 'resSize':
                aVal = calculateResponseSize(a);
                bVal = calculateResponseSize(b);
                break;
            case 'type':
                aVal = a.type || '';
                bVal = b.type || '';
                break;
            default:
                return 0;
        }
        
        let comparison = 0;
        if (typeof aVal === 'string') {
            comparison = aVal.localeCompare(bVal);
        } else {
            comparison = aVal - bVal;
        }
        
        return currentSortDirection === 'asc' ? comparison : -comparison;
    });
}

function renderRequestList() {
    const searchTerm = searchInput.value.toLowerCase();
    
    const filteredRequests = requests.filter(req => {
        // Filter by hidden types
        if (hiddenTypes.has(req.type)) {
            return false;
        }
        
        // Filter by search term
        if (!searchTerm) return true;
        
        const searchableContent = [
            req.url,
            req.method,
            req.statusCode?.toString(),
            JSON.stringify(req.requestHeaders),
            JSON.stringify(req.responseHeaders),
            req.requestBody,
            req.responseBody
        ].join(' ').toLowerCase();
        
        return searchableContent.includes(searchTerm);
    });
    
    // Sort the filtered requests
    const sortedRequests = sortRequests(filteredRequests);
    
    requestList.innerHTML = '';
    
    sortedRequests.forEach(req => {
        const row = document.createElement('tr');
        
        // Apply highlighting rules
        for (const rule of highlightRules) {
            try {
                if (rule.enabled) {
                    let isMatch = false;
                    const type = rule.type || 'regex';
                    const pattern = rule.pattern;
                    const target = req.url; // Highlighting only targets URL currently
                    
                    if (!target) continue;

                    switch (type) {
                        case 'regex':
                            isMatch = new RegExp(pattern).test(target);
                            break;
                        case 'contains':
                            isMatch = target.includes(pattern);
                            break;
                        case 'starts_with':
                            isMatch = target.startsWith(pattern);
                            break;
                        case 'ends_with':
                            isMatch = target.endsWith(pattern);
                            break;
                        case 'exact':
                            isMatch = target === pattern;
                            break;
                    }

                    if (isMatch) {
                        row.style.backgroundColor = rule.color + '40'; // Add 25% opacity
                        break; // Apply first matching rule
                    }
                }
            } catch (e) {
                console.error('Invalid highlight rule pattern:', rule.pattern);
            }
        }
        
        if (selectedRequest && selectedRequest.id === req.id) {
            row.classList.add('selected');
        }
        
        if (req.wasModified) {
            row.classList.add('modified-request');
        }
        
        // Mark requests with security findings
        if (req.hasSecurityFindings || requestFindings.has(req.id)) {
            row.classList.add('request-has-findings');
        }
        
        const numberCell = document.createElement('td');
        numberCell.textContent = req.requestNumber || '';
        numberCell.className = 'request-number';
        
        const methodCell = document.createElement('td');
        methodCell.textContent = req.method;
        methodCell.className = `method-${req.method}`;
        
        const hostCell = document.createElement('td');
        try {
            hostCell.textContent = new URL(req.url).hostname;
        } catch {
            hostCell.textContent = '';
        }
        hostCell.title = req.url;
        
        const urlCell = document.createElement('td');
        urlCell.textContent = new URL(req.url).pathname;
        urlCell.title = req.url;
        
        const statusCell = document.createElement('td');
        if (req.intercepted) {
            statusCell.textContent = 'Intercepted';
            statusCell.className = 'status-intercepted';
            statusCell.style.color = '#ff9800';
        } else if (req.autoModified) {
            statusCell.textContent = req.statusLine || 'Auto-Modified';
            statusCell.className = 'status-modified';
            statusCell.style.color = '#9c27b0'; // Purple for auto-modified
            statusCell.title = 'Request was automatically modified by a rule';
            
            // Add icon
            const icon = document.createElement('span');
            icon.textContent = ' ⚡';
            statusCell.appendChild(icon);
        } else if (req.statusLine === 'Dropped') {
            statusCell.textContent = 'Dropped';
            statusCell.className = 'status-dropped';
            statusCell.style.color = '#f44336';
        } else if (req.statusLine && req.statusLine.startsWith('Modified & Resent')) {
            statusCell.textContent = req.statusCode || 'Modified';
            statusCell.className = 'status-modified';
            statusCell.style.color = '#9c27b0';
            statusCell.title = 'Request was modified and resent';
        } else if (req.statusLine && req.statusLine.startsWith('Modification Failed')) {
            statusCell.textContent = 'Failed';
            statusCell.className = 'status-error';
            statusCell.style.color = '#f44336';
            statusCell.title = req.statusLine;
        } else if (req.statusLine && req.statusLine.startsWith('Resending')) {
            statusCell.textContent = 'Resending...';
            statusCell.style.color = '#9c27b0';
        } else if (req.statusLine && req.statusLine.startsWith('Forwarded (Unmodified)')) {
            statusCell.textContent = req.statusCode || 'Forwarded';
            statusCell.className = req.statusCode ? `status-${Math.floor(req.statusCode / 100) * 100}` : '';
            statusCell.title = 'Request was forwarded without modifications';
        } else if (req.statusLine === 'Forwarding' && !req.statusCode) {
            statusCell.textContent = 'Forwarding...';
            statusCell.style.color = '#2196F3';
        } else if (req.statusCode !== null && req.statusCode !== undefined) {
            statusCell.textContent = req.statusCode;
            statusCell.className = `status-${Math.floor(req.statusCode / 100) * 100}`;
        } else if (req.completed) {
            statusCell.textContent = 'Complete';
        } else {
            statusCell.textContent = 'Pending';
        }
        
        const reqSizeCell = document.createElement('td');
        reqSizeCell.textContent = formatSize(calculateRequestSize(req));
        
        const resSizeCell = document.createElement('td');
        resSizeCell.textContent = formatSize(calculateResponseSize(req));
        
        const typeCell = document.createElement('td');
        typeCell.textContent = req.type;
        
        row.appendChild(numberCell);
        row.appendChild(methodCell);
        row.appendChild(hostCell);
        row.appendChild(urlCell);
        row.appendChild(statusCell);
        row.appendChild(reqSizeCell);
        row.appendChild(resSizeCell);
        row.appendChild(typeCell);
        
        row.addEventListener('click', () => {
            selectedRequest = req;
            document.querySelectorAll('#requestList tr').forEach(r => r.classList.remove('selected'));
            row.classList.add('selected');
            displayRequestDetails(req);
        });
        
        requestList.appendChild(row);
    });
}

function displayRequestDetails(request) {
    // Show/hide modified tab based on whether request was modified
    const modifiedTabBtn = document.querySelector('.tab-btn[data-tab="modified"]');
    if (request.wasModified) {
        modifiedTabBtn.style.display = 'inline-block';
    } else {
        modifiedTabBtn.style.display = 'none';
        // If we're currently on the modified tab, switch to request tab
        if (currentTab === 'modified') {
            currentTab = 'request';
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelector('.tab-btn[data-tab="request"]').classList.add('active');
            document.getElementById('requestTab').style.display = 'flex';
            document.getElementById('modifiedTab').style.display = 'none';
            document.getElementById('responseTab').style.display = 'none';
            document.getElementById('securityTab').style.display = 'none';
        }
    }
    
    // Show/hide security tab based on whether request has security findings
    displayRequestSecurityFindings(request);
    
    // Show info note if auto-modified
    const existingNote = document.querySelector('.auto-modified-note');
    if (existingNote) existingNote.remove();
    
    if (request.autoModified) {
        const note = document.createElement('div');
        note.className = 'auto-modified-note';
        note.style.padding = '10px';
        note.style.backgroundColor = '#f3e5f5'; // Light purple
        note.style.borderBottom = '1px solid #e1bee7';
        note.style.color = '#7b1fa2';
        note.style.fontSize = '12px';
        note.innerHTML = '<strong>⚡ Info:</strong> This request was automatically modified by a Match & Replace rule.';
        
        // Insert after tabs
        const tabs = document.querySelector('.tabs');
        tabs.parentNode.insertBefore(note, tabs.nextSibling);
    }
    
    if (currentTab === 'request') {
        const content = formatRequestContent(request, currentRequestView);
        if (currentRequestView === 'formatted' && (content.includes('<span class="syntax-') || content.includes('syntax-key'))) {
             requestContent.innerHTML = content;
        } else {
             requestContent.textContent = content;
        }
        
        // Update active button for request tab
        document.querySelectorAll('#requestTab .view-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.view === currentRequestView);
        });
    } else if (currentTab === 'modified') {
        const content = formatModifiedRequestContent(request, currentModifiedView);
        if (currentModifiedView === 'formatted' && (content.includes('<span class="syntax-') || content.includes('syntax-key'))) {
             modifiedContent.innerHTML = content;
        } else {
             modifiedContent.textContent = content;
        }
        
        // Update active button for modified tab
        document.querySelectorAll('#modifiedTab .view-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.view === currentModifiedView);
        });
    } else if (currentTab === 'security') {
        // Security tab content is already rendered by displayRequestSecurityFindings
    } else {
        const result = formatResponseContent(request, currentResponseView);
        
        // Show/hide Preview button based on HTML content
        if (result.isHTML) {
            responsePreviewBtn.style.display = 'inline-block';
        } else {
            responsePreviewBtn.style.display = 'none';
            // If currently on preview view and content is not HTML, switch to raw view
            if (currentResponseView === 'preview') {
                currentResponseView = 'raw';
            }
        }
        
        if (result.isImage || result.isPreview || (currentResponseView === 'formatted' && (result.content.includes('<span class="syntax-') || result.content.includes('syntax-key')))) {
            responseContent.innerHTML = result.content;
        } else {
            responseContent.textContent = result.content;
        }
        
        // Update active button for response tab
        document.querySelectorAll('#responseTab .view-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.view === currentResponseView);
        });
    }
}

function highlightSyntax(code, language) {
    if (!code) return '';
    
    if (language === 'json') {
        return code.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
            let cls = 'syntax-number';
            if (/^"/.test(match)) {
                if (/:$/.test(match)) {
                    cls = 'syntax-key';
                } else {
                    cls = 'syntax-string';
                }
            } else if (/true|false/.test(match)) {
                cls = 'syntax-boolean';
            } else if (/null/.test(match)) {
                cls = 'syntax-null';
            }
            return '<span class="' + cls + '">' + match + '</span>';
        });
    } else if (language === 'xml' || language === 'html') {
        return code.replace(/(&lt;\/?)(\w+)(.*?)(\/?&gt;)/g, function(match, start, tag, attrs, end) {
            let formattedAttrs = attrs.replace(/(\s+)(\w+)(?:(=)("[^"]*"))?/g, '$1<span class="syntax-attr">$2</span>$3<span class="syntax-value">$4</span>');
            return start + '<span class="syntax-tag">' + tag + '</span>' + formattedAttrs + end;
        });
    }
    
    return code;
}

function formatRequestContent(request, view) {
    const method = request.originalMethod || request.method;
    const url = request.originalUrl || request.url;
    const headers = request.originalHeaders || request.requestHeaders || {};
    const body = request.originalBody !== undefined ? request.originalBody : request.requestBody;

    if (view === 'raw') {
        let raw = `${method} ${url} HTTP/1.1\n`;
        
        for (const [key, value] of Object.entries(headers)) {
            raw += `${key}: ${value}\n`;
        }
        
        if (body) {
            raw += `\n${body}`;
        }
        
        return raw;
    } else {
        // Formatted view - show headers as-is, format body based on content type
        let formatted = `${escapeHTML(method)} ${escapeHTML(url)} HTTP/1.1\n`;
        
        for (const [key, value] of Object.entries(headers)) {
            formatted += `${escapeHTML(key)}: ${escapeHTML(value)}\n`;
        }
        
        if (body) {
            formatted += '\n' + formatBody(body, headers);
        }
        
        return formatted;
    }
}

function formatModifiedRequestContent(request, view) {
    if (!request.wasModified) {
        return 'This request was not modified.';
    }
    
    if (view === 'raw') {
        let raw = `${request.modifiedMethod || request.method} ${request.modifiedUrl || request.url} HTTP/1.1\n`;
        
        const headers = request.modifiedHeaders || request.requestHeaders || {};
        for (const [key, value] of Object.entries(headers)) {
            raw += `${key}: ${value}\n`;
        }
        
        const body = request.modifiedBody !== undefined ? request.modifiedBody : request.requestBody;
        if (body) {
            raw += `\n${body}`;
        }
        
        return raw;
    } else {
        // Formatted view - show headers as-is, format body based on content type
        let formatted = `${escapeHTML(request.modifiedMethod || request.method)} ${escapeHTML(request.modifiedUrl || request.url)} HTTP/1.1\n`;
        
        const headers = request.modifiedHeaders || request.requestHeaders || {};
        for (const [key, value] of Object.entries(headers)) {
            formatted += `${escapeHTML(key)}: ${escapeHTML(value)}\n`;
        }
        
        const body = request.modifiedBody !== undefined ? request.modifiedBody : request.requestBody;
        if (body) {
            formatted += '\n' + formatBody(body, headers);
        }
        
        return formatted;
    }
}

function formatResponseContent(request, view) {
    // Check if response is an image
    const contentType = Object.entries(request.responseHeaders || {})
        .find(([key, value]) => key.toLowerCase() === 'content-type')?.[1] || '';
    
    const isImage = contentType.match(/^image\/(png|jpe?g|gif|svg\+xml|webp|ico|bmp)/i);
    const isHTMLContent = contentType.includes('html') || isHTML(request.responseBody || '');
    
    if (isImage && request.responseBody && view === 'formatted') {
        // For images, display the image in formatted view
        let headers = `${escapeHTML(request.statusLine || `HTTP/1.1 ${request.statusCode || 'Pending'}`)}\n`;
        for (const [key, value] of Object.entries(request.responseHeaders || {})) {
            headers += `${escapeHTML(key)}: ${escapeHTML(value)}\n`;
        }
        
        // Construct the image source
        let imgSrc;
        if (request.responseBody.startsWith('data:')) {
            // Already a data URL
            imgSrc = request.responseBody;
        } else if (request.isBase64 || request.responseBody.match(/^[A-Za-z0-9+/=]+$/)) {
            // It's base64 encoded (either marked as such or looks like base64)
            imgSrc = `data:${contentType};base64,${request.responseBody}`;
        } else {
            // Try to encode it
            try {
                imgSrc = `data:${contentType};base64,${btoa(request.responseBody)}`;
            } catch (e) {
                // If btoa fails, show error
                return { isImage: false, isHTML: false, content: `Error rendering image: ${e.message}` };
            }
        }
        
        const imageHtml = `<div class="response-image-container">
            <div class="response-headers">${escapeHTML(headers)}</div>
            <img src="${imgSrc}" alt="Response Image" class="response-image" onerror="this.style.display='none'; this.parentElement.innerHTML += '<div style=\\'padding: 20px; color: #f44336;\\'>Failed to load image</div>';" />
        </div>`;
        
        return { isImage: true, isHTML: false, content: imageHtml };
    }
    
    // Handle HTML preview in iframe
    if (isHTMLContent && request.responseBody && view === 'preview') {
        let headers = `${escapeHTML(request.statusLine || `HTTP/1.1 ${request.statusCode || 'Pending'}`)}\n`;
        for (const [key, value] of Object.entries(request.responseHeaders || {})) {
            headers += `${escapeHTML(key)}: ${escapeHTML(value)}\n`;
        }
        
        // Create iframe with sandboxed HTML content
        const htmlContent = request.responseBody
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
        
        const previewHtml = `<div class="response-preview-container">
            <div class="response-headers">${escapeHTML(headers)}</div>
            <iframe class="response-preview-iframe" sandbox="allow-same-origin" srcdoc="${htmlContent}"></iframe>
        </div>`;
        
        return { isImage: false, isHTML: true, isPreview: true, content: previewHtml };
    }
    
    if (view === 'raw') {
        let raw = `${request.statusLine || `HTTP/1.1 ${request.statusCode || 'Pending'}`}\n`;
        
        for (const [key, value] of Object.entries(request.responseHeaders || {})) {
            raw += `${key}: ${value}\n`;
        }
        
        if (request.responseBody) {
            raw += `\n${request.responseBody}`;
        }
        
        return { isImage: false, isHTML: isHTMLContent, content: raw };
    } else {
        // Formatted view - show headers as-is, format body based on content type
        let formatted = `${escapeHTML(request.statusLine || `HTTP/1.1 ${request.statusCode || 'Pending'}`)}\n`;
        
        for (const [key, value] of Object.entries(request.responseHeaders || {})) {
            formatted += `${escapeHTML(key)}: ${escapeHTML(value)}\n`;
        }
        
        if (request.responseBody) {
            formatted += '\n' + formatBody(request.responseBody, request.responseHeaders);
        }
        
        return { isImage: false, isHTML: isHTMLContent, content: formatted };
    }
}

function tryParseJSON(text) {
    if (!text) return '';
    try {
        return JSON.parse(text);
    } catch {
        return text;
    }
}

function formatBody(body, headers) {
    if (!body) return '';
    
    // Get content type from headers
    const contentType = Object.entries(headers || {})
        .find(([key, value]) => key.toLowerCase() === 'content-type')?.[1] || '';
    
    // Try to format based on content type or content detection
    if (contentType.includes('json') || isJSON(body)) {
        // Format as JSON
        try {
            const parsed = JSON.parse(body);
            const formatted = JSON.stringify(parsed, null, 2);
            // Escape HTML entities before highlighting to prevent injection
            const escaped = escapeHTML(formatted);
            return highlightSyntax(escaped, 'json');
        } catch {
            return escapeHTML(body);
        }
    } else if (contentType.includes('xml') || isXML(body)) {
        // Format as XML
        const formatted = formatXML(body);
        // Simple XML escaping for display before highlighting
        const escaped = escapeHTML(formatted);
        return highlightSyntax(escaped, 'xml');
    } else if (contentType.includes('html') || isHTML(body)) {
        // Format as HTML
        const formatted = formatHTML(body);
        const escaped = escapeHTML(formatted);
        return highlightSyntax(escaped, 'html');
    } else {
        // Return escaped body for other content types
        return escapeHTML(body);
    }
}

function isXML(str) {
    const trimmed = str.trim();
    return trimmed.startsWith('<?xml') || (trimmed.startsWith('<') && trimmed.endsWith('>'));
}

function isHTML(str) {
    const trimmed = str.trim().toLowerCase();
    return trimmed.includes('<!doctype html') || 
           trimmed.includes('<html') || 
           (trimmed.startsWith('<') && (trimmed.includes('<head') || trimmed.includes('<body') || trimmed.includes('<div')));
}

function formatXML(xml) {
    try {
        let formatted = '';
        let indent = 0;
        const parts = xml.split(/>\s*</);
        
        for (let i = 0; i < parts.length; i++) {
            let part = parts[i];
            if (i > 0) part = '<' + part;
            if (i < parts.length - 1) part = part + '>';
            
            // Decrease indent for closing tags
            if (part.match(/^<\/\w/)) indent--;
            
            formatted += '  '.repeat(Math.max(0, indent)) + part.trim() + '\n';
            
            // Increase indent for opening tags (not self-closing)
            if (part.match(/^<\w[^>]*[^\/]>.*$/)) indent++;
        }
        
        return formatted.trim();
    } catch {
        return xml;
    }
}

function formatHTML(html) {
    try {
        // Similar to XML but handles HTML specific cases
        let formatted = '';
        let indent = 0;
        const selfClosing = ['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'];
        
        const parts = html.split(/>\s*</);
        
        for (let i = 0; i < parts.length; i++) {
            let part = parts[i];
            if (i > 0) part = '<' + part;
            if (i < parts.length - 1) part = part + '>';
            
            // Check if it's a self-closing tag
            const tagName = part.match(/^<(\w+)/)?.[1]?.toLowerCase();
            const isSelfClosing = selfClosing.includes(tagName);
            
            // Decrease indent for closing tags
            if (part.match(/^<\/\w/)) indent--;
            
            formatted += '  '.repeat(Math.max(0, indent)) + part.trim() + '\n';
            
            // Increase indent for opening tags (not self-closing)
            if (part.match(/^<\w[^>]*[^\/]>.*$/) && !isSelfClosing) indent++;
        }
        
        return formatted.trim();
    } catch {
        return html;
    }
}

function clearRequestDetails() {
    requestContent.textContent = '';
    modifiedContent.textContent = '';
    responseContent.textContent = '';
    selectedRequest = null;
    
    // Hide modified tab when no request is selected
    const modifiedTabBtn = document.querySelector('.tab-btn[data-tab="modified"]');
    if (modifiedTabBtn) {
        modifiedTabBtn.style.display = 'none';
    }
    
    // Hide and clear security tab when no request is selected
    if (securityTabBtn) {
        securityTabBtn.style.display = 'none';
    }
    if (securityTabContent) {
        securityTabContent.innerHTML = `
            <div class="security-no-findings">
                <p>No security findings for this request.</p>
            </div>
        `;
    }
}

function generateCurl(request) {
    const method = request.originalMethod || request.method;
    const url = request.originalUrl || request.url;
    const headers = request.originalHeaders || request.requestHeaders || {};
    const body = request.originalBody !== undefined ? request.originalBody : request.requestBody;

    let curl = `curl -X ${method}`;
    
    for (const [key, value] of Object.entries(headers)) {
        if (key.toLowerCase() !== 'host' && key.toLowerCase() !== 'content-length') {
            curl += ` \\\n  -H '${key}: ${value}'`;
        }
    }
    
    if (body) {
        curl += ` \\\n  -d '${body.replace(/'/g, "\\'")}'`;
    }
    
    curl += ` \\\n  '${url}'`;
    
    return curl;
}

function generateModifiedCurl(request) {
    const method = request.modifiedMethod || request.method;
    const url = request.modifiedUrl || request.url;
    const headers = request.modifiedHeaders || request.requestHeaders || {};
    const body = request.modifiedBody !== undefined ? request.modifiedBody : request.requestBody;
    
    let curl = `curl -X ${method}`;
    
    for (const [key, value] of Object.entries(headers)) {
        if (key.toLowerCase() !== 'host' && key.toLowerCase() !== 'content-length') {
            curl += ` \\\n  -H '${key}: ${value}'`;
        }
    }
    
    if (body) {
        curl += ` \\\n  -d '${body.replace(/'/g, "\\'")}'`;
    }
    
    curl += ` \\\n  '${url}'`;
    
    return curl;
}

function showInterceptModal(request) {
    interceptHeadersEdited = false;
    document.getElementById('interceptMethod').value = request.method;
    document.getElementById('interceptUrl').value = request.url;
    document.getElementById('interceptHeaders').value = formatHeaders(request.requestHeaders);
    document.getElementById('interceptHeaders').placeholder = "";
    document.getElementById('interceptHeaders').readOnly = false;
    document.getElementById('interceptBody').value = request.requestBody || '';
    
    interceptModal.classList.add('show');
}

function closeInterceptModal() {
    if (interceptQueue.length > 0) {
        processNextIntercept();
    } else {
    interceptModal.classList.remove('show');
    interceptedRequest = null;
    interceptHeadersEdited = false;
    }
    updateQueueCounts();
}

function formatHeaders(headers) {
    if (!headers) return '';
    if (Array.isArray(headers)) {
        return headers.map(h => `${h.name}: ${h.value}`).join('\n');
    }
    if (typeof headers === 'object') {
        return Object.entries(headers).map(([key, value]) => `${key}: ${value}`).join('\n');
    }
    return String(headers);
}

function parseHeaders(text) {
    const headers = {};
    text.split('\n').forEach(line => {
        const index = line.indexOf(':');
        if (index > 0) {
            const key = line.substring(0, index).trim();
            const value = line.substring(index + 1).trim();
            headers[key] = value;
        }
    });
    return headers;
}

function calculateRequestSize(request) {
    let size = 0;
    
    // Calculate URL and method size
    if (request.url) size += request.url.length;
    if (request.method) size += request.method.length;
    
    // Calculate headers size
    if (request.requestHeaders) {
        for (const [key, value] of Object.entries(request.requestHeaders)) {
            size += key.length + value.length + 4; // +4 for ": " and "\r\n"
        }
    }
    
    // Calculate body size
    if (request.requestBody) {
        size += new Blob([request.requestBody]).size;
    }
    
    return size;
}

function calculateResponseSize(request) {
    let size = 0;
    
    // Calculate status line size
    if (request.statusCode) {
        size += request.statusCode.toString().length + 15; // Approximate status line
    }
    
    // Calculate headers size
    if (request.responseHeaders) {
        for (const [key, value] of Object.entries(request.responseHeaders)) {
            size += key.length + value.length + 4; // +4 for ": " and "\r\n"
        }
    }
    
    // Calculate body size
    if (request.responseBody) {
        size += new Blob([request.responseBody]).size;
    }
    
    return size;
}

function formatSize(bytes) {
    if (bytes === 0) return '-';
    
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    
    if (i === 0) return bytes + ' B';
    
    return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
}

function showRepeaterModal(request) {
    document.getElementById('repeaterMethod').value = request.method;
    document.getElementById('repeaterUrl').value = request.url;
    document.getElementById('repeaterHeaders').value = formatHeaders(request.requestHeaders);
    document.getElementById('repeaterBody').value = request.requestBody || '';
    
    document.getElementById('repeaterStatus').textContent = 'No response yet';
    document.getElementById('repeaterStatus').className = 'response-status';
    document.getElementById('repeaterResponseContent').textContent = '';
    lastRepeaterResponse = null;
    
    repeaterModal.classList.add('show');
}

function showModifiedRepeaterModal(request) {
    const method = request.modifiedMethod || request.method;
    const url = request.modifiedUrl || request.url;
    const headers = request.modifiedHeaders || request.requestHeaders || {};
    const body = request.modifiedBody !== undefined ? request.modifiedBody : request.requestBody;
    
    document.getElementById('repeaterMethod').value = method;
    document.getElementById('repeaterUrl').value = url;
    document.getElementById('repeaterHeaders').value = formatHeaders(headers);
    document.getElementById('repeaterBody').value = body || '';
    
    document.getElementById('repeaterStatus').textContent = 'No response yet';
    document.getElementById('repeaterStatus').className = 'response-status';
    document.getElementById('repeaterResponseContent').textContent = '';
    lastRepeaterResponse = null;
    
    repeaterModal.classList.add('show');
}

function sendRepeaterRequest() {
    const method = document.getElementById('repeaterMethod').value;
    const url = document.getElementById('repeaterUrl').value;
    const headersText = document.getElementById('repeaterHeaders').value;
    const body = document.getElementById('repeaterBody').value;
    
    const headers = parseHeaders(headersText);
    
    document.getElementById('repeaterStatus').textContent = 'Sending request...';
    document.getElementById('repeaterStatus').className = 'response-status';
    
    port.postMessage({
        type: 'sendRepeaterRequest',
        requestData: {
            method: method,
            url: url,
            headers: headers,
            body: body
        }
    });
}

function displayRepeaterResponse(response) {
    const content = document.getElementById('repeaterResponseContent');
    
    switch (currentRepeaterTab) {
        case 'headers':
            content.textContent = formatHeaders(response.headers);
            break;
        case 'body':
            if (isJSON(response.body)) {
                try {
                    content.textContent = JSON.stringify(JSON.parse(response.body), null, 2);
                } catch {
                    content.textContent = response.body;
                }
            } else {
                content.textContent = response.body;
            }
            break;
        case 'raw':
            let raw = `HTTP/1.1 ${response.status} ${response.statusText}\n`;
            raw += formatHeaders(response.headers);
            raw += '\n\n' + response.body;
            content.textContent = raw;
            break;
    }
}

function isJSON(str) {
    try {
        JSON.parse(str);
        return true;
    } catch {
        return false;
    }
}

function highlightContent(elementId, searchTerm, countElement) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    const originalText = element.textContent;
    
    if (!searchTerm) {
        element.textContent = originalText;
        if (countElement) countElement.textContent = '';
        return;
    }
    
    try {
        const regex = new RegExp(`(${escapeRegExp(searchTerm)})`, 'gi');
        const matches = originalText.match(regex);
        const matchCount = matches ? matches.length : 0;
        
        if (matchCount > 0) {
            const highlighted = originalText.replace(regex, '<mark>$1</mark>');
            element.innerHTML = highlighted;
            if (countElement) countElement.textContent = `${matchCount} match${matchCount !== 1 ? 'es' : ''}`;
        } else {
            element.textContent = originalText;
            if (countElement) countElement.textContent = 'No matches';
        }
    } catch (e) {
        element.textContent = originalText;
        if (countElement) countElement.textContent = '';
    }
}

function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Add search functionality for intercept and repeater modals
function setupModalSearch() {
    // Intercept modal search
    const interceptSearchInput = document.getElementById('interceptSearchInput');
    const interceptSearchCount = document.getElementById('interceptSearchCount');
    
    if (interceptSearchInput) {
        interceptSearchInput.addEventListener('input', () => {
            const searchTerm = interceptSearchInput.value;
            const content = document.getElementById('interceptMethod').value + '\n' +
                          document.getElementById('interceptUrl').value + '\n' +
                          document.getElementById('interceptHeaders').value + '\n' +
                          document.getElementById('interceptBody').value;
            
            if (searchTerm) {
                const regex = new RegExp(`(${escapeRegExp(searchTerm)})`, 'gi');
                const matches = content.match(regex);
                const matchCount = matches ? matches.length : 0;
                interceptSearchCount.textContent = matchCount > 0 ? 
                    `${matchCount} match${matchCount !== 1 ? 'es' : ''}` : 'No matches';
                
                // Highlight in textareas
                highlightTextarea('interceptHeaders', searchTerm);
                highlightTextarea('interceptBody', searchTerm);
            } else {
                interceptSearchCount.textContent = '';
            }
        });
    }
    
    // Repeater request search
    const repeaterRequestSearchInput = document.getElementById('repeaterRequestSearchInput');
    const repeaterRequestSearchCount = document.getElementById('repeaterRequestSearchCount');
    
    if (repeaterRequestSearchInput) {
        repeaterRequestSearchInput.addEventListener('input', () => {
            const searchTerm = repeaterRequestSearchInput.value;
            highlightTextarea('repeaterHeaders', searchTerm);
            highlightTextarea('repeaterBody', searchTerm);
            
            if (searchTerm) {
                const content = document.getElementById('repeaterMethod').value + '\n' +
                              document.getElementById('repeaterUrl').value + '\n' +
                              document.getElementById('repeaterHeaders').value + '\n' +
                              document.getElementById('repeaterBody').value;
                
                const regex = new RegExp(`(${escapeRegExp(searchTerm)})`, 'gi');
                const matches = content.match(regex);
                const matchCount = matches ? matches.length : 0;
                repeaterRequestSearchCount.textContent = matchCount > 0 ? 
                    `${matchCount} match${matchCount !== 1 ? 'es' : ''}` : 'No matches';
            } else {
                repeaterRequestSearchCount.textContent = '';
            }
        });
    }
    
    // Repeater response search
    const repeaterResponseSearchInput = document.getElementById('repeaterResponseSearchInput');
    const repeaterResponseSearchCount = document.getElementById('repeaterResponseSearchCount');
    
    if (repeaterResponseSearchInput) {
        repeaterResponseSearchInput.addEventListener('input', () => {
            const searchTerm = repeaterResponseSearchInput.value;
            highlightContent('repeaterResponseContent', searchTerm, repeaterResponseSearchCount);
        });
    }
}

function highlightTextarea(textareaId, searchTerm) {
    const textarea = document.getElementById(textareaId);
    if (!textarea) return;
    
    // For textareas, we can't use HTML markup, so we'll just select the first match
    if (searchTerm && textarea.value.toLowerCase().includes(searchTerm.toLowerCase())) {
        const startIndex = textarea.value.toLowerCase().indexOf(searchTerm.toLowerCase());
        textarea.setSelectionRange(startIndex, startIndex + searchTerm.length);
    }
}

// Initialize modal search when DOM is ready
setTimeout(setupModalSearch, 100);

// Intercept Settings Functions
function showInterceptSettingsModal() {
    updateInterceptSettingsUI();
    interceptSettingsModal.classList.add('show');
}

function updateInterceptSettingsUI() {
    // Update method checkboxes
    const allMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
    allMethods.forEach(method => {
        const checkbox = document.getElementById(`intercept${method}`);
        if (checkbox) {
            if (method === 'GET') {
                checkbox.checked = interceptSettings.includeGET;
            } else {
                checkbox.checked = interceptSettings.methods.includes(method);
            }
        }
    });
    
    // Update GET warning visibility
    const getWarning = document.getElementById('getWarning');
    getWarning.style.display = interceptSettings.includeGET ? 'block' : 'none';
    
    // Update URL patterns
    document.getElementById('includePatterns').value = interceptSettings.urlPatterns.join('\n');
    document.getElementById('excludePatterns').value = interceptSettings.excludePatterns.join('\n');
    
    // Update file extensions
    document.getElementById('excludeExtensions').value = interceptSettings.excludeExtensions.join(', ');
    
    // Update response interception
    document.getElementById('interceptResponses').checked = interceptSettings.interceptResponses;
    const responseWarning = document.getElementById('responseWarning');
    responseWarning.style.display = interceptSettings.interceptResponses ? 'block' : 'none';

    
    document.getElementById('useEarlyInterception').checked = interceptSettings.useEarlyInterception;
    const earlyInterceptionWarning = document.getElementById('earlyInterceptionWarning');
    earlyInterceptionWarning.style.display = interceptSettings.useEarlyInterception ? 'block' : 'none';

    // Update Scope settings
    document.getElementById('enableScope').checked = interceptSettings.scopeEnabled || false;
    document.getElementById('scopePatterns').value = (interceptSettings.scopePatterns || []).join('\n');
    document.getElementById('scopeExcludePatterns').value = (interceptSettings.scopeExcludePatterns || []).join('\n');
}

function saveInterceptSettings() {
    // Collect method settings
    const methods = [];
    let includeGET = false;
    
    const allMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
    allMethods.forEach(method => {
        const checkbox = document.getElementById(`intercept${method}`);
        if (checkbox && checkbox.checked) {
            if (method === 'GET') {
                includeGET = true;
            } else {
                methods.push(method);
            }
        }
    });
    
    // Collect URL patterns
    const includePatterns = document.getElementById('includePatterns').value
        .split('\n')
        .map(p => p.trim())
        .filter(p => p.length > 0);
        
    const excludePatterns = document.getElementById('excludePatterns').value
        .split('\n')
        .map(p => p.trim())
        .filter(p => p.length > 0);

    // Collect Scope settings
    const scopeEnabled = document.getElementById('enableScope').checked;
    const scopePatterns = document.getElementById('scopePatterns').value
        .split('\n')
        .map(p => p.trim())
        .filter(p => p.length > 0);
    const scopeExcludePatterns = document.getElementById('scopeExcludePatterns').value
        .split('\n')
        .map(p => p.trim())
        .filter(p => p.length > 0);
        
    // Collect file extensions
    const excludeExtensions = document.getElementById('excludeExtensions').value
        .split(',')
        .map(ext => ext.trim())
        .filter(ext => ext.length > 0);
        
    // Get response interception setting
    const interceptResponses = document.getElementById('interceptResponses').checked;

    // Get early interception setting
    const useEarlyInterception = document.getElementById('useEarlyInterception').checked;
    
    // Validate regex patterns
    const invalidPatterns = [];
    [...includePatterns, ...excludePatterns, ...scopePatterns, ...scopeExcludePatterns].forEach(pattern => {
        try {
            new RegExp(pattern);
        } catch (e) {
            invalidPatterns.push(pattern);
        }
    });
    
    if (invalidPatterns.length > 0) {
        alert(`Invalid regex patterns found:\n${invalidPatterns.join('\n')}\n\nPlease fix these patterns before saving.`);
        return;
    }
    
    // Update settings
    const newSettings = {
        methods: methods,
        includeGET: includeGET,
        urlPatterns: includePatterns,
        excludePatterns: excludePatterns,
        excludeExtensions: excludeExtensions,
        interceptResponses: interceptResponses,
        useEarlyInterception: useEarlyInterception,
        scopeEnabled: scopeEnabled,
        scopePatterns: scopePatterns,
        scopeExcludePatterns: scopeExcludePatterns
    };
    
    port.postMessage({
        type: 'updateInterceptSettings',
        settings: newSettings
    });
    
    interceptSettingsModal.classList.remove('show');
}

function resetInterceptSettings() {
    const defaultSettings = {
        methods: ['POST', 'PUT', 'PATCH', 'DELETE'],
        includeGET: false,
        urlPatterns: [],
        excludePatterns: [],
    excludeExtensions: ['css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'ico', 'svg', 'woff', 'woff2', 'ttf', 'eot'],
    interceptResponses: false,
    useEarlyInterception: false,
    scopeEnabled: false,
    scopePatterns: [],
    scopeExcludePatterns: []
};
    
    port.postMessage({
        type: 'updateInterceptSettings',
        settings: defaultSettings
    });
    
    interceptSettingsModal.classList.remove('show');
}

function showResponseInterceptModal(response) {
    document.getElementById('responseStatusCode').value = response.statusCode || 200;
    document.getElementById('responseStatusText').value = response.statusLine || 'OK';
    document.getElementById('responseHeaders').value = formatHeaders(response.responseHeaders);
    document.getElementById('responseBody').value = response.responseBody || '';
    
    responseInterceptModal.classList.add('show');
}

function closeResponseInterceptModal() {
    if (responseQueue.length > 0) {
        processNextResponseIntercept();
    } else {
    responseInterceptModal.classList.remove('show');
    interceptedResponse = null;
    }
    updateQueueCounts();
}

// Decoder Elements
const decoderBtn = document.getElementById('decoderBtn');
const decoderModal = document.getElementById('decoderModal');
const closeDecoderBtn = document.getElementById('closeDecoderBtn');
const decoderInput = document.getElementById('decoderInput');
const decoderOutput = document.getElementById('decoderOutput');
const decoderOperation = document.getElementById('decoderOperation');
const decoderEncodeBtn = document.getElementById('decoderEncodeBtn');
const decoderDecodeBtn = document.getElementById('decoderDecodeBtn');
const decoderPasteBtn = document.getElementById('decoderPasteBtn');
const decoderClearInputBtn = document.getElementById('decoderClearInputBtn');
const decoderClearOutputBtn = document.getElementById('decoderClearOutputBtn');
const decoderCopyBtn = document.getElementById('decoderCopyBtn');
const decoderSwapBtn = document.getElementById('decoderSwapBtn');

// Decoder Event Listeners
decoderBtn.addEventListener('click', () => {
    showDecoderModal();
});

closeDecoderBtn.addEventListener('click', () => {
    decoderModal.classList.remove('show');
});

document.getElementById('sendToDecoderBtn').addEventListener('click', () => {
    if (selectedRequest) {
        const content = formatRequestContent(selectedRequest, 'raw');
        showDecoderModal(content);
    }
});

document.getElementById('modifiedSendToDecoderBtn').addEventListener('click', () => {
    if (selectedRequest && selectedRequest.wasModified) {
        const content = formatModifiedRequestContent(selectedRequest, 'raw');
        showDecoderModal(content);
    }
});

decoderPasteBtn.addEventListener('click', async () => {
    try {
        const text = await navigator.clipboard.readText();
        decoderInput.value = text;
    } catch (err) {
        console.error('Failed to read clipboard:', err);
    }
});

decoderClearInputBtn.addEventListener('click', () => {
    decoderInput.value = '';
});

decoderClearOutputBtn.addEventListener('click', () => {
    decoderOutput.value = '';
});

decoderCopyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(decoderOutput.value).then(() => {
        const originalText = decoderCopyBtn.textContent;
        decoderCopyBtn.textContent = 'Copied!';
        setTimeout(() => {
            decoderCopyBtn.textContent = originalText;
        }, 2000);
    });
});

decoderSwapBtn.addEventListener('click', () => {
    const input = decoderInput.value;
    const output = decoderOutput.value;
    decoderInput.value = output;
    decoderOutput.value = input;
});

decoderEncodeBtn.addEventListener('click', () => {
    performEncoding();
});

decoderDecodeBtn.addEventListener('click', () => {
    performDecoding();
});

function showDecoderModal(initialText = '') {
    if (initialText) {
        decoderInput.value = initialText;
    }
    decoderModal.classList.add('show');
}

function performEncoding() {
    const input = decoderInput.value;
    const operation = decoderOperation.value;
    let output = '';

    try {
        switch (operation) {
            case 'url':
                output = encodeURIComponent(input);
                break;
            case 'base64':
                output = btoa(input);
                break;
            case 'hex':
                output = stringToHex(input);
                break;
            case 'html':
                output = escapeHTML(input);
                break;
        }
        decoderOutput.value = output;
    } catch (e) {
        decoderOutput.value = `Error encoding: ${e.message}`;
    }
}

function performDecoding() {
    const input = decoderInput.value;
    const operation = decoderOperation.value;
    let output = '';

    try {
        switch (operation) {
            case 'url':
                output = decodeURIComponent(input);
                break;
            case 'base64':
                output = atob(input);
                break;
            case 'hex':
                output = hexToString(input);
                break;
            case 'html':
                output = unescapeHTML(input);
                break;
            case 'jwt':
                output = decodeJWT(input);
                break;
        }
        decoderOutput.value = output;
    } catch (e) {
        decoderOutput.value = `Error decoding: ${e.message}`;
    }
}

function decodeJWT(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) {
            throw new Error('Invalid JWT format. Expected 3 parts separated by dots.');
        }

        const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
        
        let output = '=== Header ===\n';
        output += JSON.stringify(header, null, 2);
        output += '\n\n=== Payload ===\n';
        output += JSON.stringify(payload, null, 2);
        
        if (payload.exp) {
            const expDate = new Date(payload.exp * 1000);
            output += `\n\nExpires: ${expDate.toLocaleString()}`;
            const now = new Date();
            if (now > expDate) {
                output += ' (Expired)';
            } else {
                output += ' (Valid)';
            }
        }
        
        if (payload.iat) {
            const iatDate = new Date(payload.iat * 1000);
            output += `\nIssued At: ${iatDate.toLocaleString()}`;
        }
        
        output += '\n\n=== Signature ===\n';
        output += parts[2];
        
        return output;
    } catch (e) {
        throw new Error('Failed to decode JWT: ' + e.message);
    }
}

function stringToHex(str) {
    let hex = '';
    for (let i = 0; i < str.length; i++) {
        hex += '' + str.charCodeAt(i).toString(16).padStart(2, '0');
    }
    return hex;
}

function hexToString(hex) {
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return str;
}

function escapeHTML(str) {
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function unescapeHTML(str) {
    return str
        .replace(/&amp;/g, "&")
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&quot;/g, "\"")
        .replace(/&#039;/g, "'");
}