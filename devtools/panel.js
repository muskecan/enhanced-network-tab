let port = browser.runtime.connect({ name: 'devtools-panel' });
let requests = [];
let selectedRequest = null;
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
    // Load and apply saved column widths
    applyColumnWidths();
    
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
let currentRepeaterTab = 'headers';
let lastRepeaterResponse = null;

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
                requests[index] = msg.request;
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
            renderRequestList();
            clearRequestDetails();
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
        
        if (selectedRequest && selectedRequest.id === req.id) {
            row.classList.add('selected');
        }
        
        if (req.wasModified) {
            row.classList.add('modified-request');
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
        }
    }
    
    if (currentTab === 'request') {
        const content = formatRequestContent(request, currentRequestView);
        requestContent.textContent = content;
        
        // Update active button for request tab
        document.querySelectorAll('#requestTab .view-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.view === currentRequestView);
        });
    } else if (currentTab === 'modified') {
        const content = formatModifiedRequestContent(request, currentModifiedView);
        modifiedContent.textContent = content;
        
        // Update active button for modified tab
        document.querySelectorAll('#modifiedTab .view-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.view === currentModifiedView);
        });
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
        
        if (result.isImage || result.isPreview) {
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

function formatRequestContent(request, view) {
    if (view === 'raw') {
        let raw = `${request.method} ${request.url} HTTP/1.1\n`;
        
        for (const [key, value] of Object.entries(request.requestHeaders || {})) {
            raw += `${key}: ${value}\n`;
        }
        
        if (request.requestBody) {
            raw += `\n${request.requestBody}`;
        }
        
        return raw;
    } else {
        // Formatted view - show headers as-is, format body based on content type
        let formatted = `${request.method} ${request.url} HTTP/1.1\n`;
        
        for (const [key, value] of Object.entries(request.requestHeaders || {})) {
            formatted += `${key}: ${value}\n`;
        }
        
        if (request.requestBody) {
            formatted += '\n' + formatBody(request.requestBody, request.requestHeaders);
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
        let formatted = `${request.modifiedMethod || request.method} ${request.modifiedUrl || request.url} HTTP/1.1\n`;
        
        const headers = request.modifiedHeaders || request.requestHeaders || {};
        for (const [key, value] of Object.entries(headers)) {
            formatted += `${key}: ${value}\n`;
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
        let headers = `HTTP/1.1 ${request.statusCode || 'Pending'} ${request.statusLine || ''}\n`;
        for (const [key, value] of Object.entries(request.responseHeaders || {})) {
            headers += `${key}: ${value}\n`;
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
            <div class="response-headers">${headers}</div>
            <img src="${imgSrc}" alt="Response Image" class="response-image" onerror="this.style.display='none'; this.parentElement.innerHTML += '<div style=\\'padding: 20px; color: #f44336;\\'>Failed to load image</div>';" />
        </div>`;
        
        return { isImage: true, isHTML: false, content: imageHtml };
    }
    
    // Handle HTML preview in iframe
    if (isHTMLContent && request.responseBody && view === 'preview') {
        let headers = `HTTP/1.1 ${request.statusCode || 'Pending'} ${request.statusLine || ''}\n`;
        for (const [key, value] of Object.entries(request.responseHeaders || {})) {
            headers += `${key}: ${value}\n`;
        }
        
        // Create iframe with sandboxed HTML content
        const htmlContent = request.responseBody
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
        
        const previewHtml = `<div class="response-preview-container">
            <div class="response-headers">${headers}</div>
            <iframe class="response-preview-iframe" sandbox="allow-same-origin" srcdoc="${htmlContent}"></iframe>
        </div>`;
        
        return { isImage: false, isHTML: true, isPreview: true, content: previewHtml };
    }
    
    if (view === 'raw') {
        let raw = `HTTP/1.1 ${request.statusCode || 'Pending'} ${request.statusLine || ''}\n`;
        
        for (const [key, value] of Object.entries(request.responseHeaders || {})) {
            raw += `${key}: ${value}\n`;
        }
        
        if (request.responseBody) {
            raw += `\n${request.responseBody}`;
        }
        
        return { isImage: false, isHTML: isHTMLContent, content: raw };
    } else {
        // Formatted view - show headers as-is, format body based on content type
        let formatted = `HTTP/1.1 ${request.statusCode || 'Pending'} ${request.statusLine || ''}\n`;
        
        for (const [key, value] of Object.entries(request.responseHeaders || {})) {
            formatted += `${key}: ${value}\n`;
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
            return JSON.stringify(parsed, null, 2);
        } catch {
            return body;
        }
    } else if (contentType.includes('xml') || isXML(body)) {
        // Format as XML
        return formatXML(body);
    } else if (contentType.includes('html') || isHTML(body)) {
        // Format as HTML
        return formatHTML(body);
    } else {
        // Return as-is for other content types
        return body;
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
}

function generateCurl(request) {
    let curl = `curl -X ${request.method}`;
    
    for (const [key, value] of Object.entries(request.requestHeaders || {})) {
        if (key.toLowerCase() !== 'host' && key.toLowerCase() !== 'content-length') {
            curl += ` \\\n  -H '${key}: ${value}'`;
        }
    }
    
    if (request.requestBody) {
        curl += ` \\\n  -d '${request.requestBody.replace(/'/g, "\\'")}'`;
    }
    
    curl += ` \\\n  '${request.url}'`;
    
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
    [...includePatterns, ...excludePatterns].forEach(pattern => {
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
        useEarlyInterception: useEarlyInterception
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
        useEarlyInterception: false
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
        }
        decoderOutput.value = output;
    } catch (e) {
        decoderOutput.value = `Error decoding: ${e.message}`;
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