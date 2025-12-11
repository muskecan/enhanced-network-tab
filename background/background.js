let captureEnabled = false;
let interceptEnabled = false;
let interceptSettings = {
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
let matchReplaceRules = [];
let requests = new Map();
let activeTabId = null;
let devtoolsPorts = new Map();
let inspectedTabs = new Set(); // Track tabs that have DevTools open
let pendingRequests = new Map();
let pendingResponses = new Map();
let requestIdCounter = 0;
let requestIdMap = new Map();
let interceptedRequestIds = new Set();
let pendingUrlModifications = new Map();
let pendingHeaderModifications = new Map();
let pendingResponseHeaderIntercepts = new Map();
let pendingBodyModifications = new Map();

// Repeater request tracking - for handling forbidden headers (Cookie, Host, Origin, etc.)
let pendingRepeaterRequests = new Map(); // repeaterId -> { headers, url, method, body }
let repeaterIdCounter = 0;

const MAX_REQUESTS = 1000;

// ==========================================
// SECURITY SCANNER - Background Implementation
// ==========================================
let securityFindings = [];
const MAX_FINDINGS = 1000;

const SecurityScanner = {
    // API Key patterns - comprehensive patterns for background scanning
    apiKeyPatterns: [
        // AWS
        { pattern: /AKIA[0-9A-Z]{16}/g, type: 'AWS Access Key ID', severity: 'critical', strict: true },
        { pattern: /["']?(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret|aws[_-]?secret[_-]?key)["']?\s*[:=]\s*["']([a-zA-Z0-9/+=]{40})["']/gi, type: 'AWS Secret Key', severity: 'critical', strict: false },
        
        // Google
        { pattern: /AIza[0-9A-Za-z\-_]{35}/g, type: 'Google API Key', severity: 'critical', strict: true },
        { pattern: /ya29\.[0-9A-Za-z\-_]+/g, type: 'Google OAuth Access Token', severity: 'critical', strict: true },
        { pattern: /1\/[0-9A-Za-z\-]{43}/g, type: 'Google OAuth Refresh Token', severity: 'critical', strict: true },
        
        // GitHub
        { pattern: /ghp_[a-zA-Z0-9]{36}/g, type: 'GitHub Personal Access Token', severity: 'critical', strict: true },
        { pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g, type: 'GitHub Fine-Grained Token', severity: 'critical', strict: true },
        { pattern: /gho_[a-zA-Z0-9]{36}/g, type: 'GitHub OAuth Token', severity: 'critical', strict: true },
        { pattern: /ghu_[a-zA-Z0-9]{36}/g, type: 'GitHub User-to-Server Token', severity: 'critical', strict: true },
        { pattern: /ghs_[a-zA-Z0-9]{36}/g, type: 'GitHub Server-to-Server Token', severity: 'critical', strict: true },
        { pattern: /ghr_[a-zA-Z0-9]{36}/g, type: 'GitHub Refresh Token', severity: 'critical', strict: true },
        
        // OpenAI
        { pattern: /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g, type: 'OpenAI User API Key', severity: 'critical', strict: true },
        { pattern: /sk-proj-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g, type: 'OpenAI Project Key', severity: 'critical', strict: true },
        { pattern: /sk-proj-[a-zA-Z0-9_-]{20,}/g, type: 'OpenAI Project Key (Generic)', severity: 'critical', strict: true },
        { pattern: /sk-[a-zA-Z0-9_-]{32,}/g, type: 'OpenAI API Key (Generic)', severity: 'critical', strict: true },
        
        // Stripe
        { pattern: /sk_live_[0-9a-zA-Z]{24}/g, type: 'Stripe Live Secret Key', severity: 'critical', strict: true },
        { pattern: /sk_test_[0-9a-zA-Z]{24}/g, type: 'Stripe Test Secret Key', severity: 'medium', strict: true },
        { pattern: /rk_live_[0-9a-zA-Z]{99}/g, type: 'Stripe Restricted Key', severity: 'critical', strict: true },
        
        // Slack
        { pattern: /xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}/g, type: 'Slack Bot Token', severity: 'critical', strict: true },
        { pattern: /xoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}/g, type: 'Slack User Token', severity: 'critical', strict: true },
        { pattern: /xoxe\.xoxp-1-[0-9a-zA-Z]{166}/g, type: 'Slack Config Token', severity: 'critical', strict: true },
        { pattern: /xoxe-1-[0-9a-zA-Z]{147}/g, type: 'Slack Refresh Token', severity: 'critical', strict: true },
        { pattern: /T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}/g, type: 'Slack Webhook', severity: 'high', strict: true },
        
        // Twitter
        { pattern: /[1-9][0-9]+-[0-9a-zA-Z]{40}/g, type: 'Twitter Access Token', severity: 'critical', strict: true },
        
        // Facebook
        { pattern: /EAACEdEose0cBA[0-9A-Za-z]+/g, type: 'Facebook Access Token', severity: 'critical', strict: true },
        
        // Instagram
        { pattern: /[0-9a-fA-F]{7}\.[0-9a-fA-F]{32}/g, type: 'Instagram OAuth Token', severity: 'critical', strict: true },
        
        // Square
        { pattern: /sqOatp-[0-9A-Za-z\-_]{22}/g, type: 'Square Access Token', severity: 'critical', strict: true },
        { pattern: /sq0csp-[0-9A-Za-z\-_]{43}/g, type: 'Square OAuth Secret', severity: 'critical', strict: true },
        
        // Twilio
        { pattern: /SK[0-9a-fA-F]{32}/g, type: 'Twilio API Key', severity: 'critical', strict: true },
        { pattern: /55[0-9a-fA-F]{32}/g, type: 'Twilio Access Token', severity: 'critical', strict: true },
        
        // SendGrid
        { pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g, type: 'SendGrid API Key', severity: 'critical', strict: true },
        
        // Mailgun
        { pattern: /key-[0-9a-zA-Z]{32}/g, type: 'Mailgun API Key', severity: 'critical', strict: true },
        
        // MailChimp
        { pattern: /[0-9a-f]{32}-us[0-9]{1,2}/g, type: 'MailChimp Access Token', severity: 'critical', strict: true },
        
        // Heroku
        { pattern: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g, type: 'Heroku/UUID API Key', severity: 'medium', strict: false },
        
        // WakaTime
        { pattern: /waka_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, type: 'WakaTime API Key', severity: 'critical', strict: true },
        
        // Amazon MWS
        { pattern: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, type: 'Amazon MWS Auth Token', severity: 'critical', strict: true },
        
        // Foursquare
        { pattern: /R_[0-9a-f]{32}/g, type: 'Foursquare Secret Key', severity: 'critical', strict: true },
        
        // Picatic
        { pattern: /sk_live_[0-9a-z]{32}/g, type: 'Picatic API Key', severity: 'critical', strict: true },
        
        // Other services
        { pattern: /glpat-[a-zA-Z0-9_-]{20}/g, type: 'GitLab Personal Access Token', severity: 'critical', strict: true },
        { pattern: /sk-ant-[a-zA-Z0-9_-]{20,}/g, type: 'Anthropic API Key', severity: 'critical', strict: true },
        { pattern: /hf_[a-zA-Z0-9]{34}/g, type: 'HuggingFace API Token', severity: 'critical', strict: true },
        { pattern: /r8_[a-zA-Z0-9]{37}/g, type: 'Replicate API Token', severity: 'critical', strict: true },
        { pattern: /dop_v1_[a-f0-9]{64}/g, type: 'DigitalOcean Token', severity: 'critical', strict: true },
        { pattern: /secret_[a-zA-Z0-9]{43}/g, type: 'Notion Integration Token', severity: 'critical', strict: true },
        
        // Azure
        { pattern: /DefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=[A-Za-z0-9+/=]+/g, type: 'Azure Storage Connection', severity: 'critical', strict: true },
        
        // JWT
        { pattern: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, type: 'JWT Token', severity: 'medium', strict: false },
        
        // Basic Auth in URLs
        { pattern: /https?:\/\/[A-Za-z0-9_\-]+:[A-Za-z0-9_\-]+@[^\s"']+/g, type: 'Basic Auth URL', severity: 'critical', strict: true },
        
        // Private Keys
        { pattern: /-----BEGIN RSA PRIVATE KEY-----/g, type: 'RSA Private Key', severity: 'critical', strict: true },
        { pattern: /-----BEGIN PRIVATE KEY-----/g, type: 'Private Key', severity: 'critical', strict: true },
        
        // Generic patterns with JSON support
        { pattern: /["']?secret_key["']?\s*[:=]\s*["']([a-zA-Z0-9_\-/+=]{16,})["']/gi, type: 'Secret Key', severity: 'critical', strict: false },
        { pattern: /["']?(?:api_key|apikey)["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']/gi, type: 'API Key', severity: 'high', strict: false },
        { pattern: /["']?access_token["']?\s*[:=]\s*["']([a-zA-Z0-9_\-/+=]{20,})["']/gi, type: 'Access Token', severity: 'high', strict: false },
        { pattern: /["']?(?:api_secret|apiSecret)["']?\s*[:=]\s*["']([a-zA-Z0-9_\-/+=]{20,})["']/gi, type: 'API Secret', severity: 'critical', strict: false },
        { pattern: /["']?client_secret["']?\s*[:=]\s*["']([a-zA-Z0-9_\-/+=]{16,})["']/gi, type: 'Client Secret', severity: 'critical', strict: false },
    ],

    credentialPatterns: [
        { pattern: /["']?(?:password|passwd|pwd)["']?\s*[:=]\s*["']([^"']{6,})["']/gi, type: 'Password', severity: 'critical', strict: false },
        { pattern: /["']?(?:db[_-]?password|database[_-]?password)["']?\s*[:=]\s*["']([^"']{6,})["']/gi, type: 'Database Password', severity: 'critical', strict: false },
        { pattern: /["']?(?:connection[_-]?string|conn[_-]?str|database[_-]?url|db[_-]?url)["']?\s*[:=]\s*["']([^"']+)["']/gi, type: 'Connection String', severity: 'critical', strict: false },
    ],

    falsePositives: [
        'example.com', 'localhost', '127.0.0.1', 'test', 'demo', 'sample', 
        'placeholder', 'your_api_key', 'your_secret', 'api_key_here', 
        'secret_here', 'xxx', 'yyy', 'zzz', 'insert_', '_here', 'your-', 
        '-here', 'replace_', 'change_this', 'data:image', 'data:text'
    ],

    isFalsePositive(match, type) {
        const matchLower = match.toLowerCase();
        for (const fp of this.falsePositives) {
            if (matchLower.includes(fp)) return true;
        }
        if (type === 'JWT Token') {
            const parts = match.split('.');
            if (parts.length < 3 || match.length < 50) return true;
        }
        if (type.includes('Password')) {
            if (/["'](?:true|false|null|undefined|none|\*+|\.{3,})["']/i.test(match)) return true;
        }
        return false;
    },

    scanWithPatterns(content, patterns, category) {
        const findings = [];
        for (const patternInfo of patterns) {
            try {
                patternInfo.pattern.lastIndex = 0;
                let match;
                while ((match = patternInfo.pattern.exec(content)) !== null) {
                    const matchText = match[0];
                    if (!patternInfo.strict && this.isFalsePositive(matchText, patternInfo.type)) continue;
                    findings.push({
                        category: category,
                        type: patternInfo.type,
                        match: matchText.length > 200 ? matchText.substring(0, 200) + '...' : matchText,
                        severity: patternInfo.severity || 'info'
                    });
                    if (patternInfo.pattern.lastIndex === match.index) {
                        patternInfo.pattern.lastIndex++;
                    }
                }
            } catch (e) {
                console.error('Pattern scan error:', patternInfo.type, e);
            }
        }
        return findings;
    },

    removeDuplicates(findings) {
        const seen = new Set();
        return findings.filter(f => {
            const key = `${f.type}:${f.match}`;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });
    },

    scan(content, url = '') {
        if (!content || typeof content !== 'string' || content.length > 5 * 1024 * 1024) {
            return null;
        }
        const apiKeys = this.removeDuplicates(this.scanWithPatterns(content, this.apiKeyPatterns, 'API Keys'));
        const credentials = this.removeDuplicates(this.scanWithPatterns(content, this.credentialPatterns, 'Credentials'));
        const totalFindings = apiKeys.length + credentials.length;
        if (totalFindings === 0) return null;
        return { url, timestamp: new Date().toISOString(), apiKeys, credentials, totalFindings };
    },

    isScannable(contentType) {
        if (!contentType) return false;
        const scannableTypes = ['text/html', 'text/plain', 'text/javascript', 'application/javascript', 'application/json', 'application/xml', 'text/xml'];
        return scannableTypes.some(type => contentType.toLowerCase().includes(type));
    }
};

// Update badge with findings count
function updateBadge() {
    const count = securityFindings.reduce((acc, f) => acc + f.totalFindings, 0);
    browser.browserAction.setBadgeText({ text: count > 0 ? String(count) : '' });
    browser.browserAction.setBadgeBackgroundColor({ color: '#dc3545' });
}

// Clear security findings
function clearSecurityFindings() {
    securityFindings = [];
    browser.storage.local.set({ securityFindings: [] });
    updateBadge();
}

// Load saved settings from storage on startup
browser.storage.local.get(['interceptSettings', 'captureEnabled', 'matchReplaceRules', 'securityFindings']).then((result) => {
  if (result.interceptSettings) {
    interceptSettings = { ...interceptSettings, ...result.interceptSettings };
  }
  if (result.captureEnabled !== undefined) {
    captureEnabled = result.captureEnabled;
    updateIcon();
  }
  if (result.matchReplaceRules) {
    matchReplaceRules = result.matchReplaceRules;
  }
  if (result.securityFindings) {
    securityFindings = result.securityFindings;
    updateBadge();
  }
}).catch((err) => {
  console.error('Failed to load settings from storage:', err);
});

browser.tabs.onActivated.addListener((activeInfo) => {
  activeTabId = activeInfo.tabId;
  updateIcon();
});

browser.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
  if (tabs[0]) {
    activeTabId = tabs[0].id;
  }
});

browser.browserAction.onClicked.addListener(() => {
  captureEnabled = !captureEnabled;
  // Save capture state to storage
  browser.storage.local.set({ captureEnabled: captureEnabled }).catch((err) => {
    console.error('Failed to save capture state:', err);
  });
  updateIcon();
  notifyDevTools({ type: 'captureStateChanged', enabled: captureEnabled });
});


browser.runtime.onInstalled.addListener(() => {
  browser.contextMenus.create({
    id: "toggle-capture",
    title: "Toggle Capture",
    contexts: ["all"]
  });
  browser.contextMenus.create({
    id: "toggle-intercept",
    title: "Toggle Intercept",
    contexts: ["all"]
  });
  browser.contextMenus.create({
    id: "send-to-decoder",
    title: "Send to Decoder",
    contexts: ["selection"]
  });
});

browser.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "toggle-capture") {
    captureEnabled = !captureEnabled;
    if (!captureEnabled && interceptEnabled) {
      interceptEnabled = false;
      notifyDevTools({ type: 'interceptStateChanged', enabled: false });
    }
    // Save capture state to storage
    browser.storage.local.set({ captureEnabled: captureEnabled }).catch((err) => {
      console.error('Failed to save capture state:', err);
    });
    updateIcon();
    notifyDevTools({ type: 'captureStateChanged', enabled: captureEnabled });
  } else if (info.menuItemId === "toggle-intercept") {
    interceptEnabled = !interceptEnabled;
    if (interceptEnabled && !captureEnabled) {
      captureEnabled = true;
      browser.storage.local.set({ captureEnabled: captureEnabled }).catch((err) => {
        console.error('Failed to save capture state:', err);
      });
      notifyDevTools({ type: 'captureStateChanged', enabled: true });
    }
    updateIcon();
    notifyDevTools({ type: 'interceptStateChanged', enabled: interceptEnabled });
  } else if (info.menuItemId === "send-to-decoder") {
    notifyDevTools({ 
      type: 'sendToDecoder', 
      text: info.selectionText 
    });
  }
});

function updateIcon() {
  const iconPath = captureEnabled ? {
    16: 'icons/icon16.png',
    32: 'icons/icon32.png',
    48: 'icons/icon48.png',
    128: 'icons/icon128.png'
  } : {
    16: 'icons/icon16.png',
    32: 'icons/icon32.png',
    48: 'icons/icon48.png',
    128: 'icons/icon128.png'
  };
  
  browser.browserAction.setIcon({ path: iconPath });
  browser.browserAction.setTitle({ 
    title: `Security Proxy - ${captureEnabled ? 'Capturing' : 'Idle'}${interceptEnabled ? ' (Intercepting)' : ''}`
  });
}

function getRequestBody(details) {
  if (details.requestBody) {
    if (details.requestBody.formData) {
      return JSON.stringify(details.requestBody.formData);
    } else if (details.requestBody.raw) {
      const decoder = new TextDecoder('utf-8');
      return details.requestBody.raw.map(data => decoder.decode(new Uint8Array(data.bytes))).join('');
    }
  }
  return '';
}

function shouldInterceptRequest(details) {
  let shouldIntercept = false;
  
  if (interceptSettings.includeGET && details.method === 'GET') {
    shouldIntercept = true;
  } else if (interceptSettings.methods.includes(details.method)) {
    shouldIntercept = true;
  }
  
  if (!shouldIntercept) {
    return false;
  }
  
  if (interceptSettings.excludeExtensions.length > 0) {
    const url = new URL(details.url);
    const pathname = url.pathname.toLowerCase();
    const hasExcludedExtension = interceptSettings.excludeExtensions.some(ext => {
      return pathname.endsWith('.' + ext.toLowerCase()) || 
             pathname.includes('.' + ext.toLowerCase() + '?') ||
             pathname.includes('.' + ext.toLowerCase() + '#');
    });
    
    if (hasExcludedExtension) {
      return false;
    }
  }
  
  if (interceptSettings.urlPatterns.length > 0) {
    const matchesIncludePattern = interceptSettings.urlPatterns.some(pattern => {
      try {
        const regex = new RegExp(pattern, 'i');
        return regex.test(details.url);
      } catch (e) {
        console.warn('Invalid regex pattern:', pattern);
        return false;
      }
    });
    
    if (!matchesIncludePattern) {
      return false;
    }
  }
  
  if (interceptSettings.excludePatterns.length > 0) {
    const matchesExcludePattern = interceptSettings.excludePatterns.some(pattern => {
      try {
        const regex = new RegExp(pattern, 'i');
        return regex.test(details.url);
      } catch (e) {
        console.warn('Invalid regex pattern:', pattern);
        return false;
      }
    });
    
    if (matchesExcludePattern) {
      return false;
    }
  }
  
  return true;
}

browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    // Check if capture is enabled and the request is from an inspected tab or active tab
    const isInspectedTab = inspectedTabs.has(details.tabId);
    const isActiveTab = details.tabId === activeTabId;
    
    if (!captureEnabled || details.tabId === -1 || (!isInspectedTab && !isActiveTab)) {
      return {};
    }

    // Scope check
    if (interceptSettings.scopeEnabled) {
      // 1. Check Include Patterns (Whitelist)
      if (interceptSettings.scopePatterns.length > 0) {
        const isInScope = interceptSettings.scopePatterns.some(pattern => {
          try {
            const regex = new RegExp(pattern, 'i');
            return regex.test(details.url);
          } catch (e) {
            console.warn('Invalid regex pattern:', pattern);
            return false;
          }
        });
        
        if (!isInScope) {
          return {};
        }
      }

      // 2. Check Exclude Patterns (Blacklist)
      if (interceptSettings.scopeExcludePatterns && interceptSettings.scopeExcludePatterns.length > 0) {
        const isExcluded = interceptSettings.scopeExcludePatterns.some(pattern => {
          try {
            const regex = new RegExp(pattern, 'i');
            return regex.test(details.url);
          } catch (e) {
            console.warn('Invalid regex pattern:', pattern);
            return false;
          }
        });
        
        if (isExcluded) {
          return {};
        }
      }
    }
    
    const requestId = `${details.requestId}_${requestIdCounter++}`;
    requestIdMap.set(details.requestId, requestId);
    
    // Create request data object early to track modification
    const requestData = {
      id: requestId,
      originalRequestId: details.requestId,
      timestamp: Date.now(),
      url: details.url,
      method: details.method,
      type: details.type,
      requestHeaders: {},
      requestBody: getRequestBody(details),
      requestSize: 0,
      responseHeaders: {},
      responseBody: '',
      responseSize: 0,
      statusCode: null,
      statusLine: '',
      tabId: details.tabId,
      completed: false,
      intercepted: false,
      shouldIntercept: false,
      wasModified: false,
      autoModified: false
    };

    // Apply match & replace rules for onBeforeRequest (URL and Body)
    let modifiedDetails = { ...details };
    let wasModified = false;
    let bodyModified = false;
    let urlModified = false;
    let modifiedBody = requestData.requestBody;
    
    if (matchReplaceRules.length > 0) {
        for (const rule of matchReplaceRules) {
            if (!rule.enabled) continue;
            
            if (rule.target === 'url') {
                const newUrl = applyRuleReplacement(modifiedDetails.url, rule);
                if (newUrl !== modifiedDetails.url) {
                    modifiedDetails.url = newUrl;
                    wasModified = true;
                    urlModified = true;
                }
            } else if (rule.target === 'body') {
                const newBody = applyRuleReplacement(modifiedBody, rule);
                if (newBody !== modifiedBody) {
                    modifiedBody = newBody;
                    wasModified = true;
                    bodyModified = true;
                }
            }
        }
    }

    if (wasModified) {
        requestData.wasModified = true;
        requestData.autoModified = true;
        
        // Priority 1: URL Redirection
        if (urlModified) {
            requestData.originalUrl = details.url;
            requestData.modifiedUrl = modifiedDetails.url;
            requestData.statusLine = 'Auto-Redirected (Rule)';
            requestData.statusCode = 307; // Internal redirect code
            requestData.completed = true;
            
            requests.set(requestId, requestData);
            
            notifyDevTools({
                type: 'newRequest',
                request: requestData
            });

            return { redirectUrl: modifiedDetails.url };
        }
        
        // Priority 2: Body Modification (Wait for headers)
        if (bodyModified) {
            // Store for onBeforeSendHeaders where we can get headers and cancel/resend
            pendingBodyModifications.set(details.requestId, {
                modifiedBody: modifiedBody,
                requestData: requestData
            });
            
            // We don't cancel here anymore. We wait for headers.
            // We still update the requestData for the UI to know it's being processed
            requestData.statusLine = 'Pending Body Mod...';
            requests.set(requestId, requestData);
            notifyDevTools({ type: 'newRequest', request: requestData });
            
            return {};
        }
    }
    
    if (interceptEnabled && shouldInterceptRequest(details)) {
      requestData.shouldIntercept = true;
      requestData.intercepted = true;
      requestData.statusLine = 'Intercepted';
      
      if (interceptSettings.interceptResponses) {
        interceptedRequestIds.add(details.requestId);
      }
      
      requests.set(requestId, requestData);
      
      if (requests.size > MAX_REQUESTS) {
        const oldestKey = requests.keys().next().value;
        const oldRequest = requests.get(oldestKey);
        if (oldRequest) {
          requestIdMap.delete(oldRequest.originalRequestId);
        }
        requests.delete(oldestKey);
      }
      
      notifyDevTools({
        type: 'newRequest',
        request: requestData
      });

      if (interceptSettings.useEarlyInterception) {
        return new Promise((resolve) => {
           const pendingData = {
             ...requestData,
             resolve: resolve,
             originalRequestId: details.requestId,
             stage: 'onBeforeRequest'
           };
           pendingRequests.set(details.requestId, pendingData);
           
           notifyDevTools({
             type: 'interceptRequest',
             request: {
                 ...requestData,
                 stage: 'onBeforeRequest'
             }
           });
        });
      }

      return {};
    }
    
    requests.set(requestId, requestData);
    
    if (requests.size > MAX_REQUESTS) {
      const oldestKey = requests.keys().next().value;
      const oldRequest = requests.get(oldestKey);
      if (oldRequest) {
        requestIdMap.delete(oldRequest.originalRequestId);
      }
      requests.delete(oldestKey);
    }
    
    notifyDevTools({
      type: 'newRequest',
      request: requestData
    });
    
    return {};
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestBody"]
);

function applyHeaderRules(originalHeaders) {
    if (!matchReplaceRules.length) return { headers: originalHeaders, modified: false };

    let headersModified = false;
    let newHeaders = originalHeaders.map(header => {
        let headerModified = false;
        let newValue = header.value;
        
        for (const rule of matchReplaceRules) {
            if (!rule.enabled || rule.target !== 'headers') continue;
            
            const replaced = applyRuleReplacement(newValue, rule);
            if (replaced !== newValue) {
                newValue = replaced;
                headerModified = true;
            }
        }
        
        if (headerModified) {
            headersModified = true;
            return { name: header.name, value: newValue };
        }
        return header;
    });
    
    return { headers: newHeaders, modified: headersModified };
}

browser.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    // Check if this is a Repeater request (from background script, identified by marker header)
    const repeaterIdHeader = details.requestHeaders.find(h => h.name.toLowerCase() === 'x-repeater-id');
    if (repeaterIdHeader) {
      const repeaterId = repeaterIdHeader.value;
      const pendingRepeater = pendingRepeaterRequests.get(repeaterId);
      
      if (pendingRepeater) {
        // Build new headers array from user's desired headers (including forbidden ones like Cookie, Host, Origin, etc.)
        const newHeaders = [];
        
        for (const [name, value] of Object.entries(pendingRepeater.headers)) {
          // Skip the marker header - we don't want to send it to the server
          if (name.toLowerCase() !== 'x-repeater-id') {
            newHeaders.push({ name, value });
          }
        }
        
        // Return modified headers - this allows us to set ANY header including forbidden ones
        return { requestHeaders: newHeaders };
      }
    }
    
    const isTrackedTab = inspectedTabs.has(details.tabId) || details.tabId === activeTabId;
    if (!captureEnabled || !isTrackedTab) return {};
    
    const requestId = requestIdMap.get(details.requestId);
    if (!requestId) return {};
    
    const request = requests.get(requestId);
    
    // Check for Pending Body Modification
    if (pendingBodyModifications.has(details.requestId)) {
        const pendingBodyMod = pendingBodyModifications.get(details.requestId);
        pendingBodyModifications.delete(details.requestId);
        
        if (request) {
            request.originalBody = request.requestBody;
            request.modifiedBody = pendingBodyMod.modifiedBody;
            request.statusLine = 'Auto-Modified (Body)';
            
            // Apply header rules
            const { headers: newHeaders, modified: headersModified } = applyHeaderRules(details.requestHeaders);
            
            if (headersModified) {
                request.statusLine = 'Auto-Modified (Body & Headers)';
            }

            // Store original and modified headers
            request.originalHeaders = details.requestHeaders.reduce((acc, h) => ({ ...acc, [h.name]: h.value }), {});
            
            const newHeadersObj = newHeaders.reduce((acc, h) => {
                acc[h.name] = h.value;
                return acc;
            }, {});
            
            // Update request object with headers so they appear in UI
            request.requestHeaders = newHeadersObj;
            request.modifiedHeaders = newHeadersObj;

            // Prepare headers for fetch (filtering unsafe)
            const headers = {};
            const unsafeHeaders = ['host', 'content-length', 'connection', 'origin', 'referer', 'accept-encoding', 'cookie', 'user-agent'];
            
            newHeaders.forEach(h => {
                if (!unsafeHeaders.includes(h.name.toLowerCase())) {
                    headers[h.name] = h.value;
                }
            });
            
            // Resend
            resendModifiedRequest(request, {
                url: details.url,
                method: details.method,
                headers: headers,
                body: pendingBodyMod.modifiedBody
            });
            
            return { cancel: true };
        }
    }
    
    // Apply Match & Replace for Headers
    const { headers: newHeaders, modified: headersModified } = applyHeaderRules(details.requestHeaders);
    
    if (headersModified) {
        if (request) {
            request.wasModified = true;
            request.autoModified = true;
            request.originalHeaders = details.requestHeaders.reduce((acc, h) => ({ ...acc, [h.name]: h.value }), {});
            request.statusLine = (request.statusLine && request.statusLine !== 'Pending' ? request.statusLine : 'Auto-Modified') + ' (Headers)';
            
            request.requestHeaders = newHeaders.reduce((acc, header) => {
                acc[header.name] = header.value;
                if (header.name.toLowerCase() === 'content-length') {
                    request.requestSize = parseInt(header.value, 10) || 0;
                }
                return acc;
            }, {});
        }
        
        // Send update immediately to reflect auto-modification
        if (request) {
                notifyDevTools({
                type: 'updateRequest',
                request: request
                });
        }

        return { requestHeaders: newHeaders };
    }

    if (request) {
      // Standard logic - update headers from details (original)
      request.requestHeaders = details.requestHeaders.reduce((acc, header) => {
        acc[header.name] = header.value;
        if (header.name.toLowerCase() === 'content-length') {
          request.requestSize = parseInt(header.value, 10) || 0;
        }
        return acc;
      }, {});
      
      notifyDevTools({
        type: 'updateRequest',
        request: request
      });
      
      if (request.shouldIntercept && !pendingRequests.has(details.requestId)) {
        return new Promise((resolve) => {
          request.intercepted = true;
          request.statusLine = 'Intercepted (Headers)';
          
          const pendingData = {
            ...request,
            resolve: resolve,
            originalRequestId: details.requestId,
            stage: 'onBeforeSendHeaders'
          };
          pendingRequests.set(details.requestId, pendingData);
          
          notifyDevTools({
            type: 'interceptRequest',
            request: {
                ...request,
                stage: 'onBeforeSendHeaders'
            }
          });
        });
      }
    }
    
    return {};
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestHeaders"]
);

browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    const isTrackedTab = inspectedTabs.has(details.tabId) || details.tabId === activeTabId;
    if (!captureEnabled || details.tabId === -1 || !isTrackedTab) {
      return {};
    }
    
    const requestId = requestIdMap.get(details.requestId);
    if (!requestId) return {};
    
    const request = requests.get(requestId);
    if (!request) return {};
    
    const shouldInterceptResponse = interceptedRequestIds.has(details.requestId);
    
    const contentType = details.responseHeaders?.find(h => 
      h.name.toLowerCase() === 'content-type'
    )?.value || '';
    
    const isTextContent = contentType.includes('json') || 
        contentType.includes('text') || 
        contentType.includes('xml') ||
        contentType.includes('javascript') ||
        contentType.includes('html');
    
    const isImageContent = contentType.includes('image/');
    
    if (isTextContent || isImageContent) {
      const filter = browser.webRequest.filterResponseData(details.requestId);
      const decoder = new TextDecoder('utf-8');
      let responseData = [];
      
      if (shouldInterceptResponse) {
        filter.ondata = event => {
          responseData.push(event.data);
        };
        
        filter.onstop = event => {
          try {
            const combinedData = new Uint8Array(
              responseData.reduce((acc, chunk) => acc + chunk.byteLength, 0)
            );
            let offset = 0;
            for (const chunk of responseData) {
              combinedData.set(new Uint8Array(chunk), offset);
              offset += chunk.byteLength;
            }
            
            let bodyContent;
            if (isImageContent) {
              let binary = '';
              const len = combinedData.byteLength;
              for (let i = 0; i < len; i++) {
                binary += String.fromCharCode(combinedData[i]);
              }
              bodyContent = btoa(binary);
              request.responseBody = bodyContent;
              request.isBase64 = true;
            } else {
              bodyContent = decoder.decode(combinedData);
              request.responseBody = bodyContent.substring(0, 50000);
              request.isBase64 = false;
            }
            
            const responseInterceptData = {
              requestId: requestId,
              originalRequestId: details.requestId,
              filter: filter,
              responseHeaders: details.responseHeaders,
              responseBody: bodyContent,
              statusCode: details.statusCode,
              statusLine: details.statusLine,
              request: request,
              isBase64: isImageContent,
              stage: 'responseBody'
            };
            
            pendingResponses.set(details.requestId, responseInterceptData);
            interceptedRequestIds.delete(details.requestId);
            
            notifyDevTools({
              type: 'interceptResponse',
              response: {
                requestId: requestId,
                statusCode: details.statusCode,
                statusLine: details.statusLine,
                responseHeaders: details.responseHeaders,
                responseBody: bodyContent,
                isBase64: isImageContent,
                stage: 'responseBody'
              }
            });
            
          } catch (e) {
            console.error('Failed to decode response for interception:', e);
            filter.close();
          }
        };
        
        return new Promise((resolve) => {
            const pendingHeaderData = {
              requestId: requestId,
              originalRequestId: details.requestId,
              resolve: resolve,
              responseHeaders: details.responseHeaders,
              statusCode: details.statusCode,
              statusLine: details.statusLine,
              stage: 'responseHeaders',
              request: request
            };
            pendingResponseHeaderIntercepts.set(requestId, pendingHeaderData);
            
            notifyDevTools({
              type: 'interceptResponse',
              response: {
                 requestId: requestId,
                 statusCode: details.statusCode,
                 statusLine: details.statusLine,
                 responseHeaders: details.responseHeaders,
                 stage: 'responseHeaders'
              }
            });
         });

      } else {
        filter.ondata = event => {
          responseData.push(event.data);
          filter.write(event.data);
        };
        
        filter.onstop = event => {
          filter.close();
          
          try {
            const combinedData = new Uint8Array(
              responseData.reduce((acc, chunk) => acc + chunk.byteLength, 0)
            );
            let offset = 0;
            for (const chunk of responseData) {
              combinedData.set(new Uint8Array(chunk), offset);
              offset += chunk.byteLength;
            }
            
            if (isImageContent) {
              let binary = '';
              const len = combinedData.byteLength;
              for (let i = 0; i < len; i++) {
                binary += String.fromCharCode(combinedData[i]);
              }
              const base64 = btoa(binary);
              request.responseBody = base64;
              request.isBase64 = true;
            } else {
              const text = decoder.decode(combinedData);
              request.responseBody = text.substring(0, 50000);
              request.isBase64 = false;
              
              // Background security scanning - runs even when DevTools is closed
              if (captureEnabled && SecurityScanner.isScannable(contentType)) {
                const scanResults = SecurityScanner.scan(text, details.url);
                if (scanResults && scanResults.totalFindings > 0) {
                  scanResults.requestId = request.id;
                  securityFindings.push(scanResults);
                  
                  // Limit stored findings
                  if (securityFindings.length > MAX_FINDINGS) {
                    securityFindings = securityFindings.slice(-MAX_FINDINGS);
                  }
                  
                  // Persist findings to storage
                  browser.storage.local.set({ securityFindings }).catch(err => {
                    console.error('Failed to save security findings:', err);
                  });
                  
                  // Update badge
                  updateBadge();
                  
                  // Notify DevTools if connected
                  notifyDevTools({
                    type: 'securityFinding',
                    finding: scanResults
                  });
                }
              }
            }
            
            notifyDevTools({
              type: 'updateRequest',
              request: request
            });
          } catch (e) {
            console.error('Failed to decode response:', e);
          }
        };
      }
    }
    
    return {};
  },
  { urls: ["<all_urls>"], types: ["xmlhttprequest", "main_frame", "sub_frame", "image", "media", "font", "script", "stylesheet", "other"] },
  ["blocking", "responseHeaders"]
);

browser.webRequest.onResponseStarted.addListener(
  (details) => {
    const isTrackedTab = inspectedTabs.has(details.tabId) || details.tabId === activeTabId;
    if (!captureEnabled || !isTrackedTab) return;
    
    const requestId = requestIdMap.get(details.requestId);
    if (!requestId) return;
    
    const request = requests.get(requestId);
    if (request) {
      request.statusCode = details.statusCode;
      request.statusLine = details.statusLine;
      request.responseHeaders = details.responseHeaders.reduce((acc, header) => {
        acc[header.name] = header.value;
        if (header.name.toLowerCase() === 'content-length') {
          request.responseSize = parseInt(header.value, 10) || 0;
        }
        return acc;
      }, {});
      notifyDevTools({
        type: 'updateRequest',
        request: request
      });
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

browser.webRequest.onCompleted.addListener(
  (details) => {
    const isTrackedTab = inspectedTabs.has(details.tabId) || details.tabId === activeTabId;
    if (!captureEnabled || !isTrackedTab) return;
    
    const requestId = requestIdMap.get(details.requestId);
    if (!requestId) return;
    
    const request = requests.get(requestId);
    if (request) {
      request.completed = true;
      notifyDevTools({
        type: 'updateRequest',
        request: request
      });
      requestIdMap.delete(details.requestId);
    }
  },
  { urls: ["<all_urls>"] }
);

browser.webRequest.onErrorOccurred.addListener(
  (details) => {
    const isTrackedTab = inspectedTabs.has(details.tabId) || details.tabId === activeTabId;
    if (!captureEnabled || !isTrackedTab) return;
    
    const requestId = requestIdMap.get(details.requestId);
    if (!requestId) return;
    
    const request = requests.get(requestId);
    if (request) {
      request.statusCode = 0;
      request.statusLine = `Error: ${details.error}`;
      request.completed = true;
      notifyDevTools({
        type: 'updateRequest',
        request: request
      });
      requestIdMap.delete(details.requestId);
    }
  },
  { urls: ["<all_urls>"] }
);

browser.runtime.onConnect.addListener((port) => {
  if (port.name === 'devtools-panel') {
    const tabId = port.sender?.tab?.id || 'devtools';
    devtoolsPorts.set(tabId, port);
    
    port.postMessage({
      type: 'initialState',
      captureEnabled: captureEnabled,
      interceptEnabled: interceptEnabled,
      interceptSettings: interceptSettings,
      requests: Array.from(requests.values()),
      securityFindings: securityFindings
    });
    
    port.onMessage.addListener((msg) => {
      handleDevToolsMessage(msg, port);
    });
    
    port.onDisconnect.addListener(() => {
      devtoolsPorts.delete(tabId);
      // Clean up inspected tab when DevTools closes
      if (port.inspectedTabId) {
        inspectedTabs.delete(port.inspectedTabId);
      }
    });
  }
});

function handleDevToolsMessage(msg, port) {
  switch (msg.type) {
    case 'setInspectedTab':
      if (msg.tabId) {
        inspectedTabs.add(msg.tabId);
        // Store the tab ID with the port for cleanup
        port.inspectedTabId = msg.tabId;
      }
      break;
      
    case 'toggleCapture':
      captureEnabled = msg.enabled;
      if (!captureEnabled && interceptEnabled) {
        interceptEnabled = false;
        notifyDevTools({ type: 'interceptStateChanged', enabled: false });
      }
      // Save capture state to storage
      browser.storage.local.set({ captureEnabled: captureEnabled }).catch((err) => {
        console.error('Failed to save capture state:', err);
      });
      updateIcon();
      notifyDevTools({ type: 'captureStateChanged', enabled: captureEnabled });
      break;
      
    case 'toggleIntercept':
      interceptEnabled = msg.enabled;
      if (interceptEnabled && !captureEnabled) {
        captureEnabled = true;
        notifyDevTools({ type: 'captureStateChanged', enabled: true });
      }
      updateIcon();
      notifyDevTools({ type: 'interceptStateChanged', enabled: interceptEnabled });
      break;
      
    case 'clearRequests':
      requests.clear();
      notifyDevTools({ type: 'requestsCleared' });
      break;
      
    case 'forwardRequest':
      handleForwardRequest(msg.requestId, msg.modifiedRequest);
      break;
      
    case 'dropRequest':
      handleDropRequest(msg.requestId);
      break;
      
    case 'getRequestBody':
      const request = requests.get(msg.requestId);
      if (request) {
        fetchResponseBody(request);
      }
      break;
      
    case 'sendRepeaterRequest':
      handleRepeaterRequest(msg.requestData, port);
      break;
      
    case 'updateInterceptSettings':
      interceptSettings = { ...interceptSettings, ...msg.settings };
      // Save to storage for persistence
      browser.storage.local.set({ interceptSettings: interceptSettings }).catch((err) => {
        console.error('Failed to save intercept settings:', err);
      });
      notifyDevTools({ type: 'interceptSettingsChanged', settings: interceptSettings });
      break;

    case 'updateMatchReplaceRules':
      matchReplaceRules = msg.rules;
      browser.storage.local.set({ matchReplaceRules: matchReplaceRules }).catch((err) => {
        console.error('Failed to save match replace rules:', err);
      });
      break;
      
    case 'getInterceptSettings':
      port.postMessage({ type: 'interceptSettingsResponse', settings: interceptSettings });
      break;
      
    case 'getSecurityFindings':
      port.postMessage({ type: 'securityFindingsResponse', findings: securityFindings });
      break;
      
    case 'clearSecurityFindings':
      clearSecurityFindings();
      notifyDevTools({ type: 'securityFindingsCleared' });
      break;
      
    case 'forwardResponse':
      handleForwardResponse(msg.requestId, msg.modifiedResponse);
      break;
      
    case 'dropResponse':
      handleDropResponse(msg.requestId);
      break;
      
    case 'disableIntercept':
      handleDisableIntercept(msg.currentRequestId, msg.currentType);
      break;
  }
}

async function resendModifiedRequest(request, modifiedRequest) {
    request.intercepted = false;
    request.statusLine = 'Resending (Modified)';
    
    notifyDevTools({
      type: 'updateRequest',
      request: request
    });
    
    // Generate unique repeater ID for tracking this request (reusing repeater system)
    const repeaterId = `resend_${++repeaterIdCounter}_${Date.now()}`;
    
    try {
      // Store all desired headers (including forbidden ones like Cookie, Host, Origin, etc.)
      // These will be applied in onBeforeSendHeaders where we can set any header
      pendingRepeaterRequests.set(repeaterId, {
        headers: modifiedRequest.headers,
        url: modifiedRequest.url,
        method: modifiedRequest.method,
        body: modifiedRequest.body
      });
      
      // Only use marker header for fetch - all other headers will be set in onBeforeSendHeaders
      const fetchOptions = {
        method: modifiedRequest.method,
        headers: {
          'X-Repeater-ID': repeaterId
        }
      };
      
      if (['POST', 'PUT', 'PATCH'].includes(modifiedRequest.method) && modifiedRequest.body) {
        fetchOptions.body = modifiedRequest.body;
      }
      
      const startTime = Date.now();
      const response = await fetch(modifiedRequest.url, fetchOptions);
      const duration = Date.now() - startTime;
      
      // Cleanup after successful request
      pendingRepeaterRequests.delete(repeaterId);
      
      const responseHeaders = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });
      
      const contentType = response.headers.get('content-type') || '';
      let responseBody = '';
      
      // Determine status line - use HTTP/1.1 as fallback if protocol not available
      // fetch response doesn't typically expose protocol version
      const statusText = response.statusText || 'OK';
      const statusLine = `HTTP/1.1 ${response.status} ${statusText}`;
      
      if (contentType.includes('image/')) {
        const blob = await response.blob();
        const arrayBuffer = await blob.arrayBuffer();
        const uint8Array = new Uint8Array(arrayBuffer);
        let binary = '';
        for (let i = 0; i < uint8Array.byteLength; i++) {
          binary += String.fromCharCode(uint8Array[i]);
        }
        responseBody = btoa(binary);
        request.isBase64 = true;
      } else {
        responseBody = await response.text();
        responseBody = responseBody.substring(0, 50000);
        request.isBase64 = false;
      }
      
      request.statusCode = response.status;
      request.statusLine = statusLine;
      request.responseHeaders = responseHeaders;
      request.responseBody = responseBody;
      request.completed = true;
      request.autoModified = true; // Ensure it's marked
      request.wasModified = true;
      
      notifyDevTools({
        type: 'updateRequest',
        request: request
      });
      
    } catch (error) {
      // Cleanup on error as well
      pendingRepeaterRequests.delete(repeaterId);
      
      request.statusCode = 0;
      request.statusLine = `Modification Failed: ${error.message}`;
      request.completed = true;
      
      notifyDevTools({
        type: 'updateRequest',
        request: request
      });
    }
}

async function handleForwardRequest(requestId, modifiedRequest) {
  let originalRequestId = null;
  let pending = null;
  
  for (const [key, value] of pendingRequests.entries()) {
    if (value.id === requestId) {
      originalRequestId = key;
      pending = value;
      break;
    }
  }
  
  if (pending && pending.resolve) {
    const request = requests.get(requestId);
    
    const urlChanged = modifiedRequest && modifiedRequest.url !== pending.url;
    const methodChanged = modifiedRequest && modifiedRequest.method !== pending.method;
    const headersChanged = modifiedRequest && JSON.stringify(modifiedRequest.headers) !== JSON.stringify(pending.requestHeaders);
    const bodyChanged = modifiedRequest && modifiedRequest.body !== pending.requestBody;
    
    const wasModified = urlChanged || methodChanged || headersChanged || bodyChanged;
    
    if (pending.stage === 'onBeforeRequest') {
        if (urlChanged) {
             request.originalUrl = pending.url;
             request.modifiedUrl = modifiedRequest.url;
             request.wasModified = true;
             request.statusLine = 'Redirecting (Early Intercept)';
             request.intercepted = false;
             
             notifyDevTools({ type: 'updateRequest', request: request });
             
             pending.resolve({ redirectUrl: modifiedRequest.url });
        } else {
             request.intercepted = false;
             request.statusLine = 'Forwarded (Early Intercept)';
             notifyDevTools({ type: 'updateRequest', request: request });
             pending.resolve({});
        }
        pendingRequests.delete(originalRequestId);
        return;
    }

    if (wasModified && request) {
      request.originalUrl = pending.url;
      request.originalMethod = pending.method;
      request.originalHeaders = { ...pending.requestHeaders };
      request.originalBody = pending.requestBody;
      
      request.modifiedUrl = modifiedRequest.url;
      request.modifiedMethod = modifiedRequest.method;
      request.modifiedHeaders = { ...modifiedRequest.headers };
      request.modifiedBody = modifiedRequest.body;
      request.wasModified = true;
      
      if (urlChanged || bodyChanged || methodChanged) {
        if (request.type === 'main_frame' && modifiedRequest.method === 'GET' && modifiedRequest.url !== pending.url) {
          pending.resolve({ cancel: true });
          pendingRequests.delete(originalRequestId);
          
          request.intercepted = false;
          request.statusLine = 'Redirecting (Navigation)';
          request.statusCode = 307;
          request.completed = true;
          
          notifyDevTools({
            type: 'updateRequest',
            request: request
          });
          
          browser.tabs.update(request.tabId, { url: modifiedRequest.url });
          return;
        }

        pending.resolve({ cancel: true });
        pendingRequests.delete(originalRequestId);
        
        resendModifiedRequest(request, modifiedRequest);
        return;
      }
      
      if (headersChanged) {
         const modifiedHeadersArray = Object.entries(modifiedRequest.headers).map(([name, value]) => ({
            name,
            value
         }));
         
         pending.resolve({ requestHeaders: modifiedHeadersArray });
         pendingRequests.delete(originalRequestId);
         
         request.statusLine = 'Forwarded (Headers Modified)';
         request.intercepted = false;
         notifyDevTools({ type: 'updateRequest', request: request });
         return;
      }
    } else {
      pending.resolve({});
      pendingRequests.delete(originalRequestId);
      
      if (request) {
        request.intercepted = false;
        request.statusLine = 'Forwarded (Unmodified)';
        notifyDevTools({
          type: 'updateRequest',
          request: request
        });
      }
    }
  }
}

function handleDropRequest(requestId) {
  let originalRequestId = null;
  let pending = null;
  
  for (const [key, value] of pendingRequests.entries()) {
    if (value.id === requestId) {
      originalRequestId = key;
      pending = value;
      break;
    }
  }
  
  if (pending && pending.resolve) {
    const request = requests.get(requestId);
    if (request) {
      request.intercepted = false;
      request.statusLine = 'Dropped';
      request.statusCode = 0;
      request.completed = true;
      notifyDevTools({
        type: 'updateRequest',
        request: request
      });
    }
    
    pending.resolve({ cancel: true });
    pendingRequests.delete(originalRequestId);
  }
}

async function fetchResponseBody(request) {
  try {
    const response = await fetch(request.url, {
      method: 'GET',
      credentials: 'omit'
    });
    const text = await response.text();
    request.responseBody = text.substring(0, 50000);
    notifyDevTools({
      type: 'updateRequest',
      request: request
    });
  } catch (error) {
    console.error('Failed to fetch response body:', error);
  }
}

function handleForwardResponse(requestId, modifiedResponse) {
  const headerIntercept = pendingResponseHeaderIntercepts.get(requestId);
  if (headerIntercept) {
    const { resolve, originalRequestId, request } = headerIntercept;
    
    if (modifiedResponse && modifiedResponse.headers) {
      const modifiedHeadersArray = Object.entries(modifiedResponse.headers).map(([name, value]) => ({
        name,
        value
      }));
      
      if (request) {
        request.responseHeaders = modifiedResponse.headers;
        request.statusLine = 'Headers Modified';
        notifyDevTools({
          type: 'updateRequest',
          request: request
        });
      }
      
      resolve({ responseHeaders: modifiedHeadersArray });
    } else {
      resolve({});
    }
    
    pendingResponseHeaderIntercepts.delete(requestId);
    return;
  }

  let originalRequestId = null;
  let pending = null;
  
  for (const [key, value] of pendingResponses.entries()) {
    if (value.requestId === requestId) {
      originalRequestId = key;
      pending = value;
      break;
    }
  }
  
  if (pending && pending.filter) {
    try {
      const request = requests.get(requestId);
      if (request) {
        request.responseIntercepted = false;
        request.statusLine = 'Response Modified';
        notifyDevTools({
          type: 'updateRequest',
          request: request
        });
      }
      
      const modifiedData = new TextEncoder().encode(modifiedResponse.body || pending.responseBody);
      pending.filter.write(modifiedData);
      pending.filter.close();
      
      pendingResponses.delete(originalRequestId);
    } catch (e) {
      console.error('Failed to forward modified response:', e);
      pending.filter.close();
      pendingResponses.delete(originalRequestId);
    }
  }
}

function handleDropResponse(requestId) {
  let originalRequestId = null;
  let pending = null;
  
  for (const [key, value] of pendingResponses.entries()) {
    if (value.requestId === requestId) {
      originalRequestId = key;
      pending = value;
      break;
    }
  }
  
  if (pending && pending.filter) {
    const request = requests.get(requestId);
    if (request) {
      request.responseIntercepted = false;
      request.statusLine = 'Response Dropped';
      request.statusCode = 0;
      notifyDevTools({
        type: 'updateRequest',
        request: request
      });
    }
    
    pending.filter.close();
    pendingResponses.delete(originalRequestId);
  }
}

function handleDisableIntercept(currentRequestId, currentType) {
  interceptEnabled = false;
  
  if (currentType === 'request') {
    let currentOriginalRequestId = null;
    let currentPending = null;
    
    for (const [key, value] of pendingRequests.entries()) {
      if (value.id === currentRequestId) {
        currentOriginalRequestId = key;
        currentPending = value;
        break;
      }
    }
    
    if (currentPending && currentPending.resolve) {
      currentPending.resolve({});
      pendingRequests.delete(currentOriginalRequestId);
    }
  } else if (currentType === 'response') {
    let currentOriginalRequestId = null;
    let currentPending = null;
    
    for (const [key, value] of pendingResponses.entries()) {
      if (value.requestId === currentRequestId) {
        currentOriginalRequestId = key;
        currentPending = value;
        break;
      }
    }
    
    if (currentPending && currentPending.filter) {
      const originalData = new TextEncoder().encode(currentPending.responseBody);
      currentPending.filter.write(originalData);
      currentPending.filter.close();
      pendingResponses.delete(currentOriginalRequestId);
    }
  }
  
  for (const [requestId, pendingData] of pendingRequests.entries()) {
    if (pendingData.resolve) {
      pendingData.resolve({});
    }
  }
  pendingRequests.clear();
  
  for (const [requestId, responseData] of pendingResponses.entries()) {
    if (responseData.filter) {
      const originalData = new TextEncoder().encode(responseData.responseBody);
      responseData.filter.write(originalData);
      responseData.filter.close();
    }
  }
  pendingResponses.clear();
  
  interceptedRequestIds.clear();
  
  updateIcon();
  notifyDevTools({ 
    type: 'interceptStateChanged', 
    enabled: false 
  });
}

function notifyDevTools(message) {
  devtoolsPorts.forEach(port => {
    try {
      port.postMessage(message);
    } catch (e) {
      console.error('Failed to send message to devtools:', e);
    }
  });
}

function applyRuleReplacement(source, rule) {
    try {
        const type = rule.matchType || 'regex'; // Default to regex for backward compatibility
        const pattern = rule.matchPattern;
        const replacement = rule.replaceValue;
        
        if (!pattern) return source;

        switch (type) {
            case 'regex':
                const regex = new RegExp(pattern, 'g');
                return source.replace(regex, replacement);
                
            case 'contains':
                // Global string replacement
                return source.split(pattern).join(replacement);
                
            case 'starts_with':
                if (source.startsWith(pattern)) {
                    return replacement + source.substring(pattern.length);
                }
                return source;
            
            case 'ends_with':
                if (source.endsWith(pattern)) {
                    return source.substring(0, source.length - pattern.length) + replacement;
                }
                return source;
                
            case 'exact':
                if (source === pattern) {
                    return replacement;
                }
                return source;
                
            default:
                return source;
        }
    } catch (e) {
        console.error('Error applying rule replacement:', e);
        return source;
    }
}

async function handleRepeaterRequest(requestData, port) {
  // Generate unique repeater ID for tracking this request (outside try block for cleanup access)
  const repeaterId = `repeater_${++repeaterIdCounter}_${Date.now()}`;
  
  try {
    // Store all user's desired headers (including forbidden ones like Cookie, Host, Origin, etc.)
    // These will be applied in onBeforeSendHeaders where we can set any header
    pendingRepeaterRequests.set(repeaterId, {
      headers: requestData.headers,
      url: requestData.url,
      method: requestData.method,
      body: requestData.body
    });
    
    // Only use marker header for fetch - all other headers will be set in onBeforeSendHeaders
    const options = {
      method: requestData.method,
      headers: {
        'X-Repeater-ID': repeaterId
      }
    };
    
    if (['POST', 'PUT', 'PATCH'].includes(requestData.method) && requestData.body) {
      options.body = requestData.body;
    }
    
    const startTime = Date.now();
    const response = await fetch(requestData.url, options);
    const duration = Date.now() - startTime;
    
    // Cleanup after successful request
    pendingRepeaterRequests.delete(repeaterId);
    
    const responseHeaders = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });
    
    const responseBody = await response.text();
    
    port.postMessage({
      type: 'repeaterResponse',
      response: {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
        body: responseBody,
        duration: duration
      }
    });
  } catch (error) {
    // Cleanup on error as well
    pendingRepeaterRequests.delete(repeaterId);
    
    port.postMessage({
      type: 'repeaterError',
      error: error.message
    });
  }
}
