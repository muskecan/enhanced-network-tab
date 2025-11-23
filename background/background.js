let captureEnabled = false;
let interceptEnabled = false;
let interceptSettings = {
  methods: ['POST', 'PUT', 'PATCH', 'DELETE'],
  includeGET: false,
  urlPatterns: [],
  excludePatterns: [],
  excludeExtensions: ['css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'ico', 'svg', 'woff', 'woff2', 'ttf', 'eot'],
  interceptResponses: false,
  useEarlyInterception: false
};
let requests = new Map();
let activeTabId = null;
let devtoolsPorts = new Map();
let pendingRequests = new Map();
let pendingResponses = new Map();
let requestIdCounter = 0;
let requestIdMap = new Map();
let interceptedRequestIds = new Set();
let pendingUrlModifications = new Map();
let pendingHeaderModifications = new Map();
let pendingResponseHeaderIntercepts = new Map();

const MAX_REQUESTS = 100;

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
    updateIcon();
    notifyDevTools({ type: 'captureStateChanged', enabled: captureEnabled });
  } else if (info.menuItemId === "toggle-intercept") {
    interceptEnabled = !interceptEnabled;
    if (interceptEnabled && !captureEnabled) {
      captureEnabled = true;
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
    if (!captureEnabled || details.tabId !== activeTabId || details.tabId === -1) {
      return {};
    }
    
    const requestId = `${details.requestId}_${requestIdCounter++}`;
    requestIdMap.set(details.requestId, requestId);
    
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
      shouldIntercept: false
    };
    
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

browser.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    if (!captureEnabled || details.tabId !== activeTabId) return {};
    
    const requestId = requestIdMap.get(details.requestId);
    if (!requestId) return {};
    
    const request = requests.get(requestId);
    if (request) {
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
    if (!captureEnabled || details.tabId !== activeTabId || details.tabId === -1) {
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
    if (!captureEnabled || details.tabId !== activeTabId) return;
    
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
    if (!captureEnabled || details.tabId !== activeTabId) return;
    
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
    if (!captureEnabled || details.tabId !== activeTabId) return;
    
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
      requests: Array.from(requests.values())
    });
    
    port.onMessage.addListener((msg) => {
      handleDevToolsMessage(msg, port);
    });
    
    port.onDisconnect.addListener(() => {
      devtoolsPorts.delete(tabId);
    });
  }
});

function handleDevToolsMessage(msg, port) {
  switch (msg.type) {
    case 'toggleCapture':
      captureEnabled = msg.enabled;
      if (!captureEnabled && interceptEnabled) {
        interceptEnabled = false;
        notifyDevTools({ type: 'interceptStateChanged', enabled: false });
      }
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
      notifyDevTools({ type: 'interceptSettingsChanged', settings: interceptSettings });
      break;
      
    case 'getInterceptSettings':
      port.postMessage({ type: 'interceptSettingsResponse', settings: interceptSettings });
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
        
        request.intercepted = false;
        request.statusLine = 'Resending (Modified)';
        
        notifyDevTools({
          type: 'updateRequest',
          request: request
        });
        
        try {
          const fetchOptions = {
            method: modifiedRequest.method,
            headers: modifiedRequest.headers
          };
          
          if (['POST', 'PUT', 'PATCH'].includes(modifiedRequest.method) && modifiedRequest.body) {
            fetchOptions.body = modifiedRequest.body;
          }
          
          const startTime = Date.now();
          const response = await fetch(modifiedRequest.url, fetchOptions);
          const duration = Date.now() - startTime;
          
          const responseHeaders = {};
          response.headers.forEach((value, key) => {
            responseHeaders[key] = value;
          });
          
          const contentType = response.headers.get('content-type') || '';
          let responseBody = '';
          
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
          request.statusLine = `Modified & Resent (${duration}ms)`;
          request.responseHeaders = responseHeaders;
          request.responseBody = responseBody;
          request.completed = true;
          
          notifyDevTools({
            type: 'updateRequest',
            request: request
          });
          
        } catch (error) {
          request.statusCode = 0;
          request.statusLine = `Modification Failed: ${error.message}`;
          request.completed = true;
          
          notifyDevTools({
            type: 'updateRequest',
            request: request
          });
        }
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

async function handleRepeaterRequest(requestData, port) {
  try {
    const options = {
      method: requestData.method,
      headers: requestData.headers
    };
    
    if (['POST', 'PUT', 'PATCH'].includes(requestData.method) && requestData.body) {
      options.body = requestData.body;
    }
    
    const startTime = Date.now();
    const response = await fetch(requestData.url, options);
    const duration = Date.now() - startTime;
    
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
    port.postMessage({
      type: 'repeaterError',
      error: error.message
    });
  }
}
