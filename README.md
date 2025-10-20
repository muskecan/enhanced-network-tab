# Enhanced Network Tab

A lightweight Firefox extension for capturing, analyzing, and modifying HTTP/HTTPS requests in real-time.

[![Install from Firefox Add-ons](https://img.shields.io/badge/Firefox-Install-orange?logo=firefox)](https://addons.mozilla.org/en-US/firefox/addon/enhanced-network-tab/)

## Features

- **Request Capture**: Monitor all HTTP/HTTPS traffic from the active tab
- **Request Interception**: Intercept and modify requests before they are sent
- **Response Interception**: Intercept and modify responses before they reach the browser
- **Request Repeater**: Resend requests with custom modifications for testing
- **Advanced Filtering**: Filter requests by method, URL patterns, and file types
- **Dark/Light Theme**: Automatic or manual theme switching
- **Export as cURL**: Copy any request as a cURL command
- **Column Sorting**: Sort and resize request table columns
- **Search**: Search through request/response headers and bodies

## Screenshots

### Main Dashboard
![Enhanced Network Tab Dashboard](readme-pictures/dashboard.png)

### Request Interception
![Request Interception Modal](readme-pictures/interception.png)

## Installation

### From Firefox Add-ons

**[Install directly from Firefox Add-ons →](https://addons.mozilla.org/en-US/firefox/addon/enhanced-network-tab/)**

Click the link above or search for "Enhanced Network Tab" in Firefox Add-ons.

### From Source

1. Clone or download this repository
2. Open Firefox and navigate to `about:debugging`
3. Click "This Firefox" in the left sidebar
4. Click "Load Temporary Add-on"
5. Navigate to the extension directory and select the `manifest.json` file

## Usage

1. Open Firefox Developer Tools (F12)
2. Navigate to the "Enhanced Network Tab" panel
3. Toggle "Capture" to start monitoring network traffic
4. Toggle "Intercept" to intercept and modify requests (optional)
5. Click on any request to view details
6. Use "Send to Repeater" to resend modified requests
7. Configure intercept rules via "Intercept Settings"

## Privacy & Security

**This extension is 100% privacy-focused and works completely offline:**

- No data is sent to any external servers
- No analytics, tracking, or telemetry
- All data stays in your browser
- Only uses local storage for UI preferences (theme, column widths)
- All network requests you see are made by YOU manually (via Repeater feature)

The extension only monitors and modifies network traffic you explicitly choose to intercept. No data leaves your machine.

## Browser Compatibility

- **Firefox**: Version 57+ (Quantum and later)
- **Chrome/Edge**: Not supported (uses Firefox-specific WebExtension APIs)

## Development

The extension is built using vanilla JavaScript with the Firefox WebExtensions API.

### File Structure

```
├── background/
│   └── background.js       # Background service worker
├── devtools/
│   ├── devtools.html       # DevTools panel entry point
│   ├── devtools.js         # DevTools panel initialization
│   ├── panel.html          # Main UI
│   ├── panel.js            # UI logic and event handlers
│   └── panel.css           # Styles with theme support
├── icons/                  # Extension icons
└── manifest.json           # Extension manifest
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

For bugs, feature requests, or questions, please open an issue on GitHub.

