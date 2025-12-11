

const SecurityScanner = {
    // API Key patterns - comprehensive patterns based on official documentation
    // All patterns support both JSON ("key": "value") and config (key = "value") formats where applicable
    apiKeyPatterns: [
        // ==========================================
        // AMAZON WEB SERVICES (AWS)
        // ==========================================
        { pattern: /AKIA[0-9A-Z]{16}/g, type: 'AWS Access Key ID', severity: 'critical', strict: true },
        { pattern: /["']?(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret|aws[_-]?secret[_-]?key)["']?\s*[:=]\s*["']([a-zA-Z0-9/+=]{40})["']/gi, type: 'AWS Secret Key', severity: 'critical', strict: false },
        
        // ==========================================
        // GOOGLE CLOUD PLATFORM
        // ==========================================
        // Google API Key
        { pattern: /AIza[0-9A-Za-z\-_]{35}/g, type: 'Google API Key', severity: 'critical', strict: true },
        // Google OAuth 2.0 Access Token
        { pattern: /ya29\.[0-9A-Za-z\-_]+/g, type: 'Google OAuth Access Token', severity: 'critical', strict: true },
        // Google OAuth 2.0 Refresh Token
        { pattern: /1\/[0-9A-Za-z\-]{43}/g, type: 'Google OAuth Refresh Token (43)', severity: 'critical', strict: true },
        { pattern: /1\/[0-9A-Za-z\-]{64}/g, type: 'Google OAuth Refresh Token (64)', severity: 'critical', strict: true },
        // GCP OAuth 2.0
        { pattern: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g, type: 'GCP OAuth 2.0', severity: 'medium', strict: false },
        // GCP API Key Format
        { pattern: /[A-Za-z0-9_]{21}--[A-Za-z0-9_]{8}/g, type: 'GCP API Key', severity: 'critical', strict: true },
        
        // ==========================================
        // GITHUB
        // ==========================================
        { pattern: /ghp_[a-zA-Z0-9]{36}/g, type: 'GitHub Personal Access Token (Classic)', severity: 'critical', strict: true },
        { pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g, type: 'GitHub Personal Access Token (Fine-Grained)', severity: 'critical', strict: true },
        { pattern: /gho_[a-zA-Z0-9]{36}/g, type: 'GitHub OAuth 2.0 Access Token', severity: 'critical', strict: true },
        { pattern: /ghu_[a-zA-Z0-9]{36}/g, type: 'GitHub User-to-Server Access Token', severity: 'critical', strict: true },
        { pattern: /ghs_[a-zA-Z0-9]{36}/g, type: 'GitHub Server-to-Server Access Token', severity: 'critical', strict: true },
        { pattern: /ghr_[a-zA-Z0-9]{36}/g, type: 'GitHub Refresh Token', severity: 'critical', strict: true },
        
        // ==========================================
        // OPENAI
        // ==========================================
        // OpenAI User API Key (with T3BlbkFJ marker)
        { pattern: /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g, type: 'OpenAI User API Key', severity: 'critical', strict: true },
        // OpenAI Project Key (with T3BlbkFJ marker)
        { pattern: /sk-proj-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g, type: 'OpenAI Project API Key', severity: 'critical', strict: true },
        // OpenAI Service Key
        { pattern: /sk-[A-Za-z0-9]+-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g, type: 'OpenAI Service Key', severity: 'critical', strict: true },
        // Generic OpenAI patterns (fallback)
        { pattern: /sk-proj-[a-zA-Z0-9_-]{20,}/g, type: 'OpenAI Project Key (Generic)', severity: 'critical', strict: true },
        { pattern: /sk-[a-zA-Z0-9_-]{32,}/g, type: 'OpenAI API Key (Generic)', severity: 'critical', strict: true },
        
        // ==========================================
        // STRIPE
        // ==========================================
        { pattern: /sk_live_[0-9a-zA-Z]{24}/g, type: 'Stripe Standard API Key (Live)', severity: 'critical', strict: true },
        { pattern: /sk_test_[0-9a-zA-Z]{24}/g, type: 'Stripe Standard API Key (Test)', severity: 'medium', strict: true },
        { pattern: /rk_live_[0-9a-zA-Z]{99}/g, type: 'Stripe Restricted API Key', severity: 'critical', strict: true },
        { pattern: /pk_live_[0-9a-zA-Z]{24}/g, type: 'Stripe Publishable Key (Live)', severity: 'low', strict: true },
        { pattern: /pk_test_[0-9a-zA-Z]{24}/g, type: 'Stripe Publishable Key (Test)', severity: 'low', strict: true },
        
        // ==========================================
        // SLACK
        // ==========================================
        { pattern: /xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}/g, type: 'Slack OAuth v2 Bot Access Token', severity: 'critical', strict: true },
        { pattern: /xoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}/g, type: 'Slack OAuth v2 User Access Token', severity: 'critical', strict: true },
        { pattern: /xoxe\.xoxp-1-[0-9a-zA-Z]{166}/g, type: 'Slack OAuth v2 Configuration Token', severity: 'critical', strict: true },
        { pattern: /xoxe-1-[0-9a-zA-Z]{147}/g, type: 'Slack OAuth v2 Refresh Token', severity: 'critical', strict: true },
        { pattern: /T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}/g, type: 'Slack Webhook', severity: 'high', strict: true },
        { pattern: /xox[baprs]-[0-9a-zA-Z\-]{10,48}/g, type: 'Slack Token (Legacy)', severity: 'critical', strict: true },
        
        // ==========================================
        // TWITTER
        // ==========================================
        { pattern: /[1-9][0-9]+-[0-9a-zA-Z]{40}/g, type: 'Twitter Access Token', severity: 'critical', strict: true },
        { pattern: /["']?(?:twitter[_-]?(?:api[_-]?key|api[_-]?secret|bearer[_-]?token|access[_-]?token))["']?\s*[:=]\s*["']([a-zA-Z0-9_-]{20,})["']/gi, type: 'Twitter Credential', severity: 'critical', strict: false },
        
        // ==========================================
        // FACEBOOK
        // ==========================================
        { pattern: /EAACEdEose0cBA[0-9A-Za-z]+/g, type: 'Facebook Access Token', severity: 'critical', strict: true },
        
        // ==========================================
        // INSTAGRAM
        // ==========================================
        { pattern: /[0-9a-fA-F]{7}\.[0-9a-fA-F]{32}/g, type: 'Instagram OAuth 2.0 Token', severity: 'critical', strict: true },
        
        // ==========================================
        // SQUARE
        // ==========================================
        { pattern: /sqOatp-[0-9A-Za-z\-_]{22}/g, type: 'Square Access Token', severity: 'critical', strict: true },
        { pattern: /sq0csp-[0-9A-Za-z\-_]{43}/g, type: 'Square OAuth Secret', severity: 'critical', strict: true },
        
        // ==========================================
        // PAYPAL / BRAINTREE
        // ==========================================
        { pattern: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g, type: 'PayPal/Braintree Access Token', severity: 'critical', strict: true },
        
        // ==========================================
        // TWILIO
        // ==========================================
        { pattern: /SK[0-9a-fA-F]{32}/g, type: 'Twilio API Key', severity: 'critical', strict: true },
        { pattern: /55[0-9a-fA-F]{32}/g, type: 'Twilio Access Token', severity: 'critical', strict: true },
        
        // ==========================================
        // MAILGUN
        // ==========================================
        { pattern: /key-[0-9a-zA-Z]{32}/g, type: 'Mailgun API Key', severity: 'critical', strict: true },
        
        // ==========================================
        // MAILCHIMP
        // ==========================================
        { pattern: /[0-9a-f]{32}-us[0-9]{1,2}/g, type: 'MailChimp Access Token', severity: 'critical', strict: true },
        
        // ==========================================
        // HEROKU
        // ==========================================
        { pattern: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g, type: 'Heroku API Key', severity: 'high', strict: false },
        
        // ==========================================
        // PICATIC
        // ==========================================
        { pattern: /sk_live_[0-9a-z]{32}/g, type: 'Picatic API Key', severity: 'critical', strict: true },
        
        // ==========================================
        // FOURSQUARE
        // ==========================================
        { pattern: /R_[0-9a-f]{32}/g, type: 'Foursquare Secret Key', severity: 'critical', strict: true },
        
        // ==========================================
        // AMAZON MWS
        // ==========================================
        { pattern: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, type: 'Amazon MWS Auth Token', severity: 'critical', strict: true },
        
        // ==========================================
        // WAKATIME
        // ==========================================
        { pattern: /waka_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, type: 'WakaTime API Key', severity: 'critical', strict: true },
        
        // ==========================================
        // SENDGRID
        // ==========================================
        { pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g, type: 'SendGrid API Key', severity: 'critical', strict: true },
        
        // ==========================================
        // OTHER SERVICES
        // ==========================================
        // GitLab
        { pattern: /glpat-[a-zA-Z0-9_-]{20}/g, type: 'GitLab Personal Access Token', severity: 'critical', strict: true },
        
        // Anthropic Claude
        { pattern: /sk-ant-[a-zA-Z0-9_-]{20,}/g, type: 'Anthropic API Key', severity: 'critical', strict: true },
        
        // HuggingFace
        { pattern: /hf_[a-zA-Z0-9]{34}/g, type: 'HuggingFace API Token', severity: 'critical', strict: true },
        
        // Replicate
        { pattern: /r8_[a-zA-Z0-9]{37}/g, type: 'Replicate API Token', severity: 'critical', strict: true },
        
        // Firebase
        { pattern: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g, type: 'Firebase Cloud Messaging Token', severity: 'high', strict: true },
        
        // Dropbox
        { pattern: /sl\.[A-Za-z0-9_-]{20,}/g, type: 'Dropbox Access Token', severity: 'critical', strict: true },
        
        // Notion
        { pattern: /secret_[a-zA-Z0-9]{43}/g, type: 'Notion Integration Token', severity: 'critical', strict: true },
        
        // DigitalOcean
        { pattern: /dop_v1_[a-f0-9]{64}/g, type: 'DigitalOcean Personal Access Token', severity: 'critical', strict: true },
        
        // Cloudflare
        { pattern: /cf-[a-z0-9]{32}/g, type: 'Cloudflare API Token', severity: 'critical', strict: true },
        
        // Terraform
        { pattern: /tfr_[A-Za-z0-9]{32}/g, type: 'Terraform Token', severity: 'critical', strict: true },
        
        // Azure
        { pattern: /DefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=[A-Za-z0-9+/=]+/g, type: 'Azure Storage Connection String', severity: 'critical', strict: true },
        
        // ==========================================
        // AUTHENTICATION & TOKENS
        // ==========================================
        // JWT Token
        { pattern: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, type: 'JWT Token', severity: 'medium', strict: false },
        
        // Basic Auth in URLs
        { pattern: /https?:\/\/[A-Za-z0-9_\-]+:[A-Za-z0-9_\-]+@[^\s"']+/g, type: 'Basic Auth URL', severity: 'critical', strict: true },
        
        // ==========================================
        // CRYPTOGRAPHIC KEYS
        // ==========================================
        { pattern: /-----BEGIN RSA PRIVATE KEY-----/g, type: 'RSA Private Key', severity: 'critical', strict: true },
        { pattern: /-----BEGIN PRIVATE KEY-----/g, type: 'Private Key (Generic)', severity: 'critical', strict: true },
        { pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g, type: 'OpenSSH Private Key', severity: 'critical', strict: true },
        { pattern: /-----BEGIN DSA PRIVATE KEY-----/g, type: 'DSA Private Key', severity: 'critical', strict: true },
        { pattern: /-----BEGIN EC PRIVATE KEY-----/g, type: 'EC Private Key', severity: 'critical', strict: true },
        { pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g, type: 'PGP Private Key', severity: 'critical', strict: true },
        
        // ==========================================
        // GENERIC API KEY KEYWORDS (Variable Names with JSON support)
        // ==========================================
        { pattern: /["']?access_key["']?\s*[:=]\s*["']([a-zA-Z0-9_\-/+=]{16,})["']/gi, type: 'Access Key', severity: 'high', strict: false },
        { pattern: /["']?secret_key["']?\s*[:=]\s*["']([a-zA-Z0-9_\-/+=]{16,})["']/gi, type: 'Secret Key', severity: 'critical', strict: false },
        { pattern: /["']?access_token["']?\s*[:=]\s*["']([a-zA-Z0-9_\-/+=]{20,})["']/gi, type: 'Access Token', severity: 'high', strict: false },
        { pattern: /["']?(?:api_key|apikey)["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']/gi, type: 'API Key', severity: 'high', strict: false },
        { pattern: /["']?(?:api_secret|apiSecret)["']?\s*[:=]\s*["']([a-zA-Z0-9_\-/+=]{20,})["']/gi, type: 'API Secret', severity: 'critical', strict: false },
        { pattern: /["']?app_secret["']?\s*[:=]\s*["']([a-zA-Z0-9_\-/+=]{20,})["']/gi, type: 'App Secret', severity: 'critical', strict: false },
        { pattern: /["']?client_secret["']?\s*[:=]\s*["']([a-zA-Z0-9_\-/+=]{16,})["']/gi, type: 'Client Secret', severity: 'critical', strict: false },
        { pattern: /["']?private_key["']?\s*[:=]\s*["']([a-zA-Z0-9_\-/+=]{20,})["']/gi, type: 'Private Key', severity: 'critical', strict: false },
        { pattern: /["']?auth_token["']?\s*[:=]\s*["']([a-zA-Z0-9_\-/+=]{20,})["']/gi, type: 'Auth Token', severity: 'high', strict: false },
        { pattern: /["']?bearer_token["']?\s*[:=]\s*["']([a-zA-Z0-9_\-/+=]{20,})["']/gi, type: 'Bearer Token', severity: 'high', strict: false },
        { pattern: /["']?encryption_key["']?\s*[:=]\s*["']([a-zA-Z0-9_\-/+=]{16,})["']/gi, type: 'Encryption Key', severity: 'critical', strict: false },
        
        // signing_key - Signing key for tokens/requests
        { pattern: /["']?signing_key["']?\s*[:=]\s*["']([a-zA-Z0-9_\-/+=]{16,})["']/gi, type: 'Signing Key', severity: 'critical', strict: false },
    ],

    // Credential patterns - more specific
    // Patterns support both JSON ("key": "value") and config (key = "value") formats
    credentialPatterns: [
        // Password variations
        { pattern: /["']?(?:password|passwd|pwd)["']?\s*[:=]\s*["']([^"']{6,})["']/gi, type: 'Password', severity: 'critical', strict: false },
        { pattern: /["']?(?:db[_-]?password|database[_-]?password)["']?\s*[:=]\s*["']([^"']{6,})["']/gi, type: 'Database Password', severity: 'critical', strict: false },
        { pattern: /["']?(?:admin[_-]?password|root[_-]?password)["']?\s*[:=]\s*["']([^"']{6,})["']/gi, type: 'Admin Password', severity: 'critical', strict: false },
        { pattern: /["']?(?:user[_-]?password|userpassword)["']?\s*[:=]\s*["']([^"']{6,})["']/gi, type: 'User Password', severity: 'critical', strict: false },
        { pattern: /["']?(?:mysql[_-]?password|postgres[_-]?password|redis[_-]?password|mongo[_-]?password)["']?\s*[:=]\s*["']([^"']{6,})["']/gi, type: 'Database Password', severity: 'critical', strict: false },
        
        // Username/login
        { pattern: /["']?(?:username|user[_-]?name|login|user[_-]?id)["']?\s*[:=]\s*["']([^"']{3,})["']/gi, type: 'Username', severity: 'low', strict: false },
        
        // Connection strings
        { pattern: /["']?(?:connection[_-]?string|conn[_-]?str|database[_-]?url|db[_-]?url)["']?\s*[:=]\s*["']([^"']+)["']/gi, type: 'Connection String', severity: 'critical', strict: false },
        
        // Additional credential patterns
        { pattern: /["']?(?:secret|secret[_-]?value)["']?\s*[:=]\s*["']([^"']{8,})["']/gi, type: 'Secret Value', severity: 'high', strict: false },
        // Note: "credentials" removed due to false positives (e.g., fetch credentials: "same-origin")
        { pattern: /["']?(?:auth|authorization)["']?\s*[:=]\s*["']([^"']{10,})["']/gi, type: 'Authorization Value', severity: 'high', strict: false },
        
        // SSH/Database connection
        { pattern: /["']?(?:ssh[_-]?key|ssh[_-]?private[_-]?key)["']?\s*[:=]\s*["']([^"']+)["']/gi, type: 'SSH Key', severity: 'critical', strict: false },
        { pattern: /["']?(?:db[_-]?host|database[_-]?host|mysql[_-]?host|postgres[_-]?host)["']?\s*[:=]\s*["']([^"']+)["']/gi, type: 'Database Host', severity: 'medium', strict: false },
    ],

    // Email patterns - stricter to avoid false positives like image@2x.png
    emailPatterns: [
        // Must have valid TLD and not be a retina image notation (@2x, @3x)
        { pattern: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z][a-zA-Z0-9.-]*\.[a-zA-Z]{2,6}\b/g, type: 'Email Address', severity: 'info', strict: false },
    ],


    // API endpoint patterns - only hardcoded URLs, not variables
    // Patterns support both JSON ("key": "value") and config (key = "value") formats where applicable
    apiEndpointPatterns: [
        // fetch API - only with hardcoded string URLs (not template variables)
        { pattern: /fetch\s*\(\s*["'](\/[^"']+)["']/g, type: 'fetch() Endpoint', extract: 1 },
        { pattern: /fetch\s*\(\s*["'](https?:\/\/[^"']+)["']/g, type: 'fetch() URL', extract: 1 },
        
        // XMLHttpRequest - hardcoded URLs only
        { pattern: /\.open\s*\(\s*["'](?:GET|POST|PUT|DELETE|PATCH)["']\s*,\s*["'](\/[^"']+)["']/gi, type: 'XHR Endpoint', extract: 1 },
        { pattern: /\.open\s*\(\s*["'](?:GET|POST|PUT|DELETE|PATCH)["']\s*,\s*["'](https?:\/\/[^"']+)["']/gi, type: 'XHR URL', extract: 1 },
        
        // axios - hardcoded URLs only
        { pattern: /axios\.(?:get|post|put|delete|patch)\s*\(\s*["'](\/[^"']+)["']/gi, type: 'axios Endpoint', extract: 1 },
        { pattern: /axios\.(?:get|post|put|delete|patch)\s*\(\s*["'](https?:\/\/[^"']+)["']/gi, type: 'axios URL', extract: 1 },
        
        // Hardcoded API base URLs (these are interesting for discovery) - JSON support added
        { pattern: /["']?baseURL["']?\s*[:=]\s*["'](https?:\/\/[^"']+)["']/gi, type: 'Base URL', extract: 1 },
        { pattern: /["']?(?:api[_-]?(?:url|endpoint|base)|backend[_-]?url|server[_-]?url)["']?\s*[:=]\s*["'](https?:\/\/[^"']+)["']/gi, type: 'API URL Config', extract: 1 },
        
        // Additional URL patterns in JSON responses
        { pattern: /["']?(?:webhook[_-]?url|callback[_-]?url|redirect[_-]?url|return[_-]?url)["']?\s*[:=]\s*["'](https?:\/\/[^"']+)["']/gi, type: 'Webhook/Callback URL', extract: 1 },
        { pattern: /["']?(?:service[_-]?url|endpoint[_-]?url|host[_-]?url)["']?\s*[:=]\s*["'](https?:\/\/[^"']+)["']/gi, type: 'Service URL', extract: 1 },
    ],

    // Parameter patterns - Only sensitive URL query parameters
    parameterPatterns: [
        // Sensitive parameters in URLs only (must look like an actual URL)
        { pattern: /https?:\/\/[^"'\s]*[?&](api[_-]?key|token|auth[_-]?token|secret|password|pwd|access[_-]?token|session[_-]?id|client[_-]?secret)=([^&\s"']+)/gi, type: 'Sensitive URL Parameter', severity: 'high' },
    ],

    // Path and directory patterns - very conservative, security-relevant only
    pathPatterns: [
        // Sensitive config/env files with path
        { pattern: /["']((?:\/[^"']+)?\/\.env(?:\.[^"']+)?)["']/gi, type: 'Environment File', severity: 'critical', extract: 1 },
        { pattern: /["']((?:\/[^"']+)?\/(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)(?:\.pub)?)["']/gi, type: 'SSH Key File', severity: 'critical', extract: 1 },
        
        // Source control exposure
        { pattern: /["']((?:https?:\/\/[^"']+)?\/\.git(?:\/[^"']*)?)["']/gi, type: 'Git Exposure', severity: 'critical', extract: 1 },
        
        // Backup files with actual path-like structure
        { pattern: /["'](\/[^"']+\.(?:bak|backup|old|sql|dump))["']/gi, type: 'Backup File', severity: 'high', extract: 1 },
        
        // Well-known sensitive files
        { pattern: /["'](\/[^"']*(?:wp-config|database|db\.config|secrets|credentials|\.htpasswd|\.htaccess|web\.config|config\.php|settings\.php)(?:\.[^"']*)?)["']/gi, type: 'Sensitive Config', severity: 'high', extract: 1 },
    ],

    // False positive filters
    falsePositives: [
        'example.com', 'example.org', 'localhost', '127.0.0.1', '0.0.0.0',
        'test', 'demo', 'sample', 'placeholder', 'your_api_key', 'your_secret',
        'api_key_here', 'secret_here', 'xxx', 'yyy', 'zzz',
        'password: false', 'password: true', 'password: null', 'password: undefined',
        'api_key: null', 'api_key: undefined', 'api_key: false',
        'insert_', '_here', 'your-', '-here', 'replace_', 'change_this',
        'data:image', 'data:text', 'data:application'
    ],

    // Common false positive email patterns
    falsePositiveEmails: [
        '@example.com', '@example.org', '@test.com', '@localhost',
        '@domain.com', '@email.com', '@yourcompany.com', '@company.com',
        // Retina image notations
        '@2x.', '@3x.', '@4x.', '@1x.', '@1.5x.',
        // Asset hashes
        '@2x', '@3x'
    ],

    /**
     * Check if match is a false positive
     */
    isFalsePositive(match, type) {
        const matchLower = match.toLowerCase();
        
        // Check common false positives
        for (const fp of this.falsePositives) {
            if (matchLower.includes(fp)) {
                return true;
            }
        }
        
        // JWT specific checks
        if (type === 'JWT Token') {
            const parts = match.split('.');
            if (parts.length < 3) return true;
            if (match.length < 50) return true;
        }
        
        // Email specific checks
        if (type === 'Email Address') {
            // Check against known false positive patterns
            for (const fpEmail of this.falsePositiveEmails) {
                if (matchLower.includes(fpEmail.toLowerCase())) {
                    return true;
                }
            }
            // Filter out retina image patterns like image@2x.png, icon@3x.webp
            if (/@\d+(\.\d+)?x\./i.test(match)) {
                return true;
            }
            // Filter if it looks like a file with @ in the name
            if (/@[^.]+\.(png|jpg|jpeg|gif|svg|webp|ico|bmp|pdf|zip|tar|gz)$/i.test(match)) {
                return true;
            }
            // Must have a valid-looking domain (at least one dot after @)
            const atIndex = match.indexOf('@');
            const afterAt = match.substring(atIndex + 1);
            if (!afterAt.includes('.') || afterAt.startsWith('.') || afterAt.endsWith('.')) {
                return true;
            }
        }
        
        // Password specific checks - filter boolean/null values
        if (type.includes('Password')) {
            if (/["'](?:true|false|null|undefined|none|\*+|\.{3,})["']/i.test(match)) {
                return true;
            }
        }

        // Path specific - filter common library paths and files
        if (type.includes('Path') || type.includes('File')) {
            if (/node_modules|bower_components|vendor|\.min\.|cdn\.|polyfill|webpack|bundle/.test(matchLower)) {
                return true;
            }
            // Filter common non-sensitive file extensions being detected
            if (/\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)$/i.test(match)) {
                return true;
            }
        }
        
        return false;
    },

    /**
     * Get context around a match
     */
    getContext(content, matchIndex, matchLength, contextChars = 100) {
        const start = Math.max(0, matchIndex - contextChars);
        const end = Math.min(content.length, matchIndex + matchLength + contextChars);
        
        let context = content.substring(start, end);
        
        // Add ellipsis if truncated
        if (start > 0) context = '...' + context;
        if (end < content.length) context = context + '...';
        
        return context;
    },

    /**
     * Find line number for a match
     */
    getLineNumber(content, matchIndex) {
        return content.substring(0, matchIndex).split('\n').length;
    },

    /**
     * Scan content with a pattern array
     */
    scanWithPatterns(content, patterns, category) {
        const findings = [];
        
        for (const patternInfo of patterns) {
            try {
                // Reset lastIndex for global patterns
                patternInfo.pattern.lastIndex = 0;
                
                let match;
                while ((match = patternInfo.pattern.exec(content)) !== null) {
                    const matchText = match[0];
                    
                    // Check for false positives (skip strict patterns)
                    if (!patternInfo.strict && this.isFalsePositive(matchText, patternInfo.type)) {
                        continue;
                    }
                    
                    const lineNum = this.getLineNumber(content, match.index);
                    const context = this.getContext(content, match.index, matchText.length);
                    
                    // Extract specific value if pattern has extract group
                    let extractedValue = matchText;
                    if (patternInfo.extract && match[patternInfo.extract]) {
                        extractedValue = match[patternInfo.extract];
                    }
                    
                    findings.push({
                        category: category,
                        type: patternInfo.type,
                        match: matchText.length > 200 ? matchText.substring(0, 200) + '...' : matchText,
                        extractedValue: extractedValue.length > 200 ? extractedValue.substring(0, 200) + '...' : extractedValue,
                        severity: patternInfo.severity || 'info',
                        line: lineNum,
                        context: context
                    });
                    
                    // Prevent infinite loops
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

    /**
     * Remove duplicate findings
     */
    removeDuplicates(findings) {
        const seen = new Set();
        return findings.filter(finding => {
            const key = `${finding.type}:${finding.line}:${finding.match}`;
            if (seen.has(key)) {
                return false;
            }
            seen.add(key);
            return true;
        });
    },

    /**
     * Main scan function
     * @param {string} content - Response body content to scan
     * @param {string} url - URL of the request (for context)
     * @returns {object} - Scan results categorized by type
     */
    scan(content, url = '') {
        if (!content || typeof content !== 'string') {
            return null;
        }

        // Skip if content is too large (> 5MB)
        if (content.length > 5 * 1024 * 1024) {
            console.warn('SecurityScanner: Content too large, skipping scan');
            return null;
        }

        const results = {
            url: url,
            timestamp: new Date().toISOString(),
            apiKeys: [],
            credentials: [],
            emails: [],
            apiEndpoints: [],
            parameters: [],
            paths: [],
            totalFindings: 0
        };

        // Scan for each category
        results.apiKeys = this.removeDuplicates(
            this.scanWithPatterns(content, this.apiKeyPatterns, 'API Keys')
        );
        
        results.credentials = this.removeDuplicates(
            this.scanWithPatterns(content, this.credentialPatterns, 'Credentials')
        );
        
        results.emails = this.removeDuplicates(
            this.scanWithPatterns(content, this.emailPatterns, 'Emails')
        );
        
        results.apiEndpoints = this.removeDuplicates(
            this.scanWithPatterns(content, this.apiEndpointPatterns, 'API Endpoints')
        );
        
        results.parameters = this.removeDuplicates(
            this.scanWithPatterns(content, this.parameterPatterns, 'Parameters')
        );
        
        results.paths = this.removeDuplicates(
            this.scanWithPatterns(content, this.pathPatterns, 'Paths')
        );

        // Calculate total (excluding low-severity items for the count)
        results.totalFindings = 
            results.apiKeys.length +
            results.credentials.length;

        // Return null if no significant findings
        const hasSignificantFindings = 
            results.apiKeys.length > 0 ||
            results.credentials.length > 0;

        if (!hasSignificantFindings && 
            results.emails.length === 0 && 
            results.apiEndpoints.length === 0) {
            return null;
        }

        return results;
    },

    /**
     * Check if content type is scannable
     * @param {string} contentType - Content-Type header value
     * @returns {boolean}
     */
    isScannable(contentType) {
        if (!contentType) return false;
        
        const scannableTypes = [
            'text/html',
            'text/plain',
            'text/javascript',
            'text/css',
            'application/javascript',
            'application/x-javascript',
            'application/json',
            'application/xml',
            'text/xml',
            'application/xhtml+xml'
        ];
        
        const lowerContentType = contentType.toLowerCase();
        return scannableTypes.some(type => lowerContentType.includes(type));
    },

    /**
     * Get severity color
     * @param {string} severity
     * @returns {string} CSS color
     */
    getSeverityColor(severity) {
        const colors = {
            critical: '#dc3545',
            high: '#fd7e14',
            medium: '#ffc107',
            low: '#28a745',
            info: '#17a2b8'
        };
        return colors[severity] || colors.info;
    },

    /**
     * Get severity badge class
     * @param {string} severity
     * @returns {string} CSS class
     */
    getSeverityClass(severity) {
        return `severity-${severity}`;
    }
};

// Export for use in panel.js
if (typeof window !== 'undefined') {
    window.SecurityScanner = SecurityScanner;
}

