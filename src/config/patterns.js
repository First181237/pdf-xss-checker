/**
 * XSS Patterns
 * Defines patterns for detecting XSS vulnerabilities
 */

/**
 * Array of XSS detection patterns
 * Each pattern includes:
 * - name: Pattern name
 * - regex: Regular expression to match
 * - flags: Regex flags
 * - severity: Severity level (high, medium, low)
 * - description: Description of the vulnerability
 * - minSensitivityLevel: Minimum sensitivity level to include this pattern
 */
const xssPatterns = [
  // Script tag patterns
  {
    name: 'script-tag',
    regex: '<script[^>]*>[\\s\\S]*?<\\/script>',
    severity: 'high',
    description: 'Script tag detected in content',
    minSensitivityLevel: 1
  },
  {
    name: 'script-tag-open',
    regex: '<script[^>]*>',
    severity: 'high',
    description: 'Open script tag detected in content',
    minSensitivityLevel: 1
  },
  
  // Event handlers
  {
    name: 'event-handler',
    regex: 'on(load|click|mouseover|mouseout|keydown|keypress|submit|focus|blur|change|error)\\s*=',
    severity: 'high',
    description: 'HTML event handler detected in content',
    minSensitivityLevel: 1
  },
  
  // JavaScript protocol
  {
    name: 'javascript-protocol',
    regex: 'javascript:',
    severity: 'high',
    description: 'JavaScript protocol detected in content',
    minSensitivityLevel: 1
  },
  
  // Data URI with HTML or JavaScript
  {
    name: 'data-uri-html',
    regex: 'data:text\\/html[^,]*,',
    severity: 'high',
    description: 'Data URI with HTML content detected',
    minSensitivityLevel: 1
  },
  {
    name: 'data-uri-javascript',
    regex: 'data:text\\/javascript[^,]*,',
    severity: 'high',
    description: 'Data URI with JavaScript content detected',
    minSensitivityLevel: 1
  },
  
  // Iframe injection
  {
    name: 'iframe-tag',
    regex: '<iframe[^>]*>',
    severity: 'high',
    description: 'Iframe tag detected in content',
    minSensitivityLevel: 1
  },
  
  // Common XSS functions
  {
    name: 'dangerous-js-function',
    regex: '(eval|setTimeout|setInterval)\\s*\\(',
    severity: 'high',
    description: 'Dangerous JavaScript function detected',
    minSensitivityLevel: 1
  },
  
  // DOM manipulation
  {
    name: 'dom-manipulation',
    regex: '(innerHTML|outerHTML|insertAdjacentHTML)\\s*=',
    severity: 'high',
    description: 'DOM manipulation detected',
    minSensitivityLevel: 1
  },
  
  // Document write
  {
    name: 'document-write',
    regex: 'document\\.(write|writeln)\\s*\\(',
    severity: 'high',
    description: 'Document write function detected',
    minSensitivityLevel: 1
  },
  
  // Meta refresh with JavaScript
  {
    name: 'meta-refresh-javascript',
    regex: '<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\']?[^"\']*url=[^"\']*javascript:',
    severity: 'high',
    description: 'Meta refresh with JavaScript detected',
    minSensitivityLevel: 2
  },
  
  // SVG with script
  {
    name: 'svg-script',
    regex: '<svg[^>]*>[\\s\\S]*<script[^>]*>[\\s\\S]*?<\\/script>[\\s\\S]*<\\/svg>',
    severity: 'high',
    description: 'SVG with embedded script detected',
    minSensitivityLevel: 2
  },
  
  // Expression binding (Angular/Vue)
  {
    name: 'expression-binding',
    regex: '{{.+}}|\\[\\(.+\\)\\]|\\[(innerHTML|outerHTML)\\]',
    severity: 'medium',
    description: 'Framework expression binding detected (Angular/Vue/etc)',
    minSensitivityLevel: 2
  },
  
  // Base64 encoded script or alert
  {
    name: 'base64-script',
    regex: 'base64[^,]*PHNjcmlwdD', // Partial match for <script in base64
    severity: 'medium',
    description: 'Potential base64 encoded script detected',
    minSensitivityLevel: 2
  },
  
  // CSS expression
  {
    name: 'css-expression',
    regex: 'expression\\s*\\([^)]*\\)',
    severity: 'medium',
    description: 'CSS expression detected',
    minSensitivityLevel: 3
  },
  
  // Obfuscated script tags
  {
    name: 'obfuscated-script',
    regex: '(?:\\\\x3C|\\\\u003C)\\s*(?:\\\\x73|\\\\u0073)\\s*(?:\\\\x63|\\\\u0063)\\s*(?:\\\\x72|\\\\u0072)\\s*(?:\\\\x69|\\\\u0069)\\s*(?:\\\\x70|\\\\u0070)\\s*(?:\\\\x74|\\\\u0074)',
    severity: 'high',
    description: 'Obfuscated script tag detected',
    minSensitivityLevel: 3
  },
  
  // Common XSS payloads
  {
    name: 'alert-function',
    regex: 'alert\\s*\\([^)]*\\)',
    severity: 'medium',
    description: 'Alert function detected',
    minSensitivityLevel: 2
  },
  {
    name: 'prompt-function',
    regex: 'prompt\\s*\\([^)]*\\)',
    severity: 'medium',
    description: 'Prompt function detected',
    minSensitivityLevel: 2
  },
  {
    name: 'confirm-function',
    regex: 'confirm\\s*\\([^)]*\\)',
    severity: 'medium',
    description: 'Confirm function detected',
    minSensitivityLevel: 2
  }
];

module.exports = {
  xssPatterns
};