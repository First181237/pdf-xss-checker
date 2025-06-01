/**
 * JavaScript Injection Detector
 * Detects potential JavaScript injection in PDF content
 */

/**
 * JavaScript injection patterns
 */
const JS_INJECTION_PATTERNS = [
  {
    pattern: /app\.(\w+)\s*\(/gi,
    name: 'Acrobat API Call',
    description: 'Found calls to Acrobat JavaScript API',
    severity: 'high'
  },
  {
    pattern: /this\.(\w+)\s*\(/gi,
    name: 'PDF Object Method Call',
    description: 'Found calls to PDF object methods',
    severity: 'medium'
  },
  {
    pattern: /\bgetField\s*\(/gi,
    name: 'Form Field Access',
    description: 'Found attempts to access form fields',
    severity: 'medium'
  },
  {
    pattern: /\bapp\.alert\s*\(/gi,
    name: 'Alert Dialog',
    description: 'Found alert dialog calls',
    severity: 'low'
  },
  {
    pattern: /\bapp\.execMenuItem\s*\(/gi,
    name: 'Execute Menu Item',
    description: 'Found attempts to execute menu commands',
    severity: 'critical'
  },
  {
    pattern: /\bspawn\s*\(/gi,
    name: 'Process Spawn',
    description: 'Found attempts to spawn processes',
    severity: 'critical'
  },
  {
    pattern: /\bshell\s*\.\s*\w+/gi,
    name: 'Shell Command',
    description: 'Found potential shell command execution',
    severity: 'critical'
  }
];

/**
 * Detect JavaScript injection in PDF content
 * @param {string} content - Extracted PDF text content
 * @param {Object} options - Detection options
 * @returns {Array} List of detected vulnerabilities
 */
const detectJsInjection = (content, options = {}) => {
  const vulnerabilities = [];
  const thresholds = {
    low: ['low', 'medium', 'high', 'critical'],
    medium: ['medium', 'high', 'critical'],
    high: ['high', 'critical'],
    critical: ['critical']
  };
  
  const severityFilter = thresholds[options.threshold || 'medium'];

  // Check for JavaScript object notation
  const patternsToCheck = JS_INJECTION_PATTERNS.filter(pattern => 
    severityFilter.includes(pattern.severity)
  );

  // Check each pattern against the content
  patternsToCheck.forEach(patternDef => {
    const matches = [...content.matchAll(patternDef.pattern)];
    
    matches.forEach(match => {
      const matchedText = match[0];
      const startIndex = match.index;
      const endIndex = startIndex + matchedText.length;
      
      // Calculate line and column positions (approximate)
      const contentBeforeMatch = content.substring(0, startIndex);
      const lines = contentBeforeMatch.split('\n');
      const lineNumber = lines.length;
      const columnNumber = lines[lines.length - 1].length + 1;
      
      // Get context (text before and after the match)
      const contextStart = Math.max(0, startIndex - 20);
      const contextEnd = Math.min(content.length, endIndex + 20);
      const context = content.substring(contextStart, contextEnd);
      
      vulnerabilities.push({
        type: 'js-injection',
        name: patternDef.name,
        description: patternDef.description,
        severity: patternDef.severity,
        matchedText: matchedText,
        location: {
          startIndex,
          endIndex,
          line: lineNumber,
          column: columnNumber
        },
        context: context.trim()
      });
    });
  });

  return vulnerabilities;
};

module.exports = {
  detectJsInjection,
  JS_INJECTION_PATTERNS
};