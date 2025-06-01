/**
 * XSS Detector
 * Implements detection patterns for XSS vulnerabilities
 */

const { parse } = require('node-html-parser');
const { xssPatterns } = require('../config/patterns');

/**
 * Scan text content for XSS patterns
 * @param {string} content - Text content to scan
 * @param {Object} options - Scanner options
 * @returns {Array} Detected vulnerabilities
 */
function scanText(content, options) {
  const vulnerabilities = [];
  const { sensitivityLevel } = options;
  
  // Apply patterns based on sensitivity level
  const patternsToApply = xssPatterns.filter(pattern => 
    pattern.minSensitivityLevel <= sensitivityLevel
  );

  for (const pattern of patternsToApply) {
    const matches = findPatternMatches(content, pattern);
    vulnerabilities.push(...matches);
  }

  return vulnerabilities;
}

/**
 * Scan extracted links for XSS vulnerabilities
 * @param {Array} links - Array of links from the PDF
 * @param {Object} options - Scanner options
 * @returns {Array} Detected vulnerabilities
 */
function scanLinks(links, options) {
  const vulnerabilities = [];
  
  for (const link of links) {
    try {
      // Look for JavaScript protocol
      if (link.url.toLowerCase().startsWith('javascript:')) {
        vulnerabilities.push({
          type: 'link',
          pattern: 'javascript-protocol',
          severity: 'high',
          location: link.location || 'unknown',
          content: link.url,
          description: 'JavaScript protocol in link can execute arbitrary code'
        });
      }
      
      // Look for data URI with HTML/JavaScript content
      if (link.url.toLowerCase().startsWith('data:text/html') || 
          link.url.toLowerCase().includes('base64')) {
        vulnerabilities.push({
          type: 'link',
          pattern: 'data-uri',
          severity: 'high',
          location: link.location || 'unknown',
          content: link.url,
          description: 'Data URI can contain executable code'
        });
      }
      
      // Check for URL parameters that might contain XSS
      const urlScanResults = scanText(link.url, options);
      for (const result of urlScanResults) {
        result.type = 'link-url';
        result.location = link.location || 'unknown';
      }
      
      vulnerabilities.push(...urlScanResults);
    } catch (error) {
      // Continue with other links if one fails
      console.error(`Error scanning link: ${error.message}`);
    }
  }
  
  return vulnerabilities;
}

/**
 * Scan JavaScript content for potential XSS vulnerabilities
 * @param {Array} jsContents - Array of JavaScript content from the PDF
 * @param {Object} options - Scanner options
 * @returns {Array} Detected vulnerabilities
 */
function scanJavaScript(jsContents, options) {
  const vulnerabilities = [];
  
  for (const js of jsContents) {
    try {
      // Look for dangerous JavaScript functions
      const dangerousFunctions = [
        'eval(', 'setTimeout(', 'setInterval(', 'document.write(',
        'innerHTML', 'outerHTML', 'insertAdjacentHTML('
      ];
      
      for (const func of dangerousFunctions) {
        if (js.content.includes(func)) {
          vulnerabilities.push({
            type: 'javascript',
            pattern: 'dangerous-function',
            severity: 'high',
            location: js.location || 'unknown',
            content: js.content.substring(
              Math.max(0, js.content.indexOf(func) - 20),
              Math.min(js.content.length, js.content.indexOf(func) + func.length + 20)
            ),
            description: `Potentially dangerous JavaScript function: ${func}`
          });
        }
      }
      
      // Also apply text-based XSS patterns to JavaScript
      const jsScanResults = scanText(js.content, options);
      for (const result of jsScanResults) {
        result.type = 'javascript-content';
        result.location = js.location || 'unknown';
      }
      
      vulnerabilities.push(...jsScanResults);
    } catch (error) {
      // Continue with other JS if one fails
      console.error(`Error scanning JavaScript: ${error.message}`);
    }
  }
  
  return vulnerabilities;
}

/**
 * Find matches for a specific XSS pattern in content
 * @param {string} content - Content to scan
 * @param {Object} pattern - Pattern to match
 * @returns {Array} Detected vulnerabilities
 */
function findPatternMatches(content, pattern) {
  const matches = [];
  let match;
  
  const regex = new RegExp(pattern.regex, pattern.flags || 'gi');
  
  while ((match = regex.exec(content)) !== null) {
    // Avoid infinite loops for zero-width matches
    if (match.index === regex.lastIndex) {
      regex.lastIndex++;
    }
    
    matches.push({
      type: 'content',
      pattern: pattern.name,
      severity: pattern.severity,
      location: `character ${match.index}`,
      content: match[0],
      description: pattern.description
    });
  }
  
  return matches;
}

module.exports = {
  scanText,
  scanLinks,
  scanJavaScript
};