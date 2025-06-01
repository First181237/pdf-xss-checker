/**
 * Scanner Options
 * Default configuration options for the scanner
 */

/**
 * Default scanner options
 */
const defaultOptions = {
  // Scanner sensitivity: 1 (basic) to 5 (paranoid)
  sensitivityLevel: 3,
  
  // Maximum content length to scan (to avoid excessive processing)
  maxContentLength: 10 * 1024 * 1024, // 10MB
  
  // Whether to scan for obfuscated patterns (may increase false positives)
  scanObfuscated: true,
  
  // Extract and scan embedded files
  scanEmbeddedFiles: true,
  
  // Maximum scan time in milliseconds before timeout
  scanTimeout: 60000, // 1 minute
  
  // Reporting options
  reporting: {
    // Include full content matches in report
    includeContentMatches: true,
    
    // Maximum content match length to include in report
    maxMatchLength: 200,
    
    // Sort vulnerabilities by severity
    sortBySeverity: true
  }
};

module.exports = {
  defaultOptions
};