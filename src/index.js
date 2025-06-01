/**
 * PDF XSS Scanner
 * Main library entry point
 */

const pdfScanner = require('./scanner/pdfScanner');
const { defaultOptions } = require('./config/options');

/**
 * Scan a buffer containing PDF data for XSS vulnerabilities
 * @param {Buffer} buffer - Buffer containing PDF data
 * @param {Object} options - Scanner options
 * @returns {Promise<boolean>} True if XSS vulnerabilities found, false otherwise
 */
async function scanBuffer(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) {
    throw new Error('Input must be a buffer');
  }

  const mergedOptions = { ...defaultOptions, ...options };
  
  try {
    // Analyze PDF content
    const scanResults = await pdfScanner.scanPdfContent(buffer, mergedOptions);
    
    // Return simple boolean indicating if XSS was found
    return scanResults.hasVulnerabilities;
  } catch (error) {
    throw new Error(`PDF XSS scanning failed: ${error.message}`);
  }
}

module.exports = {
  scanBuffer
};