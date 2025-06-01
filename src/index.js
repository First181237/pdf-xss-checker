/**
 * PDF XSS Checker
 * Main entry point for the package
 */
const fs = require('fs');
const path = require('path');
const { scanPdfBuffer } = require('./scanner');
const { generateReport } = require('./reporter');

/**
 * Scan a PDF file for XSS vulnerabilities
 * @param {string} filePath - Path to the PDF file
 * @param {Object} options - Scanning options
 * @returns {Promise<Object>} Scan results
 */
const scanPdf = async (filePath, options = {}) => {
  try {
    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const fileExtension = path.extname(filePath).toLowerCase();
    if (fileExtension !== '.pdf') {
      throw new Error('File must be a PDF');
    }
    
    const pdfBuffer = fs.readFileSync(filePath);
    const scanResults = await scanPdfBuffer(pdfBuffer, options);
    return generateReport(scanResults, { fileName: path.basename(filePath), ...options });
  } catch (error) {
    return {
      success: false,
      error: error.message,
      vulnerabilities: [],
      safeToUse: false
    };
  }
};

/**
 * Scan a PDF buffer for XSS vulnerabilities
 * @param {Buffer} buffer - PDF file buffer
 * @param {Object} options - Scanning options
 * @returns {Promise<Object>} Scan results
 */
const scanBuffer = async (buffer, options = {}) => {
  try {
    const scanResults = await scanPdfBuffer(buffer, options);
    return generateReport(scanResults, { fileName: 'buffer', ...options });
  } catch (error) {
    return {
      success: false,
      error: error.message,
      vulnerabilities: [],
      safeToUse: false
    };
  }
};

/**
 * Main API for the package
 */
module.exports = {
  scanPdf,
  scanBuffer,
  // Re-export utility functions
  utils: require('./utils')
};