/**
 * PDF Scanner
 * Core functionality for scanning PDF files for XSS vulnerabilities
 */

const pdfParse = require('pdf-parse');
const fs = require('fs');
const xssDetector = require('./xssDetector');
const { extractLinks, extractJavaScript } = require('./contentExtractor');

/**
 * Scan a PDF file for XSS vulnerabilities
 * @param {string} pdfPath - Path to the PDF file
 * @param {Object} options - Scanner options
 * @returns {Promise<Object>} Scan results
 */
async function scanPdfFile(pdfPath, options) {
  try {
    // Read the PDF file
    const dataBuffer = fs.readFileSync(pdfPath);
    return await scanPdfContent(dataBuffer, options);
  } catch (error) {
    throw new Error(`Failed to scan PDF file: ${error.message}`);
  }
}

/**
 * Scan PDF content for XSS vulnerabilities
 * @param {Buffer|string} pdfContent - PDF content as buffer or string
 * @param {Object} options - Scanner options
 * @returns {Promise<Object>} Scan results
 */
async function scanPdfContent(pdfContent, options) {
  try {
    // Parse the PDF content
    const data = await pdfParse(pdfContent);
    
    // Extract text, links, and JavaScript from PDF
    const textContent = data.text;
    const links = extractLinks(data);
    const jsContent = extractJavaScript(data);
    
    // Scan for XSS in different components
    const textScanResults = xssDetector.scanText(textContent, options);
    const linkScanResults = xssDetector.scanLinks(links, options);
    const jsScanResults = xssDetector.scanJavaScript(jsContent, options);
    
    // Combine results
    const vulnerabilities = [
      ...textScanResults,
      ...linkScanResults,
      ...jsScanResults
    ];
    
    return {
      hasVulnerabilities: vulnerabilities.length > 0,
      vulnerabilityCount: vulnerabilities.length,
      vulnerabilities,
      metadata: {
        pageCount: data.numpages,
        pdfInfo: data.info,
        scannedTimestamp: new Date().toISOString()
      }
    };
  } catch (error) {
    throw new Error(`Failed to analyze PDF content: ${error.message}`);
  }
}

module.exports = {
  scanPdfFile,
  scanPdfContent
};