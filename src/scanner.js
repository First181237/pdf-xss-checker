/**
 * PDF XSS Scanner
 * Scans PDF content for XSS vulnerabilities
 */
const pdfParse = require('pdf-parse');
const { detectXssPatterns } = require('./detectors/xssPatterns');
const { detectJsInjection } = require('./detectors/jsInjection');
const { detectFormInjection } = require('./detectors/formInjection');

/**
 * Scan a PDF buffer for XSS vulnerabilities
 * @param {Buffer} pdfBuffer - PDF file buffer
 * @param {Object} options - Scanning options
 * @returns {Promise<Object>} Scan results
 */
const scanPdfBuffer = async (pdfBuffer, options = {}) => {
  try {
    // Set default options
    const scanOptions = {
      maxContentLength: options.maxContentLength || 10000000, // 10MB
      detectors: options.detectors || ['xss', 'js', 'form'],
      threshold: options.threshold || 'medium',
      ...options
    };

    // Parse the PDF
    const data = await pdfParse(pdfBuffer, {
      max: scanOptions.maxContentLength
    });

    // Initialize scan results
    const scanResults = {
      success: true,
      metadata: {
        info: data.info,
        pageCount: data.numpages,
        contentLength: data.text.length
      },
      vulnerabilities: [],
      rawContent: scanOptions.includeRawContent ? data.text : undefined
    };

    // Run enabled detectors
    if (scanOptions.detectors.includes('xss')) {
      const xssVulnerabilities = detectXssPatterns(data.text, scanOptions);
      scanResults.vulnerabilities.push(...xssVulnerabilities);
    }

    if (scanOptions.detectors.includes('js')) {
      const jsVulnerabilities = detectJsInjection(data.text, scanOptions);
      scanResults.vulnerabilities.push(...jsVulnerabilities);
    }

    if (scanOptions.detectors.includes('form')) {
      const formVulnerabilities = detectFormInjection(data.text, scanOptions);
      scanResults.vulnerabilities.push(...formVulnerabilities);
    }

    // Calculate overall safety
    scanResults.safeToUse = scanResults.vulnerabilities.length === 0;
    scanResults.riskLevel = calculateRiskLevel(scanResults.vulnerabilities);

    return scanResults;
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
 * Calculate the risk level based on vulnerabilities
 * @param {Array} vulnerabilities - List of vulnerabilities
 * @returns {string} Risk level (low, medium, high, critical)
 */
const calculateRiskLevel = (vulnerabilities) => {
  if (vulnerabilities.length === 0) return 'none';
  
  const severityCounts = vulnerabilities.reduce((counts, vuln) => {
    counts[vuln.severity] = (counts[vuln.severity] || 0) + 1;
    return counts;
  }, {});
  
  if (severityCounts.critical > 0) return 'critical';
  if (severityCounts.high > 0) return 'high';
  if (severityCounts.medium > 0) return 'medium';
  return 'low';
};

module.exports = {
  scanPdfBuffer
};