/**
 * PDF XSS Scanner Utilities
 * Helper functions for the PDF XSS scanner
 */

/**
 * Get severity level as a numeric value
 * @param {string} severity - Severity level name
 * @returns {number} Numeric severity level
 */
const getSeverityLevel = (severity) => {
  const levels = {
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4
  };
  return levels[severity] || 0;
};

/**
 * Format size in bytes to human-readable string
 * @param {number} bytes - Size in bytes
 * @returns {string} Formatted size string
 */
const formatSize = (bytes) => {
  if (bytes < 1024) return bytes + ' bytes';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
};

/**
 * Truncate text to a specified length
 * @param {string} text - Input text
 * @param {number} maxLength - Maximum length
 * @returns {string} Truncated text
 */
const truncateText = (text, maxLength = 100) => {
  if (!text) return '';
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength - 3) + '...';
};

/**
 * Get all patterns from all detectors
 * @returns {Array} Combined patterns from all detectors
 */
const getAllPatterns = () => {
  const { XSS_PATTERNS } = require('./detectors/xssPatterns');
  const { JS_INJECTION_PATTERNS } = require('./detectors/jsInjection');
  const { FORM_INJECTION_PATTERNS } = require('./detectors/formInjection');
  
  return [
    ...XSS_PATTERNS,
    ...JS_INJECTION_PATTERNS,
    ...FORM_INJECTION_PATTERNS
  ];
};

/**
 * Check if a pattern matches in the content
 * @param {RegExp} pattern - Regular expression pattern
 * @param {string} content - Content to check
 * @returns {boolean} Whether pattern matches
 */
const hasPattern = (pattern, content) => {
  return pattern.test(content);
};

module.exports = {
  getSeverityLevel,
  formatSize,
  truncateText,
  getAllPatterns,
  hasPattern
};