/**
 * PDF XSS Scanner Report Generator
 * Generates formatted reports from scan results
 */

/**
 * Generate a detailed report from scan results
 * @param {Object} results - Scan results
 * @param {Object} options - Report options
 * @returns {Object} Formatted report
 */
const generateReport = (results, options = {}) => {
  if (!results.success) {
    return {
      success: false,
      error: results.error,
      fileName: options.fileName || 'unknown',
      timestamp: new Date().toISOString(),
      safeToUse: false
    };
  }

  // Group vulnerabilities by type and severity
  const groupedVulnerabilities = groupVulnerabilities(results.vulnerabilities);
  
  // Generate summary statistics
  const summary = {
    fileName: options.fileName || 'unknown',
    timestamp: new Date().toISOString(),
    pageCount: results.metadata.pageCount,
    vulnerabilityCount: results.vulnerabilities.length,
    riskLevel: results.riskLevel,
    safeToUse: results.safeToUse,
    severityCounts: countSeverities(results.vulnerabilities),
    typeCounts: countTypes(results.vulnerabilities)
  };

  // Create the full report
  const report = {
    success: true,
    summary,
    metadata: results.metadata,
    vulnerabilities: options.includeFullDetails 
      ? results.vulnerabilities 
      : results.vulnerabilities.map(simplifyVulnerability),
    groupedVulnerabilities: options.includeGrouped ? groupedVulnerabilities : undefined,
    rawContent: results.rawContent
  };

  return report;
};

/**
 * Group vulnerabilities by type and severity
 * @param {Array} vulnerabilities - List of vulnerabilities
 * @returns {Object} Grouped vulnerabilities
 */
const groupVulnerabilities = (vulnerabilities) => {
  // Group by type
  const byType = vulnerabilities.reduce((groups, vuln) => {
    const type = vuln.type;
    if (!groups[type]) {
      groups[type] = [];
    }
    groups[type].push(vuln);
    return groups;
  }, {});

  // Group by severity
  const bySeverity = vulnerabilities.reduce((groups, vuln) => {
    const severity = vuln.severity;
    if (!groups[severity]) {
      groups[severity] = [];
    }
    groups[severity].push(vuln);
    return groups;
  }, {});

  return { byType, bySeverity };
};

/**
 * Count vulnerabilities by severity
 * @param {Array} vulnerabilities - List of vulnerabilities
 * @returns {Object} Counts by severity
 */
const countSeverities = (vulnerabilities) => {
  return vulnerabilities.reduce((counts, vuln) => {
    const severity = vuln.severity;
    counts[severity] = (counts[severity] || 0) + 1;
    return counts;
  }, {});
};

/**
 * Count vulnerabilities by type
 * @param {Array} vulnerabilities - List of vulnerabilities
 * @returns {Object} Counts by type
 */
const countTypes = (vulnerabilities) => {
  return vulnerabilities.reduce((counts, vuln) => {
    const type = vuln.type;
    counts[type] = (counts[type] || 0) + 1;
    return counts;
  }, {});
};

/**
 * Simplify vulnerability object for summary reports
 * @param {Object} vulnerability - Full vulnerability object
 * @returns {Object} Simplified vulnerability
 */
const simplifyVulnerability = (vulnerability) => {
  return {
    type: vulnerability.type,
    name: vulnerability.name,
    description: vulnerability.description,
    severity: vulnerability.severity,
    location: {
      line: vulnerability.location.line,
      column: vulnerability.location.column
    }
  };
};

module.exports = {
  generateReport
};