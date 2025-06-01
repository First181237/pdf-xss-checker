/**
 * Report Generator
 * Generates structured reports from scan results
 */

const chalk = require('chalk');

/**
 * Generate a structured report from scan results
 * @param {Object} results - Scan results
 * @param {string} pdfSource - PDF source identifier (path or description)
 * @param {Object} options - Scanner options
 * @returns {Object} Structured report
 */
function generateReport(results, pdfSource, options) {
  const { vulnerabilities, metadata } = results;
  
  // Group vulnerabilities by severity
  const groupedByType = {};
  const groupedBySeverity = {
    high: [],
    medium: [],
    low: []
  };
  
  for (const vuln of vulnerabilities) {
    // Group by type
    if (!groupedByType[vuln.type]) {
      groupedByType[vuln.type] = [];
    }
    groupedByType[vuln.type].push(vuln);
    
    // Group by severity
    if (groupedBySeverity[vuln.severity]) {
      groupedBySeverity[vuln.severity].push(vuln);
    } else {
      groupedBySeverity.low.push(vuln);
    }
  }
  
  // Calculate risk score (simple algorithm)
  const riskScore = calculateRiskScore(groupedBySeverity);
  
  return {
    source: pdfSource,
    timestamp: new Date().toISOString(),
    summary: {
      hasVulnerabilities: vulnerabilities.length > 0,
      vulnerabilityCount: vulnerabilities.length,
      highSeverityCount: groupedBySeverity.high.length,
      mediumSeverityCount: groupedBySeverity.medium.length,
      lowSeverityCount: groupedBySeverity.low.length,
      riskScore: riskScore,
      riskLevel: getRiskLevel(riskScore)
    },
    metadata,
    vulnerabilities,
    groupedResults: {
      byType: groupedByType,
      bySeverity: groupedBySeverity
    },
    scanOptions: options
  };
}

/**
 * Generate a CLI-friendly report string
 * @param {Object} report - The structured report
 * @returns {string} Formatted report string for CLI
 */
function generateCliReport(report) {
  const { summary, source, vulnerabilities } = report;
  let output = '\n';
  
  // Header
  output += chalk.bold(`=== PDF XSS SCAN REPORT: ${source} ===\n\n`);
  
  // Summary
  output += chalk.bold('SUMMARY:\n');
  output += `Status: ${summary.hasVulnerabilities 
    ? chalk.red('⚠️ VULNERABILITIES DETECTED') 
    : chalk.green('✅ NO VULNERABILITIES DETECTED')}\n`;
  
  if (summary.hasVulnerabilities) {
    output += `Total Vulnerabilities: ${chalk.yellow(summary.vulnerabilityCount)}\n`;
    output += `Risk Level: ${getColoredRiskLevel(summary.riskLevel)}\n`;
    output += `Severity Breakdown:\n`;
    output += `  ${chalk.red('■')} High: ${summary.highSeverityCount}\n`;
    output += `  ${chalk.yellow('■')} Medium: ${summary.mediumSeverityCount}\n`;
    output += `  ${chalk.blue('■')} Low: ${summary.lowSeverityCount}\n`;
    output += '\n';
    
    // Vulnerabilities
    output += chalk.bold('VULNERABILITIES DETAIL:\n');
    
    vulnerabilities.forEach((vuln, index) => {
      const severityColor = getSeverityColor(vuln.severity);
      output += `${index + 1}. ${severityColor(`[${vuln.severity.toUpperCase()}]`)} ${vuln.pattern} (${vuln.type})\n`;
      output += `   Location: ${vuln.location}\n`;
      output += `   Description: ${vuln.description}\n`;
      if (vuln.content) {
        output += `   Content: ${chalk.gray(truncateString(vuln.content, 100))}\n`;
      }
      output += '\n';
    });
  }
  
  // Footer
  output += chalk.bold('=== END OF REPORT ===\n');
  
  return output;
}

/**
 * Calculate risk score based on vulnerability counts
 * @param {Object} groupedBySeverity - Vulnerabilities grouped by severity
 * @returns {number} Risk score from 0-100
 */
function calculateRiskScore(groupedBySeverity) {
  const highCount = groupedBySeverity.high.length;
  const mediumCount = groupedBySeverity.medium.length;
  const lowCount = groupedBySeverity.low.length;
  
  // Simple weighted calculation
  const score = Math.min(
    100,
    (highCount * 25) + (mediumCount * 10) + (lowCount * 3)
  );
  
  return Math.round(score);
}

/**
 * Get risk level based on score
 * @param {number} score - Risk score
 * @returns {string} Risk level
 */
function getRiskLevel(score) {
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  if (score > 0) return 'low';
  return 'none';
}

/**
 * Get colored risk level for CLI output
 * @param {string} level - Risk level
 * @returns {string} Colored risk level
 */
function getColoredRiskLevel(level) {
  switch (level) {
    case 'critical': return chalk.bgRed.white(' CRITICAL ');
    case 'high': return chalk.red(' HIGH ');
    case 'medium': return chalk.yellow(' MEDIUM ');
    case 'low': return chalk.blue(' LOW ');
    default: return chalk.green(' NONE ');
  }
}

/**
 * Get color function for severity
 * @param {string} severity - Vulnerability severity
 * @returns {Function} Chalk color function
 */
function getSeverityColor(severity) {
  switch (severity) {
    case 'high': return chalk.red;
    case 'medium': return chalk.yellow;
    case 'low': return chalk.blue;
    default: return chalk.white;
  }
}

/**
 * Truncate string with ellipsis
 * @param {string} str - String to truncate
 * @param {number} length - Max length
 * @returns {string} Truncated string
 */
function truncateString(str, length) {
  if (str.length <= length) return str;
  return str.substring(0, length - 3) + '...';
}

module.exports = {
  generateReport,
  generateCliReport
};