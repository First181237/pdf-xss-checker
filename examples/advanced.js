/**
 * Advanced example of using pdf-xss-checker
 */
const fs = require('fs');
const { scanPdf, scanBuffer, utils } = require('../src/index');

async function advancedCheck(filePath, options = {}) {
  console.log(`Advanced scan of ${filePath} with options:`, options);
  
  try {
    // Read the file as a buffer
    const pdfBuffer = fs.readFileSync(filePath);
    
    // Get the file size
    const fileSize = utils.formatSize(pdfBuffer.length);
    console.log(`File size: ${fileSize}`);
    
    // Custom scan options
    const scanOptions = {
      threshold: options.threshold || 'medium',
      detectors: options.detectors || ['xss', 'js', 'form'],
      includeRawContent: options.includeRawContent || false,
      includeFullDetails: true,
      includeGrouped: true
    };
    
    // Scan the buffer directly
    console.log('Scanning PDF buffer...');
    const results = await scanBuffer(pdfBuffer, scanOptions);
    
    if (results.success) {
      console.log('\nScan Summary:');
      console.log(`  Safe to use: ${results.safeToUse ? 'Yes' : 'No'}`);
      console.log(`  Risk level: ${results.riskLevel}`);
      console.log(`  Vulnerabilities: ${results.vulnerabilities.length}`);
      
      // Severity breakdown
      if (results.vulnerabilities.length > 0) {
        const severityCounts = results.vulnerabilities.reduce((counts, vuln) => {
          counts[vuln.severity] = (counts[vuln.severity] || 0) + 1;
          return counts;
        }, {});
        
        console.log('\nVulnerabilities by Severity:');
        Object.keys(severityCounts).forEach(severity => {
          console.log(`  ${severity}: ${severityCounts[severity]}`);
        });
        
        // List top 5 vulnerabilities
        console.log('\nTop Vulnerabilities:');
        results.vulnerabilities
          .sort((a, b) => utils.getSeverityLevel(b.severity) - utils.getSeverityLevel(a.severity))
          .slice(0, 5)
          .forEach((vuln, index) => {
            console.log(`\n${index + 1}. ${vuln.name} (${vuln.severity})`);
            console.log(`   ${vuln.description}`);
            if (vuln.matchedText) {
              console.log(`   Matched: ${utils.truncateText(vuln.matchedText, 50)}`);
            }
          });
      }
      
      // Save full results to file if requested
      if (options.outputFile) {
        fs.writeFileSync(
          options.outputFile, 
          JSON.stringify(results, null, 2)
        );
        console.log(`\nFull results saved to ${options.outputFile}`);
      }
    } else {
      console.error(`Error scanning PDF: ${results.error}`);
    }
  } catch (error) {
    console.error('Error:', error.message);
  }
}

// Usage example (uncomment to use)
// advancedCheck('./sample.pdf', {
//   threshold: 'low',
//   detectors: ['xss', 'js'],
//   outputFile: 'results.json'
// });

module.exports = { advancedCheck };