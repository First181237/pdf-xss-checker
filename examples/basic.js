/**
 * Basic example of using pdf-xss-checker
 */
const { scanPdf, scanBuffer } = require('../src/index');

async function checkPdf(filePath) {
  console.log(`Scanning ${filePath} for XSS vulnerabilities...`);
  
  try {
    const results = await scanPdf(filePath);
    
    if (results.success) {
      console.log(`\nScan completed successfully.`);
      console.log(`File: ${results.summary.fileName}`);
      console.log(`Pages: ${results.metadata.pageCount}`);
      console.log(`Safe to use: ${results.safeToUse ? 'Yes' : 'No'}`);
      console.log(`Risk level: ${results.riskLevel}`);
      console.log(`Vulnerabilities found: ${results.vulnerabilities.length}`);
      
      if (results.vulnerabilities.length > 0) {
        console.log('\nVulnerabilities:');
        results.vulnerabilities.forEach((vuln, index) => {
          console.log(`\n${index + 1}. ${vuln.name}`);
          console.log(`   Type: ${vuln.type}`);
          console.log(`   Severity: ${vuln.severity}`);
          console.log(`   Description: ${vuln.description}`);
        });
      }
    } else {
      console.error(`Error scanning PDF: ${results.error}`);
    }
  } catch (error) {
    console.error('Error:', error.message);
  }
}

// Example of scanning a buffer
async function checkBuffer(buffer) {
  console.log('Scanning PDF buffer for XSS vulnerabilities...');
  
  try {
    const results = await scanBuffer(buffer);
    
    if (results.success) {
      console.log(`\nScan completed successfully.`);
      console.log(`Safe to use: ${results.safeToUse ? 'Yes' : 'No'}`);
      console.log(`Risk level: ${results.riskLevel}`);
      console.log(`Vulnerabilities found: ${results.vulnerabilities.length}`);
      
      return results;
    } else {
      console.error(`Error scanning PDF: ${results.error}`);
    }
  } catch (error) {
    console.error('Error:', error.message);
  }
}

// Usage example (uncomment to use)
// checkPdf('./sample.pdf');
// checkBuffer(fs.readFileSync('./sample.pdf'));

module.exports = { checkPdf, checkBuffer };