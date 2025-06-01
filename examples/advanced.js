/**
 * PDF XSS Scanner - Advanced Example
 * 
 * This example demonstrates advanced usage with custom options.
 */

const pdfXssScanner = require('../src/index');
const fs = require('fs');
const path = require('path');

async function advancedScan(pdfPath) {
  try {
    if (!pdfPath) {
      throw new Error('Please provide a path to a PDF file as an argument');
    }

    console.log('Starting advanced PDF XSS vulnerability scan...');
    
    // Resolve the PDF path
    const resolvedPath = path.resolve(pdfPath);
    console.log(`Scanning PDF at: ${resolvedPath}`);
    
    // Custom scanner options
    const options = {
      sensitivityLevel: 4, // Higher sensitivity (1-5)
      scanObfuscated: true,
      scanEmbeddedFiles: true,
      scanTimeout: 120000, // 2 minutes
      reporting: {
        includeContentMatches: true,
        maxMatchLength: 300,
        sortBySeverity: true
      }
    };
    
    // Scan the PDF with custom options
    const results = await pdfXssScanner.scanPdf(resolvedPath, options);
    
    // Print results summary
    console.log('\nScan Results:');
    console.log('--------------');
    console.log(`PDF: ${resolvedPath}`);
    console.log(`Vulnerabilities detected: ${results.summary.vulnerabilityCount}`);
    console.log(`Risk level: ${results.summary.riskLevel}`);
    console.log(`High severity: ${results.summary.highSeverityCount}`);
    console.log(`Medium severity: ${results.summary.mediumSeverityCount}`);
    console.log(`Low severity: ${results.summary.lowSeverityCount}`);
    
    // Save full results to a JSON file
    const outputPath = path.join(__dirname, 'scan_results.json');
    fs.writeFileSync(outputPath, JSON.stringify(results, null, 2));
    console.log(`\nDetailed results saved to: ${outputPath}`);
    
    // Analyze results by type
    if (results.summary.hasVulnerabilities) {
      console.log('\nVulnerability Analysis by Type:');
      
      const { byType } = results.groupedResults;
      for (const type in byType) {
        console.log(`\n${type}: ${byType[type].length} vulnerabilities`);
        
        // Show a sample of each type
        const sample = byType[type][0];
        console.log(`  Sample: [${sample.severity.toUpperCase()}] ${sample.pattern}`);
        console.log(`  Description: ${sample.description}`);
      }
    }
    
    console.log('\nAdvanced scan completed successfully.');
  } catch (error) {
    console.error(`Error: ${error.message}`);
  }
}

// Get PDF path from command line arguments
const pdfPath = process.argv[2];
advancedScan(pdfPath);