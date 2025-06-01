/**
 * PDF XSS Scanner - Simple Example
 * 
 * This example demonstrates basic usage with buffer input
 */

const fs = require('fs');
const pdfXssScanner = require('../src/index');

async function scanPdfBuffer(buffer) {
  try {
    if (!Buffer.isBuffer(buffer)) {
      throw new Error('Input must be a buffer');
    }

    console.log('Starting PDF XSS vulnerability scan...');
    
    // Scan the PDF buffer
    const hasXss = await pdfXssScanner.scanBuffer(buffer);
    
    // Print simple result
    console.log('\nScan Result:', hasXss ? 'XSS DETECTED' : 'NO XSS DETECTED');
    
  } catch (error) {
    console.error(`Error: ${error.message}`);
  }
}

// Example usage with a file
if (require.main === module) {
  const pdfPath = process.argv[2];
  if (!pdfPath) {
    console.error('Please provide a path to a PDF file as an argument');
    process.exit(1);
  }
  
  const buffer = fs.readFileSync(pdfPath);
  scanPdfBuffer(buffer);
}