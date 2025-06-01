# PDF XSS Scanner

A powerful Node.js tool for detecting Cross-Site Scripting (XSS) vulnerabilities in PDF documents.

## Features

- Comprehensive XSS pattern detection in PDF content
- Detailed vulnerability reporting with severity levels
- Command-line interface for easy usage
- Programmatic API for integration into security workflows
- Configurable sensitivity levels for different security needs
- Color-coded terminal output for easy interpretation

## Installation

```bash
npm install pdf-xss-scanner
```

Or install globally:

```bash
npm install -g pdf-xss-scanner
```

## Usage

### Command Line

```bash
# Basic usage
pdf-xss-scan example.pdf

# Set sensitivity level (1-5)
pdf-xss-scan --sensitivity 4 example.pdf

# Output results to JSON file
pdf-xss-scan --output results.json example.pdf

# Quiet mode (only output if vulnerabilities found)
pdf-xss-scan --quiet example.pdf
```

### Programmatic API

```javascript
const pdfXssScanner = require('pdf-xss-scanner');

async function scanMyPdf() {
  try {
    // Scan a PDF file
    const results = await pdfXssScanner.scanPdf('path/to/file.pdf');
    
    if (results.summary.hasVulnerabilities) {
      console.log(`Found ${results.summary.vulnerabilityCount} vulnerabilities!`);
      console.log(`Risk level: ${results.summary.riskLevel}`);
      
      // Access detailed vulnerabilities
      results.vulnerabilities.forEach(vuln => {
        console.log(`${vuln.severity}: ${vuln.description}`);
      });
    } else {
      console.log('No vulnerabilities detected');
    }
  } catch (error) {
    console.error('Scanning failed:', error.message);
  }
}

scanMyPdf();
```

## Configuration Options

You can customize the scanner behavior by passing options:

```javascript
const options = {
  sensitivityLevel: 3, // 1 (basic) to 5 (paranoid)
  scanObfuscated: true, // Look for obfuscated patterns
  scanEmbeddedFiles: true, // Scan embedded files in the PDF
  reporting: {
    includeContentMatches: true, // Include matched content in results
    maxMatchLength: 200, // Maximum length of included content
    sortBySeverity: true // Sort vulnerabilities by severity
  }
};

const results = await pdfXssScanner.scanPdf('example.pdf', options);
```

## How It Works

The scanner performs the following steps:

1. Parses the PDF document to extract text content, links, and JavaScript
2. Applies a comprehensive set of XSS detection patterns
3. Analyzes different components for potential vulnerabilities
4. Assigns severity levels based on the type and context of matches
5. Generates a detailed report with findings

## License

MIT