#!/usr/bin/env node

/**
 * PDF XSS Scanner CLI
 * Command-line interface for the PDF XSS scanner
 */

const fs = require('fs');
const path = require('path');
const { Command } = require('commander');
const chalk = require('chalk');
const ora = require('ora');
const scanner = require('../src/index');
const { generateCliReport } = require('../src/utils/reportGenerator');
const { defaultOptions } = require('../src/config/options');
const packageJson = require('../package.json');

// Setup commander
const program = new Command();

program
  .name('pdf-xss-scan')
  .description('Scan PDF files for XSS vulnerabilities')
  .version(packageJson.version);

program
  .argument('<file>', 'PDF file to scan')
  .option('-s, --sensitivity <level>', 'Scanner sensitivity level (1-5)', parseInt)
  .option('-o, --output <file>', 'Output results to a JSON file')
  .option('-q, --quiet', 'Quiet mode - only output if vulnerabilities found')
  .option('--no-color', 'Disable colored output')
  .action(async (file, options) => {
    // Configure scanner options
    const scannerOptions = { ...defaultOptions };
    if (options.sensitivity) {
      scannerOptions.sensitivityLevel = Math.min(5, Math.max(1, options.sensitivity));
    }
    
    // Validate file
    if (!fs.existsSync(file)) {
      console.error(chalk.red(`Error: File not found: ${file}`));
      process.exit(1);
    }
    
    if (!file.toLowerCase().endsWith('.pdf')) {
      console.warn(chalk.yellow(`Warning: File doesn't have a .pdf extension: ${file}`));
    }
    
    // Start scanning
    const spinner = ora('Scanning PDF for XSS vulnerabilities...').start();
    
    try {
      // Run the scan
      const results = await scanner.scanPdf(file, scannerOptions);
      
      // Update spinner based on results
      if (results.summary.hasVulnerabilities) {
        spinner.fail(chalk.red(`Found ${results.summary.vulnerabilityCount} potential XSS vulnerabilities!`));
      } else {
        spinner.succeed(chalk.green('No XSS vulnerabilities detected.'));
      }
      
      // Output results to console (unless quiet mode with no vulnerabilities)
      if (!options.quiet || results.summary.hasVulnerabilities) {
        const report = generateCliReport(results);
        console.log(report);
      }
      
      // Output to file if requested
      if (options.output) {
        fs.writeFileSync(
          options.output,
          JSON.stringify(results, null, 2),
          'utf8'
        );
        console.log(chalk.green(`Full report saved to: ${options.output}`));
      }
      
      // Exit with status code based on results
      process.exit(results.summary.hasVulnerabilities ? 1 : 0);
    } catch (error) {
      spinner.fail(chalk.red(`Error scanning PDF: ${error.message}`));
      process.exit(1);
    }
  });

// Run the CLI
program.parse(process.argv);