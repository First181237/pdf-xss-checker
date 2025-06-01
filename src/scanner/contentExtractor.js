/**
 * Content Extractor
 * Extracts various content types from PDF data
 */

/**
 * Extract links from PDF data
 * @param {Object} pdfData - The parsed PDF data
 * @returns {Array} Extracted links
 */
function extractLinks(pdfData) {
  const links = [];
  
  try {
    // This is a simplified implementation
    // Real implementation would need to use PDF.js or a similar library
    // to properly extract all links from the PDF structure
    
    // Extract links from text content using regex
    // This is not comprehensive but gives a starting point
    const urlRegex = /(https?:\/\/[^\s]+)|(www\.[^\s]+)|((javascript|data):[^\s]+)/gi;
    const text = pdfData.text;
    let match;
    
    while ((match = urlRegex.exec(text)) !== null) {
      links.push({
        url: match[0],
        location: `character ${match.index}`,
        pageNum: estimatePageNumber(match.index, text, pdfData.numpages)
      });
    }
    
    return links;
  } catch (error) {
    console.error(`Error extracting links: ${error.message}`);
    return links;
  }
}

/**
 * Extract JavaScript content from PDF data
 * @param {Object} pdfData - The parsed PDF data
 * @returns {Array} Extracted JavaScript content
 */
function extractJavaScript(pdfData) {
  const jsContents = [];
  
  try {
    // This is a simplified implementation
    // Real implementation would need to parse the PDF structure to find
    // JavaScript actions, form actions, etc.
    
    // Look for common JS indicators in text
    const jsIndicators = [
      /function\s*\([^)]*\)\s*{[^}]*}/gi,
      /var\s+[a-zA-Z0-9_$]+\s*=/gi,
      /let\s+[a-zA-Z0-9_$]+\s*=/gi,
      /const\s+[a-zA-Z0-9_$]+\s*=/gi,
      /new\s+[a-zA-Z0-9_$]+\(/gi,
      /return\s+[a-zA-Z0-9_$]+/gi,
      /document\.get/gi,
      /document\.write/gi,
      /window\./gi
    ];
    
    const text = pdfData.text;
    
    for (const regex of jsIndicators) {
      let match;
      while ((match = regex.exec(text)) !== null) {
        // Extract a larger context around the match
        const startIndex = Math.max(0, match.index - 50);
        const endIndex = Math.min(text.length, match.index + match[0].length + 100);
        const jsSnippet = text.substring(startIndex, endIndex);
        
        jsContents.push({
          content: jsSnippet,
          location: `character ${match.index}`,
          pageNum: estimatePageNumber(match.index, text, pdfData.numpages)
        });
      }
    }
    
    return jsContents;
  } catch (error) {
    console.error(`Error extracting JavaScript: ${error.message}`);
    return jsContents;
  }
}

/**
 * Estimate page number based on character index
 * @param {number} charIndex - Character index in the text
 * @param {string} text - Full text content
 * @param {number} pageCount - Number of pages in the PDF
 * @returns {number} Estimated page number
 */
function estimatePageNumber(charIndex, text, pageCount) {
  if (!text || text.length === 0 || pageCount <= 1) return 1;
  
  // Simple estimation - assuming equal content distribution
  const estimatedPage = Math.ceil((charIndex / text.length) * pageCount);
  return Math.min(estimatedPage, pageCount);
}

module.exports = {
  extractLinks,
  extractJavaScript
};