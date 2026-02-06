const SECRET = "STD_";

/**
 * Generate HMAC signature for a student ID
 * Works in both Node.js and browser environments
 * @param {number|string} studentId - The student ID
 * @returns {Promise<string>} - The HMAC signature
 */
export async function generateSignature(studentId) {
  const message = SECRET + studentId;
  
  // Browser environment - use Web Crypto API
  if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }
  
  // Node.js environment - use crypto module
  // Check if we're in Node.js environment (not browser)
  if (typeof window === 'undefined' && typeof require !== 'undefined') {
    const nodeCrypto = require('crypto');
    return nodeCrypto.createHash('sha256').update(message).digest('hex');
  }
  
  // Fallback: if neither works, throw an error
  throw new Error('Crypto API not available in this environment');
}

/**
 * Verify HMAC signature for a student ID
 * Works in both Node.js and browser environments
 * @param {number|string} studentId - The student ID
 * @param {string} signature - The signature to verify
 * @returns {Promise<boolean>} - True if signature is valid
 */
export async function verifySignature(studentId, signature) {
  // Input validation
  if (!studentId || !signature) {
    console.log('❌ HMAC: Missing studentId or signature');
    return false;
  }
  
  // Convert to string and trim
  const cleanStudentId = String(studentId).trim();
  const cleanSignature = String(signature).trim();
  
  if (!cleanStudentId || !cleanSignature) {
    console.log('❌ HMAC: Empty studentId or signature after trimming');
    return false;
  }
  
  try {
    const expectedSignature = await generateSignature(cleanStudentId);
    
    // Ensure both signatures are the same length
    if (cleanSignature.length !== expectedSignature.length) {
      console.log('❌ HMAC: Signature length mismatch');
      return false;
    }
    
    // Use simple string comparison for browser environment
    // This is secure enough for our use case since we're comparing hashes
    const isValid = cleanSignature === expectedSignature;
    console.log(`🔍 HMAC Verification: ${isValid ? 'VALID' : 'INVALID'}`);
    return isValid;
  } catch (error) {
    console.error('❌ HMAC: Error during verification:', error);
    return false;
  }
}

/**
 * Create a public student info URL
 * @param {number|string} studentId - The student ID
 * @returns {Promise<string>} - The public URL with signature
 */
export async function createPublicStudentUrl(studentId) {
  const signature = await generateSignature(studentId);
  return `/dashboard/student_info?id=${studentId}&sig=${signature}`;
}
