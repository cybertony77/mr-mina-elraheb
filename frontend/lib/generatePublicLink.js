import { createPublicStudentUrl } from './hmac';

/**
 * Generate a public student link with HMAC signature
 * @param {number|string} studentId - The student ID
 * @returns {Promise<string>} - The full public URL with signature
 */
export async function generatePublicStudentLink(studentId) {
  if (!studentId) {
    throw new Error('Student ID is required');
  }
  
  const baseUrl = typeof window !== 'undefined' 
    ? window.location.origin 
    : process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3000';
  
  const path = await createPublicStudentUrl(String(studentId));
  return `${baseUrl}${path}`;
}
