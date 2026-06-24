import crypto from 'crypto';

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function hashIdentifierForLog(identifier: string): string {
  return crypto.createHash('sha256').update(identifier).digest('hex').slice(0, 8);
}
