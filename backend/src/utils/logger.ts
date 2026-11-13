/**
 * CipherGuard AI - Security-Conscious Structured Logger
 * Member 3: Cryptography & Secure Storage
 *
 * Security Requirements (SRS SEC-2, Architecture §9):
 * - NO sensitive data (passwords, raw AES keys, RSA private keys, plaintext file contents) shall appear in logs.
 * - Sensitive patterns are strictly sanitized before emission.
 * - High-priority security alerts emitted on tampering, tag mismatch, or hash discrepancy.
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'security_alert';

export interface StructuredLogEvent {
  level: LogLevel;
  message: string;
  timestamp: string;
  context?: string;
  scanId?: string;
  userId?: string;
  storagePath?: string;
  isSecurityAlert?: boolean;
  meta?: Record<string, unknown>;
}

// Patterns that must NEVER appear in logs
const SENSITIVE_KEY_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gi,
  /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/gi,
  /("?(?:aesKey|privateKey|password|passwordHash|rawKey)"?\s*[:=]\s*)"[^"]+"/gi,
  /("?(?:aesKey|privateKey|password|passwordHash|rawKey)"?\s*[:=]\s*)'[^']+'/gi,
];

function sanitizeString(str: string): string {
  let sanitized = str;
  for (const pattern of SENSITIVE_KEY_PATTERNS) {
    sanitized = sanitized.replace(pattern, '[REDACTED_SECRET]');
  }
  return sanitized;
}

function sanitizeObject(obj: unknown, depth = 0): unknown {
  if (depth > 5 || obj === null || obj === undefined) return obj;
  if (Buffer.isBuffer(obj)) {
    return `[Buffer: ${obj.length} bytes]`;
  }
  if (typeof obj === 'string') {
    return sanitizeString(obj);
  }
  if (Array.isArray(obj)) {
    return obj.map((item) => sanitizeObject(item, depth + 1));
  }
  if (typeof obj === 'object') {
    const sanitizedObj: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      const lowerKey = key.toLowerCase();
      if (
        lowerKey.includes('key') ||
        lowerKey.includes('password') ||
        lowerKey.includes('secret') ||
        lowerKey.includes('private') ||
        lowerKey.includes('content')
      ) {
        if (lowerKey === 'wrappedaeskey') {
          sanitizedObj[key] = Buffer.isBuffer(value)
            ? `[Wrapped AES Key: ${value.length} bytes]`
            : '[Wrapped AES Key: sanitized]';
        } else {
          sanitizedObj[key] = '[REDACTED]';
        }
      } else {
        sanitizedObj[key] = sanitizeObject(value, depth + 1);
      }
    }
    return sanitizedObj;
  }
  return obj;
}

export class Logger {
  private readonly context: string;

  constructor(context: string) {
    this.context = context;
  }

  private log(level: LogLevel, message: string, meta?: Record<string, unknown>, isSecurityAlert = false): void {
    const event: StructuredLogEvent = {
      level,
      message: sanitizeString(message),
      timestamp: new Date().toISOString(),
      context: this.context,
      isSecurityAlert,
      ...(meta ? { meta: sanitizeObject(meta) as Record<string, unknown> } : {})
    };

    const serialized = JSON.stringify(event);

    if (level === 'error' || isSecurityAlert) {
      console.error(serialized);
    } else if (level === 'warn') {
      console.warn(serialized);
    } else {
      console.log(serialized);
    }
  }

  public debug(message: string, meta?: Record<string, unknown>): void {
    if (process.env.NODE_ENV !== 'production' || process.env.DEBUG === 'true') {
      this.log('debug', message, meta);
    }
  }

  public info(message: string, meta?: Record<string, unknown>): void {
    this.log('info', message, meta);
  }

  public warn(message: string, meta?: Record<string, unknown>): void {
    this.log('warn', message, meta);
  }

  public error(message: string, meta?: Record<string, unknown>): void {
    this.log('error', message, meta);
  }

  /**
   * Log high-severity security alert (e.g. GCM authentication failure or SHA-256 integrity mismatch).
   * Maps to Architecture §9 Alerting requirements.
   */
  public securityAlert(message: string, meta?: Record<string, unknown>): void {
    this.log('security_alert', `[SECURITY ALERT] ${message}`, meta, true);
  }
}

export const defaultLogger = new Logger('CipherGuard:Crypto');
