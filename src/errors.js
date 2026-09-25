'use strict';
/**
 * Normalized error categories surfaced to users (see docs/API.md).
 * Raw OS/system errors are mapped onto these; stack traces stay in logs.
 */
const CATEGORIES = [
  'TIMEOUT',
  'CONNECTION_REFUSED',
  'DNS_ERROR',
  'AUTH_FAILED',
  'TLS_ERROR',
  'INVALID_PROXY',
  'UNSUPPORTED_PROTOCOL',
  'TARGET_ERROR',
  'NETWORK_ERROR',
  'UNKNOWN_ERROR',
];

/** Errors that a retry might plausibly fix. */
const RETRYABLE = new Set(['TIMEOUT', 'NETWORK_ERROR', 'TARGET_ERROR']);

class CheckError extends Error {
  constructor(category, message, { cause, detail } = {}) {
    super(message);
    this.name = 'CheckError';
    this.category = CATEGORIES.includes(category) ? category : 'UNKNOWN_ERROR';
    this.detail = detail;
    if (cause) this.cause = cause;
  }
}

/** Thrown when SSRF protection blocks a destination. */
class SsrfBlockedError extends CheckError {
  constructor(message, detail) {
    super('INVALID_PROXY', message, { detail });
    this.name = 'SsrfBlockedError';
    this.ssrf = true;
  }
}

/** HTTP-level API error with a status code. */
class ApiError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

function fromOsError(err, fallbackMessage) {
  const code = err && (err.code || (err.cause && err.cause.code));
  switch (code) {
    case 'ECONNREFUSED':
      return new CheckError('CONNECTION_REFUSED', 'Connection refused by the proxy.');
    case 'ECONNRESET':
      return new CheckError('CONNECTION_REFUSED', 'Connection reset by the proxy.');
    case 'ETIMEDOUT':
    case 'ECONNABORTED':
      return new CheckError('TIMEOUT', 'Connection attempt timed out.');
    case 'EHOSTUNREACH':
    case 'ENETUNREACH':
    case 'ENETDOWN':
      return new CheckError('NETWORK_ERROR', 'Host or network unreachable.');
    case 'EACCES':
    case 'EPERM':
      return new CheckError('NETWORK_ERROR', 'Connection blocked locally (firewall or permissions).');
    case 'ENOTFOUND':
    case 'EAI_AGAIN':
      return new CheckError('DNS_ERROR', 'Proxy hostname could not be resolved.');
    default:
      // code-less connect failures (silent filters, aborts) are network errors
      return new CheckError('NETWORK_ERROR', fallbackMessage || 'Network error during connection.', { cause: err });
  }
}

module.exports = { CATEGORIES, RETRYABLE, CheckError, SsrfBlockedError, ApiError, fromOsError };
