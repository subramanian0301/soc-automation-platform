export const JWT_MIN_SECRET_LENGTH = 32;
export const JWT_DEFAULT_ALGORITHM = 'HS256' as const;
export const JWT_DEFAULT_EXPIRY = '15m'; // 15-minute token lifetime for demo & standard sessions

const INSECURE_FALLBACK_PATTERNS = [
  'soc_default_development_secret_key',
  'development_secret_key',
  'default_secret_key',
];

const WEAK_EXACT_SECRETS = [
  'secret',
  'password',
  'admin',
  'change_me',
  '123456',
  '12345678',
  'jwt_secret',
  'default',
];

export interface JwtValidationResult {
  valid: boolean;
  error?: string;
}

/**
 * Validates JWT secret configuration against security policies.
 * Ensures secrets never appear in error messages or logs.
 */
export function validateJwtConfig(
  env: Record<string, string | undefined> = process.env,
): JwtValidationResult {
  const isProduction = env.NODE_ENV === 'production';
  const secret = env.JWT_SECRET;

  if (!secret || secret.trim().length === 0) {
    const msg =
      'JWT_SECRET environment variable is missing or empty. Token issuance and verification are disabled.';
    if (isProduction) {
      throw new Error(`FATAL: Insecure configuration. ${msg} Platform startup aborted in production.`);
    }
    return { valid: false, error: msg };
  }

  if (secret.length < JWT_MIN_SECRET_LENGTH) {
    const msg = `JWT_SECRET must be at least ${JWT_MIN_SECRET_LENGTH} characters for HMAC-SHA256 security. Configured length is ${secret.length}.`;
    if (isProduction) {
      throw new Error(`FATAL: Insecure configuration. ${msg} Platform startup aborted in production.`);
    }
    return { valid: false, error: msg };
  }

  const isPredictable =
    INSECURE_FALLBACK_PATTERNS.some((pattern) =>
      secret.toLowerCase().includes(pattern),
    ) ||
    WEAK_EXACT_SECRETS.some((weak) => secret.toLowerCase() === weak);

  if (isPredictable) {
    const msg =
      'Insecure or predictable JWT_SECRET detected. Default fallback keys are strictly prohibited.';
    if (isProduction) {
      throw new Error(`FATAL: Insecure configuration. ${msg} Platform startup aborted in production.`);
    }
    return { valid: false, error: msg };
  }

  return { valid: true };
}

/**
 * Resolves the JWT secret if valid, otherwise throws an error.
 * Does not expose the secret in exception text.
 */
export function getJwtSecret(
  env: Record<string, string | undefined> = process.env,
): string {
  const result = validateJwtConfig(env);
  if (!result.valid || !env.JWT_SECRET) {
    throw new Error(result.error || 'JWT_SECRET is not configured or fails security validation.');
  }
  return env.JWT_SECRET;
}
