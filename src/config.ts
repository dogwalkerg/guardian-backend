import 'dotenv/config';

function required(name: string, fallback?: string): string {
  const value = process.env[name] ?? fallback;
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
}

export const config = {
  nodeEnv: process.env.NODE_ENV ?? 'development',
  host: process.env.HOST ?? '0.0.0.0',
  port: Number(process.env.PORT ?? 3000),
  jwtSecret: required('JWT_SECRET', 'development-only-change-me'),
  databaseUrl: required('DATABASE_URL', 'postgres://guardian:guardian_dev_password@localhost:5432/guardian'),
  redisUrl: required('REDIS_URL', 'redis://localhost:6379'),
  allowFixedCaptcha: (process.env.DEV_ALLOW_FIXED_CAPTCHA ?? 'false') === 'true',
  fixedCaptcha: process.env.FIXED_CAPTCHA ?? '123456',
  corsOrigin: process.env.CORS_ORIGIN ?? true,
  logLevel: process.env.LOG_LEVEL ?? 'info'
};
