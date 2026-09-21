import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import jwt from '@fastify/jwt';
import rateLimit from '@fastify/rate-limit';
import websocket from '@fastify/websocket';
import fastifyStatic from '@fastify/static';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from './config.js';
import { pool, ensureRuntimeSchema } from './db.js';
import { registerRoutes } from './routes.js';

const app = Fastify({
  logger: {
    level: config.logLevel,
    transport: config.nodeEnv === 'development' ? { target: 'pino-pretty', options: { translateTime: 'SYS:standard' } } : undefined
  },
  // A child device uploads one base64 PNG per installed application. A full
  // application list can legitimately exceed the default Fastify limit.
  bodyLimit: 20 * 1024 * 1024
});

await app.register(cors, { origin: config.corsOrigin, credentials: true });
await app.register(helmet, { contentSecurityPolicy: false });
await app.register(jwt, { secret: config.jwtSecret, sign: { expiresIn: '30d' } });
await app.register(rateLimit, { max: 120, timeWindow: '1 minute' });
await app.register(websocket);
await app.register(fastifyStatic, { root: path.join(path.dirname(fileURLToPath(import.meta.url)), '../public'), prefix: '/admin/' });
// The shipped parent APK treats code=0 as the only successful response. Most
// legacy routes historically returned only {data}, so normalize API success
// responses at the transport boundary while preserving explicit error codes.
app.addHook('preSerialization', async (request, reply, payload: unknown) => {
  if (!request.url.startsWith('/api/') || reply.statusCode >= 400 || !payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return payload;
  }
  const value = payload as Record<string, unknown>;
  if (Object.prototype.hasOwnProperty.call(value, 'code')) return value;
  if (Object.prototype.hasOwnProperty.call(value, 'error') || Object.prototype.hasOwnProperty.call(value, 'message') && !Object.prototype.hasOwnProperty.call(value, 'data')) {
    return { code: 40000, ...value };
  }
  return { code: 0, message: 'success', ...value };
});
await ensureRuntimeSchema();
await registerRoutes(app);
app.get('/', async (_request, reply) => reply.redirect('/admin/'));
app.get('/admin', async (_request, reply) => reply.redirect('/admin/'));

app.addHook('onClose', async () => { await pool.end(); });

try {
  await app.listen({ host: config.host, port: config.port });
  app.log.info(`guardian backend listening on ${config.host}:${config.port}`);
} catch (error) {
  app.log.error(error);
  process.exit(1);
}


