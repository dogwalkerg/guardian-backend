import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { query } from './db.js';

export type AuthUser = { id: string; phone: string; familyId: string };
export type AdminUser = { username: string; role: 'admin' };

export async function issueToken(app: FastifyInstance, user: AuthUser) {
  return app.jwt.sign({ sub: user.id, phone: user.phone, familyId: user.familyId });
}

export async function getAuthUser(app: FastifyInstance, request: FastifyRequest): Promise<AuthUser> {
  const payload = await verifyJwtCompat(app, request) as { sub?: string; phone?: string; familyId?: string; role?: string };
  if (payload.role === 'admin' || !payload.sub || !payload.phone || !payload.familyId) {
    throw new Error('parent token required');
  }
  return { id: payload.sub, phone: payload.phone, familyId: payload.familyId };
}

export async function issueAdminToken(app: FastifyInstance, username: string) {
  return app.jwt.sign({ role: 'admin', username, sub: `admin:${username}` });
}

export async function getAdminUser(app: FastifyInstance, request: FastifyRequest): Promise<AdminUser> {
  const payload = await verifyJwtCompat(app, request) as { role?: string; username?: string };
  if (payload.role !== 'admin' || !payload.username) throw new Error('admin token required');
  return { role: 'admin', username: payload.username };
}

async function verifyJwtCompat(app: FastifyInstance, request: FastifyRequest) {
  const authorization = String(request.headers.authorization ?? '').trim();
  // The installed parent APK sends the JWT directly. The administrator console
  // and standard clients send the normal "Bearer <JWT>" form, so accept both.
  if (authorization && !/^Bearer\s+/i.test(authorization)) {
    return app.jwt.verify(authorization);
  }
  await request.jwtVerify();
  return request.user;
}

export function hashToken(value: string) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export async function ensureUserAndFamily(phone: string, displayName?: string) {
  // Keep these operations sequential. A data-modifying CTE cannot reliably
  // read rows inserted by a sibling CTE in the same statement snapshot, which
  // made the first login write records but return an undefined family.
  const userResult = await query<{ id: string; phone: string }>(
    `INSERT INTO users(phone, display_name) VALUES ($1, $2)
     ON CONFLICT(phone) DO UPDATE SET updated_at = now()
     RETURNING id, phone`,
    [phone, displayName ?? `家长${phone.slice(-4)}`]
  );
  const user = userResult.rows[0];
  if (!user) throw new Error('无法创建家长账号');

  let familyResult = await query<{ id: string }>(
    'SELECT id FROM families WHERE owner_user_id=$1 ORDER BY created_at LIMIT 1',
    [user.id]
  );
  if (!familyResult.rows[0]) {
    familyResult = await query<{ id: string }>(
      'INSERT INTO families(owner_user_id) VALUES ($1) RETURNING id',
      [user.id]
    );
  }
  const family = familyResult.rows[0];
  if (!family) throw new Error('无法创建家庭');
  await query(
    `INSERT INTO family_members(family_id, user_id, role)
     VALUES ($1, $2, 'owner') ON CONFLICT DO NOTHING`,
    [family.id, user.id]
  );
  return { id: user.id, phone: user.phone, family_id: family.id };
}

export async function verifyCaptcha(phone: string, code: string, fixedAllowed: boolean, fixedCode: string) {
  if (fixedAllowed && code === fixedCode) return true;
  const result = await query<{ ok: boolean }>(
    'SELECT now() < expires_at AS ok FROM captcha_codes WHERE phone = $1 AND code = $2',
    [phone, code]
  );
  return result.rows[0]?.ok === true;
}

export async function passwordHash(value: string) {
  return bcrypt.hash(value, 10);
}

export async function verifyPassword(value: string, hash: string) {
  return bcrypt.compare(value, hash);
}
