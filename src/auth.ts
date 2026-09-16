import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { query } from './db.js';

export type AuthUser = { id: string; phone: string; familyId: string };

export async function issueToken(app: FastifyInstance, user: AuthUser) {
  return app.jwt.sign({ sub: user.id, phone: user.phone, familyId: user.familyId });
}

export async function getAuthUser(app: FastifyInstance, request: FastifyRequest): Promise<AuthUser> {
  await request.jwtVerify();
  const payload = request.user as { sub: string; phone: string; familyId: string };
  return { id: payload.sub, phone: payload.phone, familyId: payload.familyId };
}

export function hashToken(value: string) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export async function ensureUserAndFamily(phone: string, displayName?: string) {
  return (await query<{ id: string; phone: string; family_id: string }>(
    `WITH new_user AS (
       INSERT INTO users(phone, display_name) VALUES ($1, $2)
       ON CONFLICT(phone) DO UPDATE SET updated_at = now()
       RETURNING id, phone
     ), family AS (
       INSERT INTO families(owner_user_id) SELECT id FROM new_user
       WHERE NOT EXISTS (SELECT 1 FROM families f WHERE f.owner_user_id = new_user.id)
       RETURNING id, owner_user_id
     ), membership AS (
       INSERT INTO family_members(family_id, user_id, role)
       SELECT f.id, u.id, 'owner' FROM users u
       JOIN families f ON f.owner_user_id = u.id
       WHERE u.phone = $1
       ON CONFLICT DO NOTHING
     )
     SELECT u.id, u.phone, f.id AS family_id
     FROM users u JOIN families f ON f.owner_user_id = u.id WHERE u.phone = $1`,
    [phone, displayName ?? `家长${phone.slice(-4)}`]
  )).rows[0];
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
