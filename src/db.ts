import { Pool, type PoolClient, type QueryResultRow } from 'pg';
import { config } from './config.js';

export const pool = new Pool({ connectionString: config.databaseUrl, max: 8, idleTimeoutMillis: 30_000 });

export async function query<T extends QueryResultRow = QueryResultRow>(text: string, values: unknown[] = []) {
  return pool.query<T>(text, values);
}

export async function withTransaction<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

/** Apply additive schema changes on every boot so existing Docker volumes upgrade safely. */
export async function ensureRuntimeSchema() {
  const statements = [
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ`,
    `ALTER TABLE devices ADD COLUMN IF NOT EXISTS step_count INTEGER`,
    `ALTER TABLE devices ADD COLUMN IF NOT EXISTS current_app_package VARCHAR(255)`,
    `ALTER TABLE devices ADD COLUMN IF NOT EXISTS current_app_name VARCHAR(255)`,
    `ALTER TABLE devices ADD COLUMN IF NOT EXISTS current_app_started_at TIMESTAMPTZ`,
    `ALTER TABLE devices ADD COLUMN IF NOT EXISTS control_status VARCHAR(32) NOT NULL DEFAULT 'normal'`,
    `ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_location_at TIMESTAMPTZ`,
    `ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_usage_sync_at TIMESTAMPTZ`,
    `ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_apps_sync_at TIMESTAMPTZ`,
    `CREATE TABLE IF NOT EXISTS child_app_settings (
      child_id UUID PRIMARY KEY REFERENCES children(id) ON DELETE CASCADE,
      allow_new_apps BOOLEAN NOT NULL DEFAULT true,
      offline_mode VARCHAR(32) NOT NULL DEFAULT 'allow',
      location_enabled BOOLEAN NOT NULL DEFAULT true,
      automatic_location_enabled BOOLEAN NOT NULL DEFAULT true,
      hotspot_enabled BOOLEAN NOT NULL DEFAULT true,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`,
    `CREATE TABLE IF NOT EXISTS step_records (
      id BIGSERIAL PRIMARY KEY,
      device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      child_id UUID NOT NULL REFERENCES children(id) ON DELETE CASCADE,
      steps INTEGER NOT NULL,
      recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      day DATE NOT NULL DEFAULT current_date
    )`,
    `CREATE INDEX IF NOT EXISTS idx_steps_child_day ON step_records(child_id, day, recorded_at DESC)`,
    `CREATE TABLE IF NOT EXISTS delete_tasks (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      child_id UUID NOT NULL REFERENCES children(id) ON DELETE CASCADE,
      device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
      package_name VARCHAR(255) NOT NULL,
      app_name VARCHAR(255),
      status VARCHAR(32) NOT NULL DEFAULT 'queued',
      command_id UUID,
      requested_by VARCHAR(120),
      result JSONB,
      requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      completed_at TIMESTAMPTZ
    )`,
    `ALTER TABLE delete_tasks ADD COLUMN IF NOT EXISTS requested_by VARCHAR(120)`,
    `ALTER TABLE delete_tasks DROP CONSTRAINT IF EXISTS delete_tasks_requested_by_fkey`,
    `ALTER TABLE delete_tasks ALTER COLUMN requested_by TYPE VARCHAR(120) USING requested_by::text`,
    `CREATE INDEX IF NOT EXISTS idx_delete_tasks_child_time ON delete_tasks(child_id, requested_at DESC)`,
    `CREATE TABLE IF NOT EXISTS device_events (
      id BIGSERIAL PRIMARY KEY,
      device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      child_id UUID NOT NULL REFERENCES children(id) ON DELETE CASCADE,
      event_type VARCHAR(100) NOT NULL,
      payload JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_device_events_child_time ON device_events(child_id, created_at DESC)`,
    `CREATE TABLE IF NOT EXISTS admin_audit_logs (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(120) NOT NULL,
      action VARCHAR(120) NOT NULL,
      family_id UUID REFERENCES families(id) ON DELETE SET NULL,
      child_id UUID REFERENCES children(id) ON DELETE SET NULL,
      device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
      detail JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_time ON admin_audit_logs(created_at DESC)`
  ];
  for (const statement of statements) await pool.query(statement);
}
