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
    `ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_owner_enabled BOOLEAN NOT NULL DEFAULT false`,
    `ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_owner_package VARCHAR(255)`,
    `ALTER TABLE devices ADD COLUMN IF NOT EXISTS dpm_api_level INTEGER`,
    `ALTER TABLE devices ADD COLUMN IF NOT EXISTS dpm_restrictions JSONB NOT NULL DEFAULT '{}'::jsonb`,
    `ALTER TABLE devices ADD COLUMN IF NOT EXISTS dpm_last_sync_at TIMESTAMPTZ`,
    `ALTER TABLE installed_apps ADD COLUMN IF NOT EXISTS app_id VARCHAR(255)`,
    `ALTER TABLE delete_tasks ADD COLUMN IF NOT EXISTS task_set_id UUID`,
    `ALTER TABLE location_records ADD COLUMN IF NOT EXISTS address_details TEXT`,
    `ALTER TABLE location_records ADD COLUMN IF NOT EXISTS city VARCHAR(160)`,
    `ALTER TABLE location_records ADD COLUMN IF NOT EXISTS location_msg TEXT`,
    `CREATE TABLE IF NOT EXISTS child_app_settings (
      child_id UUID PRIMARY KEY REFERENCES children(id) ON DELETE CASCADE,
      allow_new_apps BOOLEAN NOT NULL DEFAULT true,
      offline_mode VARCHAR(32) NOT NULL DEFAULT 'allow',
      location_enabled BOOLEAN NOT NULL DEFAULT true,
      automatic_location_enabled BOOLEAN NOT NULL DEFAULT true,
      hotspot_enabled BOOLEAN NOT NULL DEFAULT true,
      show_app_management BOOLEAN NOT NULL DEFAULT true,
      reset_disabled BOOLEAN NOT NULL DEFAULT false,
      allow_call BOOLEAN NOT NULL DEFAULT true,
      allow_wechat BOOLEAN NOT NULL DEFAULT true,
      allow_qq BOOLEAN NOT NULL DEFAULT true,
      allow_phone BOOLEAN NOT NULL DEFAULT true,
      offline_lock_after_days INTEGER,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`,
    `ALTER TABLE child_app_settings ADD COLUMN IF NOT EXISTS show_app_management BOOLEAN NOT NULL DEFAULT true`,
    `ALTER TABLE child_app_settings ADD COLUMN IF NOT EXISTS reset_disabled BOOLEAN NOT NULL DEFAULT false`,
    `ALTER TABLE child_app_settings ADD COLUMN IF NOT EXISTS allow_call BOOLEAN NOT NULL DEFAULT true`,
    `ALTER TABLE child_app_settings ADD COLUMN IF NOT EXISTS allow_wechat BOOLEAN NOT NULL DEFAULT true`,
    `ALTER TABLE child_app_settings ADD COLUMN IF NOT EXISTS allow_qq BOOLEAN NOT NULL DEFAULT true`,
    `ALTER TABLE child_app_settings ADD COLUMN IF NOT EXISTS allow_phone BOOLEAN NOT NULL DEFAULT true`,
    `ALTER TABLE child_app_settings ADD COLUMN IF NOT EXISTS offline_lock_after_days INTEGER`,
    `CREATE TABLE IF NOT EXISTS control_periods (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      child_id UUID NOT NULL REFERENCES children(id) ON DELETE CASCADE,
      name VARCHAR(120) NOT NULL,
      weekdays SMALLINT[] NOT NULL DEFAULT '{1,2,3,4,5,6,7}',
      start_time TIME NOT NULL,
      end_time TIME NOT NULL,
      mode VARCHAR(32) NOT NULL DEFAULT 'allow',
      daily_limit_seconds INTEGER,
      allowed_packages JSONB NOT NULL DEFAULT '[]'::jsonb,
      priority INTEGER NOT NULL DEFAULT 100,
      enabled BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_control_periods_child ON control_periods(child_id, enabled, priority)`,
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
    ,`CREATE TABLE IF NOT EXISTS parent_active_codes (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      code VARCHAR(80) UNIQUE NOT NULL,
      days INTEGER NOT NULL DEFAULT 30,
      used_by UUID REFERENCES users(id) ON DELETE SET NULL,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`
    ,`CREATE TABLE IF NOT EXISTS parent_entitlements (
      family_id UUID PRIMARY KEY REFERENCES families(id) ON DELETE CASCADE,
      enabled BOOLEAN NOT NULL DEFAULT false,
      expires_at TIMESTAMPTZ,
      granted_by VARCHAR(120),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`
  ];
  for (const statement of statements) await pool.query(statement);
}
