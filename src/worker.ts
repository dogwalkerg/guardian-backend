import 'dotenv/config';
import { pool } from './db.js';

const intervalMs = Number(process.env.WORKER_INTERVAL_MS ?? 15_000);

async function expireCommands() {
  await pool.query(`UPDATE commands SET status='expired',updated_at=now() WHERE status IN ('queued','sent') AND expires_at IS NOT NULL AND expires_at < now()`);
  await pool.query(`UPDATE devices SET online=false WHERE online=true AND last_heartbeat_at IS NOT NULL AND last_heartbeat_at < now() - interval '3 minutes'`);
}

async function run() {
  console.log(`guardian worker started, interval=${intervalMs}ms`);
  await expireCommands();
  setInterval(() => expireCommands().catch((error) => console.error('worker tick failed', error)), intervalMs);
}

run().catch((error) => { console.error(error); process.exit(1); });
