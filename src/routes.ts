import { randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { FastifyInstance } from 'fastify';
import { config } from './config.js';
import { query } from './db.js';
import { getAuthUser, getAdminUser, ensureUserAndFamily, issueAdminToken, issueToken, verifyCaptcha, hashToken, verifyPassword } from './auth.js';
import type { DeviceMessage } from './protocol.js';

const deviceSockets = new Map<string, any>();

const COMMANDS = {
  policyUpdate: 'policy_update',
  appPolicyUpdate: 'app_policy_update',
  appSettingsUpdate: 'app_settings_update',
  lock: 'lock',
  unlock: 'unlock',
  requestLocation: 'request_location',
  syncApps: 'sync_apps',
  syncUsage: 'sync_usage',
  uninstallApp: 'uninstall_app',
  unbind: 'unbind',
  emergencyNumbersUpdate: 'emergency_numbers_update',
  locationSettingsUpdate: 'location_settings_update',
  hotspotUpdate: 'hotspot_update',
  clientUpdate: 'client_update',
  functionPolicyUpdate: 'function_policy_update',
  periodsUpdate: 'periods_update',
  deviceOwnerPolicyUpdate: 'device_owner_policy_update'
} as const;

const COMMAND_SET = new Set<string>(Object.values(COMMANDS));
const WIRE_COMMANDS: Record<string, string> = {
  [COMMANDS.policyUpdate]: 'CONTROL_POLICY_UPDATE',
  // The vendor child uses this legacy signal to reload
  // /child/software/appcontrol, despite its misleading historical name.
  [COMMANDS.appPolicyUpdate]: 'CONTROL_APP_POLICY_CHANGE',
  [COMMANDS.appSettingsUpdate]: 'CONTROL_APPSYSTEM_CHANGE',
  [COMMANDS.lock]: 'CONTROL_POLICY_LOCK',
  [COMMANDS.unlock]: 'CONTROL_POLICY_REMOVE_LOCK',
  [COMMANDS.requestLocation]: 'LOCATION_NOTIFICAT',
  [COMMANDS.syncApps]: 'CHILD_UPDATE_DEVICE',
  [COMMANDS.syncUsage]: 'CHILD_UPDATE_APP_USE_TIME',
  [COMMANDS.uninstallApp]: 'REMOTE_UNINSTALL_APPLICATION',
  [COMMANDS.unbind]: 'CHILD_REMOVE_DEVICE',
  [COMMANDS.emergencyNumbersUpdate]: 'EMERGENCY_NUMBER_UPDATE',
  [COMMANDS.locationSettingsUpdate]: 'AUTOMATIC_POSITIONING_UPDATE',
  [COMMANDS.hotspotUpdate]: 'CONTROL_APPSYSTEM_CHANGE',
  [COMMANDS.clientUpdate]: 'CLIENT_VERSION_UP',
  [COMMANDS.functionPolicyUpdate]: 'APP_FUNCTION_POLICY_UPDATE',
  [COMMANDS.periodsUpdate]: 'CONTROL_PERIODS_UPDATE',
  [COMMANDS.deviceOwnerPolicyUpdate]: 'DEVICE_OWNER_POLICY_UPDATE'
};

// The installed child APK does not parse the newer command envelope. It reads
// the vendor push format instead: a numeric `type` plus an optional `content`.
// Keep the command/payload fields as well for newer clients during migration.
const LEGACY_WIRE_TYPES: Record<string, number> = {
  [COMMANDS.policyUpdate]: 1001,
  [COMMANDS.lock]: 1002,
  [COMMANDS.unlock]: 1003,
  [COMMANDS.appSettingsUpdate]: 1005,
  [COMMANDS.emergencyNumbersUpdate]: 1006,
  [COMMANDS.locationSettingsUpdate]: 1007,
  [COMMANDS.requestLocation]: 1008,
  [COMMANDS.clientUpdate]: 1009,
  [COMMANDS.uninstallApp]: 1010,
  // 1013 only reloads /child/appsettings. 1023 emits APP_CONTROL (0x777793),
  // which reloads the per-application time-limit list.
  [COMMANDS.appPolicyUpdate]: 1023
};

type JsonRecord = Record<string, any>;

function firstObject(value: unknown): JsonRecord {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value as JsonRecord;
  return {};
}

function normalizeMessagePayload(value: unknown): any {
  if (Array.isArray(value)) return { apps: value };
  const root = firstObject(value);
  const nested = firstObject(root.data ?? root.result ?? root.payload ?? root.message);
  // The vendor APK has used both a direct object and a data-wrapped object.
  return Object.keys(nested).length ? { ...root, ...nested } : root;
}

function extractAppItems(value: unknown): JsonRecord[] {
  if (Array.isArray(value)) return value.filter((item): item is JsonRecord => Boolean(item && typeof item === 'object'));
  const payload = normalizeMessagePayload(value);
  for (const key of ['apps', 'appList', 'applicationList', 'applications', 'list', 'data', 'result', 'payload', 'message']) {
    if (Array.isArray(payload[key])) return payload[key].filter((item: unknown): item is JsonRecord => Boolean(item && typeof item === 'object'));
  }
  // `/child/software/uploadApp` in older builds posts one UploadAppReq object
  // at a time (packageName + iconBase64), while websocket sync uses an array.
  // Treat a package-shaped object as one app instead of returning an empty list.
  if (nonEmpty(payload.packageName, payload.package_name, payload.appPackageName, payload.package, payload.pkg)) return [payload];
  return [];
}

function nonEmpty(...values: unknown[]) {
  return values.find((value) => value !== undefined && value !== null && String(value).trim() !== '') ?? null;
}

function safeTimestamp(value: unknown): string | null {
  if (value === undefined || value === null || String(value).trim() === '') return null;
  const raw = String(value).trim();
  if (/^\d{10,13}$/.test(raw)) {
    const number = Number(raw);
    return new Date(raw.length === 13 ? number : number * 1000).toISOString();
  }
  const date = new Date(raw);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function splitIds(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap((item) => splitIds(item));
  if (value === undefined || value === null) return [];
  return String(value).split(',').map((item) => item.trim()).filter(Boolean);
}

async function reverseGeocode(latitude: number, longitude: number): Promise<{ address: string | null; city: string | null; details: string | null }> {
  const enabled = (process.env.LOCATION_GEOCODER_ENABLED ?? 'true').toLowerCase() === 'true';
  if (!enabled) return { address: null, city: null, details: null };
  try {
    const url = new URL(process.env.LOCATION_GEOCODER_URL ?? 'https://nominatim.openstreetmap.org/reverse');
    url.searchParams.set('format', 'jsonv2');
    url.searchParams.set('lat', String(latitude));
    url.searchParams.set('lon', String(longitude));
    url.searchParams.set('zoom', '18');
    url.searchParams.set('addressdetails', '1');
    const response = await fetch(url, { headers: { 'user-agent': 'Guardian/1.0 location reverse geocoder' }, signal: AbortSignal.timeout(2500) });
    if (!response.ok) return { address: null, city: null, details: null };
    const body = await response.json() as JsonRecord;
    const address = typeof body.display_name === 'string' ? body.display_name : null;
    const parts = firstObject(body.address);
    const city = String(nonEmpty(parts.city, parts.town, parts.municipality, parts.county, parts.state) ?? '') || null;
    return { address, city, details: Object.keys(parts).length ? JSON.stringify(parts) : null };
  } catch {
    return { address: null, city: null, details: null };
  }
}

export function broadcastToDevice(deviceId: string, message: DeviceMessage) {
  const socket = deviceSockets.get(deviceId);
  if (!socket || socket.readyState !== 1) return false;
  socket.send(JSON.stringify(message));
  return true;
}

export function isDeviceOnline(deviceId: string) {
  const socket = deviceSockets.get(deviceId);
  return Boolean(socket && socket.readyState === 1);
}

function deviceWireMessage(command: string, messageId: string, payload: Record<string, unknown>): DeviceMessage {
  const legacyType = LEGACY_WIRE_TYPES[command];
  if (!legacyType) return { type: 'command', messageId, command: WIRE_COMMANDS[command] ?? command, payload };
  const taskSetId = String(payload.taskSetId ?? payload.task_set_id ?? '');
  return {
    type: legacyType,
    msgId: 0,
    content: command === COMMANDS.uninstallApp ? `REMOTE_UNINSTALL_APPLICATION|${taskSetId}` : '',
    messageId,
    command: WIRE_COMMANDS[command] ?? command,
    payload
  };
}

async function markDevice(deviceId: string, online: boolean, patch: Record<string, unknown> = {}) {
  await query(
    `UPDATE devices SET online=$2, last_seen_at=now(), updated_at=now(),
      last_heartbeat_at=COALESCE($3::timestamptz, last_heartbeat_at),
      battery=COALESCE($4::integer, battery), network_type=COALESCE($5::varchar, network_type),
      client_version=COALESCE($6::varchar, client_version), metadata=COALESCE($7::jsonb, metadata),
      step_count=COALESCE($8::integer, step_count),
      current_app_package=COALESCE($9::varchar, current_app_package),
      current_app_name=COALESCE($10::varchar, current_app_name),
      current_app_started_at=COALESCE($11::timestamptz, current_app_started_at),
      control_status=COALESCE($12::varchar, control_status),
      permissions=COALESCE($13::jsonb, permissions),
      device_owner_enabled=COALESCE($14::boolean, device_owner_enabled),
      device_owner_package=COALESCE($15::varchar, device_owner_package),
      dpm_api_level=COALESCE($16::integer, dpm_api_level),
      dpm_restrictions=COALESCE($17::jsonb, dpm_restrictions),
      dpm_last_sync_at=COALESCE($18::timestamptz, dpm_last_sync_at)
     WHERE id=$1`,
    [deviceId, online, patch.lastHeartbeatAt ?? null, patch.battery ?? null, patch.networkType ?? null, patch.clientVersion ?? null,
      patch.metadata ? JSON.stringify(patch.metadata) : null, patch.stepCount ?? patch.steps ?? null,
      patch.currentAppPackage ?? patch.current_app_package ?? null, patch.currentAppName ?? patch.current_app_name ?? null,
      patch.currentAppStartedAt ?? patch.current_app_started_at ?? null, patch.controlStatus ?? patch.control_status ?? null,
      patch.permissions ? JSON.stringify(patch.permissions) : null,
      patch.deviceOwnerEnabled ?? patch.device_owner_enabled ?? null,
      patch.deviceOwnerPackage ?? patch.device_owner_package ?? null,
      patch.dpmApiLevel ?? patch.dpm_api_level ?? null,
      patch.dpmRestrictions ? JSON.stringify(patch.dpmRestrictions) : null,
      patch.dpmLastSyncAt ?? patch.dpm_last_sync_at ?? null]
  );
}

async function recordDeviceEvent(deviceId: string, eventType: string, payload: Record<string, unknown>) {
  const device = await query<{ child_id: string }>('SELECT child_id FROM devices WHERE id=$1', [deviceId]);
  if (!device.rows[0]) return;
  await query('INSERT INTO device_events(device_id,child_id,event_type,payload) VALUES ($1,$2,$3,$4::jsonb)', [deviceId, device.rows[0].child_id, eventType, JSON.stringify(payload)]);
}

function normalizeLocationPayload(value: unknown): JsonRecord {
  // The vendor client posts location points as a one-item array. The generic
  // message normalizer treats arrays as app lists, so unwrap location-shaped
  // array entries before looking at the usual object wrappers.
  const rawCandidates: unknown[] = [value];
  if (Array.isArray(value)) rawCandidates.push(...value);
  const initialObjects = rawCandidates.filter((item): item is JsonRecord => Boolean(item && typeof item === 'object' && !Array.isArray(item)));
  for (const item of initialObjects) {
    for (const key of ['location', 'locationInfo', 'locationData', 'data', 'list', 'locations', 'locationList']) {
      const nested = item[key];
      if (Array.isArray(nested)) rawCandidates.push(...nested);
      else if (nested && typeof nested === 'object') rawCandidates.push(nested);
    }
  }
  const root = normalizeMessagePayload(value);
  const candidates = [root, ...rawCandidates]
    .filter((item): item is JsonRecord => Boolean(item && typeof item === 'object' && !Array.isArray(item)));
  const selected = candidates.find((item) => nonEmpty(item.lat, item.latitude) !== null && nonEmpty(item.lng, item.longitude, item.lon) !== null) ?? root;
  return { ...root, ...selected };
}

async function storeInstalledApps(deviceId: string, messageType: string, value: unknown) {
  const apps = extractAppItems(value);
  for (const item of apps) {
    const packageName = String(nonEmpty(item.packageName, item.package_name, item.appPackageName, item.package, item.pkg) ?? '').trim();
    if (!packageName) continue;
    const appId = String(nonEmpty(item.appId, item.app_id, item.id, packageName) ?? packageName);
    await query(
      `INSERT INTO installed_apps(device_id,app_id,package_name,app_name,version_name,version_code,icon_url,is_system,last_seen_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,COALESCE($8,false),now())
       ON CONFLICT(device_id,package_name) DO UPDATE SET app_id=EXCLUDED.app_id,app_name=EXCLUDED.app_name,version_name=EXCLUDED.version_name,version_code=EXCLUDED.version_code,icon_url=EXCLUDED.icon_url,is_system=EXCLUDED.is_system,last_seen_at=now()`,
      [deviceId, appId, packageName, String(nonEmpty(item.appName, item.app_name, item.name, packageName)), nonEmpty(item.versionName, item.version_name, item.version), String(nonEmpty(item.versionCode, item.version_code, '') ?? ''), nonEmpty(item.iconUrl, item.icon_url, item.icon, item.iconBase64), item.isSystem ?? item.is_system ?? item.systemApp ?? false]
    );
  }
  await query('UPDATE devices SET last_apps_sync_at=now(),last_seen_at=now(),online=true,updated_at=now() WHERE id=$1', [deviceId]);
  await recordDeviceEvent(deviceId, messageType, { count: apps.length });
  return apps.length;
}

async function flushQueuedCommands(deviceId: string) {
  const pending = await query<{ id: string; command: string; payload: Record<string, unknown> }>(`SELECT id,command,payload FROM commands WHERE device_id=$1 AND status='queued' AND (expires_at IS NULL OR expires_at>now()) ORDER BY created_at LIMIT 50`, [deviceId]);
  for (const item of pending.rows) {
    const sent = broadcastToDevice(deviceId, deviceWireMessage(item.command, item.id, item.payload));
    if (sent) await query(`UPDATE commands SET status='sent',attempts=attempts+1,sent_at=now(),updated_at=now() WHERE id=$1`, [item.id]);
  }
}

async function handleDeviceMessage(deviceId: string, message: DeviceMessage) {
  const payload = message.payload ?? message.result ?? {};
  if (message.type === 'heartbeat' || message.type === 'device_heartbeat' || message.type === 'HEARTBEAT') {
    await markDevice(deviceId, true, { lastHeartbeatAt: new Date().toISOString(), ...payload, battery: payload.battery ?? payload.batteryLevel, networkType: payload.networkType ?? payload.network_type, clientVersion: payload.clientVersion ?? payload.client_version });
    await flushQueuedCommands(deviceId);
    await recordDeviceEvent(deviceId, message.type, payload);
    return;
  }
  if (message.type === 'device_info' || message.type === 'CHILD_UPDATE_DEVICE') {
    await markDevice(deviceId, true, { ...payload, battery: payload.battery ?? payload.batteryLevel, networkType: payload.networkType ?? payload.network_type, clientVersion: payload.clientVersion ?? payload.client_version });
    if (extractAppItems(payload).length > 0) await storeInstalledApps(deviceId, message.type, payload);
    await recordDeviceEvent(deviceId, message.type, payload);
    return;
  }
  if (message.type === 'battery' || message.type === 'BATTERY_CHANGE') {
    await markDevice(deviceId, true, { battery: payload.battery ?? payload.batteryLevel, lastHeartbeatAt: new Date().toISOString() });
    await recordDeviceEvent(deviceId, message.type, payload);
    return;
  }
  if (message.type === 'step' || message.type === 'steps' || message.type === 'STEP_CHANGE' || message.type === 'CHILD_UPDATE_STEP') {
    const steps = Number(payload.steps ?? payload.stepCount ?? payload.count);
    if (Number.isFinite(steps) && steps >= 0) {
      const device = await query<{ child_id: string }>('SELECT child_id FROM devices WHERE id=$1', [deviceId]);
      await markDevice(deviceId, true, { stepCount: Math.floor(steps), lastHeartbeatAt: new Date().toISOString() });
      if (device.rows[0]) await query('INSERT INTO step_records(device_id,child_id,steps,recorded_at,day) VALUES ($1,$2,$3,COALESCE($4::timestamptz,now()),COALESCE(($4::timestamptz)::date,current_date))', [deviceId, device.rows[0].child_id, Math.floor(steps), payload.recordedAt ?? null]);
    }
    await recordDeviceEvent(deviceId, message.type, payload);
    return;
  }
  if (message.type === 'current_app' || message.type === 'foreground_app' || message.type === 'CHILD_CURRENT_APP') {
    await markDevice(deviceId, true, { currentAppPackage: payload.packageName ?? payload.package_name, currentAppName: payload.appName ?? payload.app_name, currentAppStartedAt: payload.startedAt ?? payload.startTime, lastHeartbeatAt: new Date().toISOString() });
    await recordDeviceEvent(deviceId, message.type, payload);
    return;
  }
  if (message.type === 'permission_status' || message.type === 'permissions' || message.type === 'CHILD_CONTROL_STATUS_CHANGE') {
    await markDevice(deviceId, true, { permissions: payload.permissions ?? payload, controlStatus: payload.controlStatus ?? payload.status, lastHeartbeatAt: new Date().toISOString() });
    await recordDeviceEvent(deviceId, message.type, payload);
    return;
  }
  if (message.type === 'device_owner_status' || message.type === 'dpm_status' || message.type === 'DEVICE_OWNER_STATUS') {
    await markDevice(deviceId, true, {
      deviceOwnerEnabled: payload.deviceOwnerEnabled ?? payload.isDeviceOwner ?? payload.device_owner_enabled,
      deviceOwnerPackage: payload.deviceOwnerPackage ?? payload.adminPackage ?? payload.device_owner_package,
      dpmApiLevel: payload.apiLevel ?? payload.dpmApiLevel ?? payload.dpm_api_level,
      dpmRestrictions: payload.restrictions ?? payload.dpmRestrictions ?? payload.dpm_restrictions ?? {},
      dpmLastSyncAt: payload.updatedAt ?? new Date().toISOString(),
      controlStatus: payload.controlStatus ?? payload.status,
      permissions: payload.permissions ?? payload,
      lastHeartbeatAt: new Date().toISOString()
    });
    await recordDeviceEvent(deviceId, message.type, payload);
    return;
  }
  if (message.type === 'location' || message.type === 'location_upload' || message.type === 'CHILD_LOCATION_CHANGE') {
    const location = normalizeLocationPayload(payload);
    const lat = Number(nonEmpty(location.latitude, location.lat));
    const lng = Number(nonEmpty(location.longitude, location.lng, location.lon));
    if (Number.isFinite(lat) && Number.isFinite(lng)) {
      const device = await query<{ child_id: string }>('SELECT child_id FROM devices WHERE id=$1', [deviceId]);
      const directAddress = nonEmpty(location.address, location.addressDetails, location.locationMsg, location.location_message);
      const geocoded = directAddress ? { address: String(directAddress), city: String(nonEmpty(location.city) ?? '') || null, details: String(nonEmpty(location.addressDetails) ?? '') || null } : await reverseGeocode(lat, lng);
      const recordedAt = safeTimestamp(nonEmpty(location.recordedAt, location.recorded_at, location.pointTime, location.point_time, location.timestamp));
      if (device.rows[0]) await query(
        `INSERT INTO location_records(device_id, child_id, latitude, longitude, accuracy, address, address_details, city, location_msg, recorded_at, source)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,COALESCE($10::timestamptz,now()),$11)`,
        [deviceId, device.rows[0].child_id, lat, lng, nonEmpty(location.accuracy, location.radius), geocoded.address, geocoded.details, geocoded.city, nonEmpty(location.locationMsg, location.location_msg), recordedAt, nonEmpty(location.source, location.provider, location.gpsStatus) ?? 'device']
      );
      await query('UPDATE devices SET last_location_at=COALESCE($2::timestamptz,now()),last_seen_at=now(),online=true,updated_at=now() WHERE id=$1', [deviceId, recordedAt]);
    }
    await recordDeviceEvent(deviceId, message.type, location);
    return;
  }
  if (message.type === 'usage' || message.type === 'usage_upload' || message.type === 'CHILD_UPLOAD_APP_USE_TIME' || message.type === 'CHILD_UPDATE_APP_USE_TIME') {
    const device = await query<{ child_id: string }>('SELECT child_id FROM devices WHERE id=$1', [deviceId]);
    const items = Array.isArray(payload.items) ? payload.items : [payload];
    if (device.rows[0]) for (const item of items) {
      if (!item.packageName && !item.package_name) continue;
      const start = item.startedAt ?? item.startTime ?? new Date().toISOString();
      const seconds = Number(item.useSeconds ?? item.useTime ?? item.duration ?? 0);
      await query(
        `INSERT INTO usage_records(device_id, child_id, package_name, app_name, started_at, ended_at, use_seconds, day)
         VALUES ($1,$2,$3,$4,$5::timestamptz,($5::timestamptz + ($6::integer * interval '1 second')),$6,($5::timestamptz)::date)`,
        [deviceId, device.rows[0].child_id, item.packageName ?? item.package_name, item.appName ?? item.app_name ?? null, start, seconds]
      );
    }
    await query('UPDATE devices SET last_usage_sync_at=now(),last_seen_at=now(),online=true,updated_at=now() WHERE id=$1', [deviceId]);
    await recordDeviceEvent(deviceId, message.type, payload);
    return;
  }
  if (message.type === 'apps' || message.type === 'apps_upload' || message.type === 'CHILD_APP_SYSTEM_LIST' || message.type === 'app_list' || message.type === 'CHILD_UPDATE_DEVICE') {
    await storeInstalledApps(deviceId, message.type, payload);
    return;
  }
  if (message.type === 'REMOTE_UNINSTALL_APPLICATION_DONE' || message.type === 'command_result' || message.type === 'control_result' || message.status) {
    const messageId = message.messageId ?? String(payload.messageId ?? payload.commandId ?? '');
    const taskSetId = String(payload.taskSetId ?? payload.task_set_id ?? '');
    if (!messageId && !taskSetId) return;
    const explicitFailure = payload.success === false || ['failed', 'failure', 'error'].includes(String(message.status ?? payload.status ?? '').toLowerCase());
    const finalStatus = !explicitFailure && (message.type === 'REMOTE_UNINSTALL_APPLICATION_DONE' || payload.success === true || ['success', 'succeeded', 'ok', 'completed'].includes(String(message.status ?? payload.status ?? '').toLowerCase())) ? 'succeeded' : 'failed';
    if (messageId) await query(
      `UPDATE commands SET status=$2, result=$3::jsonb, acknowledged_at=now(), updated_at=now()
       WHERE id=$1`,
      [messageId, finalStatus, JSON.stringify(message.result ?? payload)]
    );
    const tasks = await query<{ package_name: string }>(`UPDATE delete_tasks SET status=$2,result=$3::jsonb,completed_at=now() WHERE ($1<>'' AND command_id::text=$1) OR ($4<>'' AND task_set_id::text=$4) RETURNING package_name`, [messageId || '', finalStatus, JSON.stringify(message.result ?? payload), taskSetId || '']);
    if (finalStatus === 'succeeded' && tasks.rows.length > 0) {
      await query(`DELETE FROM installed_apps WHERE device_id=$1 AND package_name = ANY($2::text[])`, [deviceId, tasks.rows.map((item) => item.package_name)]);
    }
    await recordDeviceEvent(deviceId, String(message.type), { messageId, taskSetId, status: finalStatus, ...(message.result ?? payload) });
  }
}

async function authOrNull(app: FastifyInstance, request: any) {
  try { return await getAuthUser(app, request); } catch { return null; }
}

async function readJsonFile(filePath: string, fallback: unknown) {
  try { return JSON.parse(await readFile(filePath, 'utf8')); } catch { return fallback; }
}

async function writeJsonFile(filePath: string, value: unknown) {
  await mkdir(path.dirname(filePath), { recursive: true });
  const temporary = `${filePath}.${process.pid}.tmp`;
  await writeFile(temporary, JSON.stringify(value, null, 2), { encoding: 'utf8', mode: 0o600 });
  await rename(temporary, filePath);
}

function compareVersions(current: string, latest: string) {
  const parse = (value: string) => value.replace(/^v/, '').split('-')[0].split('.').slice(0, 3).map((item) => Number.parseInt(item, 10) || 0);
  const a = parse(current); const b = parse(latest);
  for (let i = 0; i < 3; i += 1) { if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1; }
  return 0;
}

async function adminChild(childId: string) {
  const result = await query<{ id: string; family_id: string; device_id: string | null; online: boolean | null }>(`SELECT c.id,c.family_id,d.id AS device_id,d.online FROM children c LEFT JOIN LATERAL (SELECT id,online FROM devices WHERE child_id=c.id ORDER BY updated_at DESC LIMIT 1) d ON true WHERE c.id=$1 AND c.active=true`, [childId]);
  return result.rows[0] ?? null;
}

async function dispatchAdminCommand(childId: string, command: string, payload: Record<string, unknown>, username: string) {
  if (!COMMAND_SET.has(command)) throw new Error('command is not allowed');
  const child = await adminChild(childId);
  if (!child?.device_id) return null;
  const commandId = randomUUID();
  const online = isDeviceOnline(child.device_id);
  const status = online ? 'sent' : 'queued';
  await query(`INSERT INTO commands(id,device_id,child_id,command,payload,status,attempts,sent_at,expires_at) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,now()+interval '24 hours')`, [commandId, child.device_id, childId, command, JSON.stringify(payload), status, online ? 1 : 0, online ? new Date().toISOString() : null]);
  let delivered = false;
  if (online) {
    delivered = broadcastToDevice(child.device_id, deviceWireMessage(command, commandId, payload));
    if (!delivered) await query(`UPDATE commands SET status='queued',attempts=0,sent_at=NULL,updated_at=now() WHERE id=$1`, [commandId]);
  }
  await query('INSERT INTO admin_audit_logs(username,action,family_id,child_id,device_id,detail) VALUES ($1,$2,$3,$4,$5,$6::jsonb)', [username, `command:${command}`, child.family_id, childId, child.device_id, JSON.stringify({ commandId, payload, status: delivered ? 'sent' : status })]);
  return { commandId, deviceId: child.device_id, status: delivered ? 'sent' : status, delivered };
}

export async function registerRoutes(app: FastifyInstance) {
  app.get('/health', async () => ({ ok: true, service: 'guardian-backend', time: new Date().toISOString() }));
  app.get('/api/health', async () => ({ ok: true, service: 'guardian-backend', time: new Date().toISOString() }));

  app.post('/api/v1/admin/auth/login', async (request: any, reply) => {
    const body = request.body ?? {};
    const username = String(body.username ?? '').trim();
    const password = String(body.password ?? '');
    const validUser = username === config.adminUsername;
    const validPassword = config.adminPasswordHash
      ? await verifyPassword(password, config.adminPasswordHash)
      : config.nodeEnv !== 'production' && password === config.adminPassword;
    if (!validUser || !validPassword) return reply.code(401).send({ message: '管理员账号或密码错误' });
    const token = await issueAdminToken(app, username);
    return { data: { token, accessToken: token, username, role: 'admin' }, token };
  });

  app.get('/api/v1/admin/auth/me', async (request: any, reply) => {
    try { return { data: await getAdminUser(app, request) }; } catch { return reply.code(401).send({ message: '管理员登录已失效' }); }
  });

  const requireAdmin = async (request: any, reply: any) => {
    try { return await getAdminUser(app, request); } catch { await reply.code(401).send({ message: '需要管理员登录' }); return null; }
  };

  app.get('/api/v1/admin/overview', async (request: any, reply) => {
    const admin = await requireAdmin(request, reply); if (!admin) return;
    const [counts, devices, events] = await Promise.all([
      query(`SELECT (SELECT count(*) FROM families)::int AS families,(SELECT count(*) FROM users)::int AS parents,(SELECT count(*) FROM children WHERE active=true)::int AS children,(SELECT count(*) FROM devices)::int AS devices,(SELECT count(*) FROM devices WHERE online=true)::int AS online_devices,(SELECT count(*) FROM devices WHERE online=false)::int AS offline_devices`),
      query(`SELECT d.id AS "deviceId",d.child_id AS "childId",c.name AS "childName",f.id AS "familyId",f.name AS "familyName",d.device_name AS "deviceName",d.brand,d.model,d.android_version AS "androidVersion",d.client_version AS "clientVersion",d.online,d.battery,d.network_type AS "networkType",d.last_heartbeat_at AS "lastHeartbeatAt",d.last_seen_at AS "lastSeenAt",d.step_count AS "stepCount",d.current_app_package AS "currentAppPackage",d.current_app_name AS "currentAppName",d.control_status AS "controlStatus",d.permissions,d.device_owner_enabled AS "deviceOwnerEnabled",d.device_owner_package AS "deviceOwnerPackage",d.dpm_api_level AS "dpmApiLevel",d.dpm_restrictions AS "dpmRestrictions",d.dpm_last_sync_at AS "dpmLastSyncAt",d.last_location_at AS "lastLocationAt",d.last_usage_sync_at AS "lastUsageSyncAt",d.last_apps_sync_at AS "lastAppsSyncAt" FROM devices d JOIN children c ON c.id=d.child_id JOIN families f ON f.id=c.family_id ORDER BY d.online DESC,d.last_seen_at DESC NULLS LAST LIMIT 200`),
      query(`SELECT id,event_type AS "eventType",payload,created_at AS "createdAt" FROM device_events ORDER BY created_at DESC LIMIT 20`)
    ]);
    return { data: { ...(counts.rows[0] ?? {}), devices: devices.rows, recentEvents: events.rows, checkedAt: new Date().toISOString(), admin: admin.username } };
  });

  app.get('/api/v1/admin/families', async (request: any, reply) => {
    if (!await requireAdmin(request, reply)) return;
    const q = request.query ?? {};
    const result = await query(`SELECT f.id AS "familyId",f.name AS "familyName",f.created_at AS "createdAt",u.id AS "parentId",u.phone,u.display_name AS "displayName",(SELECT count(*) FROM children c WHERE c.family_id=f.id AND c.active=true)::int AS "childCount",(SELECT count(*) FROM devices d JOIN children c ON c.id=d.child_id WHERE c.family_id=f.id AND d.online=true)::int AS "onlineDevices",COALESCE(e.enabled,false) AS "membershipEnabled",e.expires_at AS "membershipExpiresAt",(COALESCE(e.enabled,false) AND (e.expires_at IS NULL OR e.expires_at>now())) AS "membershipActive",e.granted_by AS "membershipGrantedBy",e.updated_at AS "membershipUpdatedAt" FROM families f JOIN users u ON u.id=f.owner_user_id LEFT JOIN parent_entitlements e ON e.family_id=f.id WHERE ($1='' OR f.name ILIKE '%'||$1||'%' OR u.phone ILIKE '%'||$1||'%') ORDER BY f.created_at DESC LIMIT 200`, [String(q.search ?? '')]);
    return { data: result.rows };
  });

  app.get('/api/v1/admin/families/:familyId', async (request: any, reply) => {
    if (!await requireAdmin(request, reply)) return;
    const result = await query(`SELECT f.id AS "familyId",f.name AS "familyName",u.id AS "parentId",u.phone,u.display_name AS "displayName",json_agg(json_build_object('childId',c.id,'name',c.name,'phone',c.phone,'active',c.active,'devices',(SELECT coalesce(json_agg(json_build_object('deviceId',d.id,'deviceName',d.device_name,'brand',d.brand,'model',d.model,'online',d.online,'battery',d.battery,'lastSeenAt',d.last_seen_at,'controlStatus',d.control_status)), '[]'::json) FROM devices d WHERE d.child_id=c.id))) FILTER (WHERE c.id IS NOT NULL) AS children FROM families f JOIN users u ON u.id=f.owner_user_id LEFT JOIN children c ON c.family_id=f.id WHERE f.id=$1 GROUP BY f.id,u.id`, [request.params.familyId]);
    if (!result.rows[0]) return reply.code(404).send({ message: '家庭不存在' });
    return { data: result.rows[0] };
  });

  app.get('/api/v1/admin/families/:familyId/membership', async (request: any, reply) => {
    const admin = await requireAdmin(request, reply); if (!admin) return;
    const result = await query(`SELECT f.id AS "familyId",u.phone,e.enabled,e.expires_at AS "expiresAt",e.granted_by AS "grantedBy",e.updated_at AS "updatedAt" FROM families f JOIN users u ON u.id=f.owner_user_id LEFT JOIN parent_entitlements e ON e.family_id=f.id WHERE f.id=$1`, [request.params.familyId]);
    if (!result.rows[0]) return reply.code(404).send({ message: '家庭不存在' });
    return { data: result.rows[0] };
  });

  app.put('/api/v1/admin/families/:familyId/membership', async (request: any, reply) => {
    const admin = await requireAdmin(request, reply); if (!admin) return;
    const familyId = String(request.params.familyId); const body = request.body ?? {};
    const family = await query('SELECT id FROM families WHERE id=$1', [familyId]);
    if (!family.rows[0]) return reply.code(404).send({ message: '家庭不存在' });
    const enabled = body.enabled !== false;
    let expiresAt: string | null = body.expiresAt ? String(body.expiresAt) : null;
    if (!expiresAt && body.days !== undefined && body.days !== null) {
      const days = Math.max(1, Math.min(36500, Number(body.days) || 0));
      expiresAt = new Date(Date.now() + days * 86400000).toISOString();
    }
    await query(`INSERT INTO parent_entitlements(family_id,enabled,expires_at,granted_by) VALUES($1,$2,$3,$4) ON CONFLICT(family_id) DO UPDATE SET enabled=EXCLUDED.enabled,expires_at=EXCLUDED.expires_at,granted_by=EXCLUDED.granted_by,updated_at=now()`, [familyId, enabled, expiresAt, admin.username]);
    await query('INSERT INTO admin_audit_logs(username,action,family_id,detail) VALUES($1,$2,$3,$4::jsonb)', [admin.username, enabled ? 'membership_granted' : 'membership_revoked', familyId, JSON.stringify({ enabled, expiresAt })]);
    return { data: { familyId, enabled, expiresAt, grantedBy: admin.username } };
  });

  app.post('/api/v1/admin/families/:familyId/bind-code', async (request: any, reply) => {
    if (!await requireAdmin(request, reply)) return;
    return reply.code(403).send({ message: '绑定码只能由家长端打开绑定页面生成' });
  });

  app.get('/api/v1/admin/bind-codes', async (request: any, reply) => {
    if (!await requireAdmin(request, reply)) return;
    const result = await query(`SELECT b.token AS code,b.child_id AS "childId",c.name AS "childName",b.family_id AS "familyId",f.name AS "familyName",b.expires_at AS "expiresAt",b.created_at AS "createdAt" FROM bind_tokens b JOIN families f ON f.id=b.family_id LEFT JOIN children c ON c.id=b.child_id WHERE b.used_at IS NULL AND b.expires_at>now() ORDER BY b.created_at DESC LIMIT 200`);
    return { data: result.rows };
  });

  app.delete('/api/v1/admin/bind-codes/:code', async (request: any, reply) => {
    const admin = await requireAdmin(request, reply); if (!admin) return;
    const code = String(request.params.code ?? '').trim();
    if (!/^\d{6}$/.test(code)) return reply.code(400).send({ message: '绑定码必须是 6 位数字' });
    const removed = await query<{ family_id: string; child_id: string | null }>('DELETE FROM bind_tokens WHERE token=$1 RETURNING family_id,child_id', [code]);
    if (!removed.rows[0]) return reply.code(404).send({ message: '绑定码不存在、已使用或已过期' });
    await query('INSERT INTO admin_audit_logs(username,action,family_id,child_id,detail) VALUES($1,$2,$3,$4,$5::jsonb)', [admin.username, 'bind_code_deleted', removed.rows[0].family_id, removed.rows[0].child_id, JSON.stringify({ code })]);
    return { data: true };
  });

  app.get('/api/v1/admin/children/:childId', async (request: any, reply) => {
    if (!await requireAdmin(request, reply)) return;
    const child = await query(`SELECT c.id AS "childId",c.name,c.phone,c.active,f.id AS "familyId",f.name AS "familyName",u.phone AS "parentPhone",d.id AS "deviceId",d.device_name,d.brand,d.model,d.android_version,d.client_version,d.battery,d.network_type,d.online,d.last_heartbeat_at,d.last_seen_at,d.permissions,d.metadata,d.step_count,d.current_app_package,d.current_app_name,d.current_app_started_at,d.control_status,d.last_location_at,d.last_usage_sync_at,d.last_apps_sync_at,d.device_owner_enabled AS "deviceOwnerEnabled",d.device_owner_package AS "deviceOwnerPackage",d.dpm_api_level AS "dpmApiLevel",d.dpm_restrictions AS "dpmRestrictions",d.dpm_last_sync_at AS "dpmLastSyncAt" FROM children c JOIN families f ON f.id=c.family_id JOIN users u ON u.id=f.owner_user_id LEFT JOIN LATERAL (SELECT * FROM devices WHERE child_id=c.id ORDER BY updated_at DESC LIMIT 1) d ON true WHERE c.id=$1`, [request.params.childId]);
    if (!child.rows[0]) return reply.code(404).send({ message: '孩子不存在' });
    const [policy, settings, periods, apps, location, usage, commands, events] = await Promise.all([
      query('SELECT * FROM control_policies WHERE child_id=$1', [request.params.childId]),
      query('SELECT * FROM child_app_settings WHERE child_id=$1', [request.params.childId]),
      query('SELECT id,name,weekdays,start_time AS "startTime",end_time AS "endTime",mode,daily_limit_seconds AS "dailyLimitSeconds",allowed_packages AS "allowedPackages",priority,enabled,created_at AS "createdAt",updated_at AS "updatedAt" FROM control_periods WHERE child_id=$1 ORDER BY priority,start_time', [request.params.childId]),
      query(`SELECT COALESCE(a.app_id,a.package_name) AS "appId",a.package_name AS "packageName",a.app_name AS "appName",a.version_name AS "versionName",a.version_code AS "versionCode",a.icon_url AS "iconUrl",a.is_system AS "isSystem",a.last_seen_at AS "lastSeenAt",p.policy_type AS "policyType",p.daily_limit_seconds AS "dailyLimitSeconds" FROM installed_apps a LEFT JOIN app_policies p ON p.child_id=$1 AND p.package_name=a.package_name JOIN devices d ON d.id=a.device_id WHERE d.child_id=$1 ORDER BY a.app_name`, [request.params.childId]),
      query(`SELECT latitude,longitude,accuracy,address,address_details AS "addressDetails",city,location_msg AS "locationMsg",recorded_at AS "recordedAt",source FROM location_records WHERE child_id=$1 ORDER BY recorded_at DESC LIMIT 100`, [request.params.childId]),
      query(`SELECT package_name AS "packageName",max(app_name) AS "appName",sum(use_seconds)::int AS "useSeconds",day FROM usage_records WHERE child_id=$1 GROUP BY package_name,day ORDER BY day DESC,"useSeconds" DESC LIMIT 500`, [request.params.childId]),
      query(`SELECT id,command,payload,status,attempts,sent_at AS "sentAt",acknowledged_at AS "acknowledgedAt",result,created_at AS "createdAt" FROM commands WHERE child_id=$1 ORDER BY created_at DESC LIMIT 100`, [request.params.childId]),
      query(`SELECT id,event_type AS "eventType",payload,created_at AS "createdAt" FROM device_events WHERE child_id=$1 ORDER BY created_at DESC LIMIT 100`, [request.params.childId])
    ]);
    return { data: { child: child.rows[0], policy: policy.rows[0] ?? null, settings: settings.rows[0] ?? null, periods: periods.rows, apps: apps.rows, locationHistory: location.rows, usage: usage.rows, commands: commands.rows, events: events.rows } };
  });

  app.get('/api/v1/admin/children/:childId/location/history', async (request: any, reply) => {
    if (!await requireAdmin(request, reply)) return;
    const result = await query(`SELECT latitude,longitude,accuracy,address,address_details AS "addressDetails",city,location_msg AS "locationMsg",recorded_at AS "recordedAt",source FROM location_records WHERE child_id=$1 ORDER BY recorded_at DESC LIMIT 500`, [request.params.childId]);
    return { data: result.rows };
  });
  app.get('/api/v1/admin/children/:childId/usage', async (request: any, reply) => {
    if (!await requireAdmin(request, reply)) return;
    const result = await query(`SELECT package_name AS "packageName",max(app_name) AS "appName",sum(use_seconds)::int AS "useSeconds",day FROM usage_records WHERE child_id=$1 AND day BETWEEN COALESCE($2::date,current_date-30) AND COALESCE($3::date,current_date) GROUP BY package_name,day ORDER BY day DESC,"useSeconds" DESC`, [request.params.childId, request.query?.from ?? null, request.query?.to ?? null]);
    return { data: result.rows };
  });
  app.get('/api/v1/admin/children/:childId/steps', async (request: any, reply) => {
    if (!await requireAdmin(request, reply)) return;
    const result = await query(`SELECT steps,recorded_at AS "recordedAt",day FROM step_records WHERE child_id=$1 ORDER BY recorded_at DESC LIMIT 500`, [request.params.childId]);
    return { data: result.rows };
  });
  app.get('/api/v1/admin/children/:childId/apps', async (request: any, reply) => {
    if (!await requireAdmin(request, reply)) return;
    const result = await query(`SELECT COALESCE(a.app_id,a.package_name) AS "appId",a.package_name AS "packageName",a.app_name AS "appName",a.version_name AS "versionName",a.version_code AS "versionCode",a.icon_url AS "iconUrl",a.is_system AS "isSystem",a.last_seen_at AS "lastSeenAt",p.policy_type AS "policyType",p.daily_limit_seconds AS "dailyLimitSeconds" FROM installed_apps a JOIN devices d ON d.id=a.device_id LEFT JOIN app_policies p ON p.child_id=$1 AND p.package_name=a.package_name WHERE d.child_id=$1 ORDER BY a.app_name`, [request.params.childId]);
    return { data: result.rows };
  });
  app.get('/api/v1/admin/children/:childId/commands', async (request: any, reply) => {
    if (!await requireAdmin(request, reply)) return;
    const result = await query(`SELECT id,command,payload,status,attempts,sent_at AS "sentAt",acknowledged_at AS "acknowledgedAt",result,created_at AS "createdAt" FROM commands WHERE child_id=$1 ORDER BY created_at DESC LIMIT 200`, [request.params.childId]);
    return { data: result.rows };
  });
  app.get('/api/v1/admin/children/:childId/logs', async (request: any, reply) => {
    if (!await requireAdmin(request, reply)) return;
    const result = await query(`SELECT id,event_type AS "eventType",payload,created_at AS "createdAt" FROM device_events WHERE child_id=$1 ORDER BY created_at DESC LIMIT 200`, [request.params.childId]);
    return { data: result.rows };
  });
  app.get('/api/v1/admin/logs', async (request: any, reply) => {
    if (!await requireAdmin(request, reply)) return;
    const result = await query(`SELECT id,username,action,family_id AS "familyId",child_id AS "childId",device_id AS "deviceId",detail,created_at AS "createdAt" FROM admin_audit_logs ORDER BY created_at DESC LIMIT 300`);
    return { data: result.rows };
  });

  app.get('/api/v1/admin/system/version', async (request: any, reply) => {
    if (!await requireAdmin(request, reply)) return;
    const fallback = { currentVersion: config.appVersion, latestVersion: config.appVersion, updateAvailable: false, releaseNotes: '', publishedAt: null, image: config.updateImage };
    if (!config.updateEnabled) return { data: fallback };
    try {
      const response = await fetch(`https://api.github.com/repos/${config.updateRepository}/releases/latest`, { headers: { accept: 'application/vnd.github+json', 'user-agent': 'guardian-backend' } });
      if (!response.ok) return { data: { ...fallback, warning: `GitHub release check failed (${response.status})` } };
      const release: any = await response.json();
      const latestVersion = String(release.tag_name ?? '').replace(/^v/, '') || config.appVersion;
      return { data: { currentVersion: config.appVersion, latestVersion, updateAvailable: compareVersions(config.appVersion, latestVersion) < 0, releaseNotes: release.body ?? '', publishedAt: release.published_at ?? null, image: config.updateImage, releaseUrl: release.html_url ?? null } };
    } catch (error) { return { data: { ...fallback, warning: error instanceof Error ? error.message : 'release check failed' } }; }
  });

  app.get('/api/v1/admin/system/releases', async (request: any, reply) => {
    if (!await requireAdmin(request, reply)) return;
    try {
      const response = await fetch(`https://api.github.com/repos/${config.updateRepository}/releases?per_page=10`, { headers: { accept: 'application/vnd.github+json', 'user-agent': 'guardian-backend' } });
      if (!response.ok) return reply.code(502).send({ message: `release list failed (${response.status})` });
      const releases: any[] = await response.json();
      return { data: releases.filter((item) => !item.draft && !item.prerelease).map((item) => ({ version: String(item.tag_name ?? '').replace(/^v/, ''), name: item.name, releaseNotes: item.body ?? '', publishedAt: item.published_at, url: item.html_url })) };
    } catch (error) { return reply.code(502).send({ message: error instanceof Error ? error.message : 'release list failed' }); }
  });

  app.get('/api/v1/admin/system/update/status', async (request: any, reply) => {
    if (!await requireAdmin(request, reply)) return;
    return { data: await readJsonFile(config.updateStatusPath, { status: 'idle', currentVersion: config.appVersion }) };
  });
  app.post('/api/v1/admin/system/update', async (request: any, reply) => {
    const admin = await requireAdmin(request, reply); if (!admin) return;
    if (!config.updateEnabled) return reply.code(409).send({ message: '后台更新功能已禁用' });
    const current = await readJsonFile(config.updateStatusPath, { status: 'idle' }) as any;
    if (['requested', 'pulling', 'restarting'].includes(String(current.status))) return reply.code(409).send({ message: '已有更新任务正在执行', data: current });
    const version = String((request.body ?? {}).version ?? 'latest').trim();
    const image = version === 'latest' ? config.updateImage : `${config.updateImage.split(':')[0]}:v${version.replace(/^v/, '')}`;
    const requestedAt = new Date().toISOString();
    await writeJsonFile(config.updateRequestPath, { id: randomUUID(), requestedBy: admin.username, version, image, requestedAt });
    await writeJsonFile(config.updateStatusPath, { status: 'requested', message: 'update request queued', version, requestedAt });
    await query('INSERT INTO admin_audit_logs(username,action,detail) VALUES ($1,$2,$3::jsonb)', [admin.username, 'system_update_requested', JSON.stringify({ version })]);
    return { data: { status: 'requested', version } };
  });

  app.post('/api/v1/admin/system/rollback', async (request: any, reply) => {
    const admin = await requireAdmin(request, reply); if (!admin) return;
    if (!config.updateEnabled) return reply.code(409).send({ message: '后台更新功能已禁用' });
    const version = String((request.body ?? {}).version ?? '').trim();
    if (!version) return reply.code(400).send({ message: 'version is required' });
    const requestedAt = new Date().toISOString();
    await writeJsonFile(config.updateRequestPath, { id: randomUUID(), requestedBy: admin.username, version, rollback: true, image: `${config.updateImage.split(':')[0]}:${version.startsWith('v') ? version : `v${version}`}`, requestedAt });
    await writeJsonFile(config.updateStatusPath, { status: 'requested', message: 'rollback request queued', version, requestedAt });
    await query('INSERT INTO admin_audit_logs(username,action,detail) VALUES ($1,$2,$3::jsonb)', [admin.username, 'system_rollback_requested', JSON.stringify({ version })]);
    return { data: { status: 'requested', version, rollback: true } };
  });

  app.post('/api/v1/admin/children/:childId/commands', async (request: any, reply) => {
    const admin = await requireAdmin(request, reply); if (!admin) return;
    const command = String((request.body ?? {}).command ?? '');
    const payload = ((request.body ?? {}).payload ?? {}) as Record<string, unknown>;
    if (!COMMAND_SET.has(command)) return reply.code(400).send({ message: '不允许的设备命令' });
    const result = await dispatchAdminCommand(String(request.params.childId), command, payload, admin.username);
    if (!result) return reply.code(404).send({ message: '孩子或设备不存在' });
    return { data: result };
  });

  app.put('/api/v1/admin/children/:childId/policy', async (request: any, reply) => {
    const admin = await requireAdmin(request, reply); if (!admin) return;
    const childId = String(request.params.childId); const b = request.body ?? {};
    const child = await adminChild(childId); if (!child) return reply.code(404).send({ message: '孩子不存在' });
    await query(`INSERT INTO control_policies(child_id,name,enabled,no_play_enabled,lock_enabled,allow_call,emergency_numbers,no_play_allowed_packages,periods,daily_limit_seconds,timezone) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9::jsonb,$10,$11) ON CONFLICT(child_id) DO UPDATE SET name=EXCLUDED.name,enabled=EXCLUDED.enabled,no_play_enabled=EXCLUDED.no_play_enabled,lock_enabled=EXCLUDED.lock_enabled,allow_call=EXCLUDED.allow_call,emergency_numbers=EXCLUDED.emergency_numbers,no_play_allowed_packages=EXCLUDED.no_play_allowed_packages,periods=EXCLUDED.periods,daily_limit_seconds=EXCLUDED.daily_limit_seconds,timezone=EXCLUDED.timezone,updated_at=now()`, [childId, b.name ?? '默认管控策略', b.enabled ?? true, b.noPlayEnabled ?? false, b.lockEnabled ?? false, b.allowCall ?? true, JSON.stringify(b.emergencyNumbers ?? []), JSON.stringify(b.noPlayAllowedPackages ?? []), JSON.stringify(b.periods ?? []), b.dailyLimitSeconds ?? null, b.timezone ?? 'Asia/Shanghai']);
    await replaceControlPeriods(childId, b.periods);
    const command = await dispatchAdminCommand(childId, COMMANDS.policyUpdate, b, admin.username);
    return { data: { saved: true, command } };
  });
  app.put('/api/v1/admin/children/:childId/app-settings', async (request: any, reply) => {
    const admin = await requireAdmin(request, reply); if (!admin) return;
    const childId = String(request.params.childId); const b = request.body ?? {};
    if (!await adminChild(childId)) return reply.code(404).send({ message: '孩子不存在' });
    await query(`INSERT INTO child_app_settings(child_id,allow_new_apps,offline_mode,location_enabled,automatic_location_enabled,hotspot_enabled,show_app_management,reset_disabled,allow_call,allow_wechat,allow_qq,allow_phone,offline_lock_after_days) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT(child_id) DO UPDATE SET allow_new_apps=EXCLUDED.allow_new_apps,offline_mode=EXCLUDED.offline_mode,location_enabled=EXCLUDED.location_enabled,automatic_location_enabled=EXCLUDED.automatic_location_enabled,hotspot_enabled=EXCLUDED.hotspot_enabled,show_app_management=EXCLUDED.show_app_management,reset_disabled=EXCLUDED.reset_disabled,allow_call=EXCLUDED.allow_call,allow_wechat=EXCLUDED.allow_wechat,allow_qq=EXCLUDED.allow_qq,allow_phone=EXCLUDED.allow_phone,offline_lock_after_days=EXCLUDED.offline_lock_after_days,updated_at=now()`, [childId, b.allowNewApps ?? true, b.offlineMode ?? 'allow', b.locationEnabled ?? true, b.automaticLocationEnabled ?? true, b.hotspotEnabled ?? true, b.showAppManagement ?? true, b.resetDisabled ?? false, b.allowCall ?? true, b.allowWechat ?? true, b.allowQq ?? true, b.allowPhone ?? true, b.offlineLockAfterDays ?? null]);
    const command = await dispatchAdminCommand(childId, COMMANDS.deviceOwnerPolicyUpdate, b, admin.username);
    return { data: { saved: true, command } };
  });
  app.put('/api/v1/admin/children/:childId/app-policies', async (request: any, reply) => {
    const admin = await requireAdmin(request, reply); if (!admin) return;
    const childId = String(request.params.childId); if (!await adminChild(childId)) return reply.code(404).send({ message: '孩子不存在' });
    const items = Array.isArray((request.body ?? {}).items) ? (request.body as any).items : [request.body ?? {}];
    for (const item of items) if (item.packageName) await query(`INSERT INTO app_policies(child_id,package_name,app_name,policy_type,daily_limit_seconds,enabled) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT(child_id,package_name) DO UPDATE SET app_name=EXCLUDED.app_name,policy_type=EXCLUDED.policy_type,daily_limit_seconds=EXCLUDED.daily_limit_seconds,enabled=EXCLUDED.enabled,updated_at=now()`, [childId, item.packageName, item.appName ?? null, Number(item.policyType ?? item.type ?? 1), item.dailyLimitSeconds ?? item.useTime ?? null, item.enabled ?? true]);
    const command = await dispatchAdminCommand(childId, COMMANDS.appPolicyUpdate, { items }, admin.username);
    return { data: { saved: true, command } };
  });
  app.put('/api/v1/admin/children/:childId/functions', async (request: any, reply) => {
    const admin = await requireAdmin(request, reply); if (!admin) return;
    const childId = String(request.params.childId); const b = request.body ?? {};
    if (!await adminChild(childId)) return reply.code(404).send({ message: '孩子不存在' });
    await query(`INSERT INTO child_app_settings(child_id,allow_call,allow_wechat,allow_qq,allow_phone) VALUES ($1,$2,$3,$4,$5) ON CONFLICT(child_id) DO UPDATE SET allow_call=EXCLUDED.allow_call,allow_wechat=EXCLUDED.allow_wechat,allow_qq=EXCLUDED.allow_qq,allow_phone=EXCLUDED.allow_phone,updated_at=now()`, [childId, b.allowCall ?? true, b.allowWechat ?? true, b.allowQq ?? true, b.allowPhone ?? true]);
    const command = await dispatchAdminCommand(childId, COMMANDS.functionPolicyUpdate, b, admin.username);
    return { data: { saved: true, command } };
  });
  app.put('/api/v1/admin/children/:childId/periods', async (request: any, reply) => {
    const admin = await requireAdmin(request, reply); if (!admin) return;
    const childId = String(request.params.childId); const items = Array.isArray((request.body ?? {}).items) ? (request.body as any).items : [];
    if (!await adminChild(childId)) return reply.code(404).send({ message: '孩子不存在' });
    await replaceControlPeriods(childId, items);
    const command = await dispatchAdminCommand(childId, COMMANDS.periodsUpdate, { items }, admin.username);
    return { data: { saved: true, command } };
  });

  for (const [route, command] of [['emergency-numbers', COMMANDS.emergencyNumbersUpdate], ['location-settings', COMMANDS.locationSettingsUpdate], ['hotspot', COMMANDS.hotspotUpdate], ['client-update', COMMANDS.clientUpdate]] as const) {
    app.post(`/api/v1/admin/children/:childId/${route}`, async (request: any, reply) => {
      const admin = await requireAdmin(request, reply); if (!admin) return;
      const result = await dispatchAdminCommand(String(request.params.childId), command, request.body ?? {}, admin.username);
      if (!result) return reply.code(404).send({ message: '孩子或设备不存在' });
      return { data: result };
    });
  }

  for (const [route, command] of [['lock', COMMANDS.lock], ['unlock', COMMANDS.unlock], ['request-location', COMMANDS.requestLocation], ['sync-apps', COMMANDS.syncApps], ['sync-usage', COMMANDS.syncUsage], ['unbind', COMMANDS.unbind]] as const) {
    app.post(`/api/v1/admin/children/:childId/${route}`, async (request: any, reply) => {
      const admin = await requireAdmin(request, reply); if (!admin) return;
      const result = await dispatchAdminCommand(String(request.params.childId), command, request.body ?? {}, admin.username);
      if (!result) return reply.code(404).send({ message: '孩子或设备不存在' });
      return { data: result };
    });
  }
  app.post('/api/v1/admin/children/:childId/uninstall', async (request: any, reply) => {
    const admin = await requireAdmin(request, reply); if (!admin) return;
    const childId = String(request.params.childId); const packageName = String((request.body ?? {}).packageName ?? '');
    if (!packageName) return reply.code(400).send({ message: 'packageName is required' });
    const result = await dispatchAdminCommand(childId, COMMANDS.uninstallApp, { packageName, appName: (request.body ?? {}).appName ?? null }, admin.username);
    if (!result) return reply.code(404).send({ message: '孩子或设备不存在' });
    await query(`INSERT INTO delete_tasks(child_id,device_id,package_name,app_name,status,command_id) VALUES ($1,$2,$3,$4,$5,$6)`, [childId, result.deviceId, packageName, (request.body ?? {}).appName ?? null, result.status, result.commandId]);
    return { data: result };
  });

  app.post('/api/v1/auth/account/sendCaptcha', async (request: any) => {
    const body = request.body ?? {};
    const phone = String(body.phone ?? body.username ?? body.mobile ?? '').trim();
    if (!phone) return { code: 40001, message: '手机号不能为空', data: null };
    const code = config.allowFixedCaptcha ? config.fixedCaptcha : String(Math.floor(100000 + Math.random() * 900000));
    await query(`INSERT INTO captcha_codes(phone,code,expires_at) VALUES ($1,$2,now()+interval '10 minutes') ON CONFLICT(phone) DO UPDATE SET code=EXCLUDED.code,expires_at=EXCLUDED.expires_at`, [phone, code]);
    request.log.info({ phone, fixedCaptcha: config.allowFixedCaptcha }, 'captcha issued');
    return { code: 0, message: '验证码已发送', data: { sent: true, expiresIn: 600, ...(config.allowFixedCaptcha ? { fixedCode: code } : {}) } };
  });

  app.post('/api/v1/auth/account/captchaLogin', async (request: any, reply) => {
    const body = request.body ?? {};
    const phone = String(body.phone ?? body.username ?? body.mobile ?? '').trim();
    const code = String(body.code ?? body.captcha ?? '').trim();
    if (!phone || !code || !(await verifyCaptcha(phone, code, config.allowFixedCaptcha, config.fixedCaptcha))) {
      return reply.code(401).send({ code: 40101, message: '验证码错误或已过期', data: null });
    }
    const record = await ensureUserAndFamily(phone);
    const token = await issueToken(app, { id: record.id, phone: record.phone, familyId: record.family_id });
    return { code: 0, message: '登录成功', data: { token, accessToken: token, userId: record.id, familyId: record.family_id }, token };
  });

  app.get('/api/v1/auth/account/userAgreement', async () => ({ data: { title: '用户协议', content: '请在正式上线前补充用户协议内容。' } }));
  app.get('/api/v1/auth/account/privacyPolicy', async () => ({ data: { title: '隐私政策', content: '请在正式上线前补充隐私政策内容。' } }));

  app.get('/api/v1/parent/user/getUserInfo', async (request: any) => {
    const user = await getAuthUser(app, request);
    const result = await query(`SELECT u.id AS "parentId",u.phone,u.phone AS "userName",COALESCE(NULLIF(u.display_name,''),'家长'||right(u.phone,4)) AS "displayName",COALESCE(NULLIF(u.display_name,''),'家长'||right(u.phone,4)) AS "nickName",u.avatar_url AS "avatarUrl",f.id AS "familyId",f.name AS "familyName",'家长' AS "familyRoleName",COALESCE(e.enabled=false OR (e.expires_at IS NOT NULL AND e.expires_at<=now()),false) AS "membershipExpired",COALESCE(e.enabled,false) AND (e.expires_at IS NULL OR e.expires_at>now()) AS "isVip" FROM users u JOIN families f ON f.owner_user_id=u.id LEFT JOIN parent_entitlements e ON e.family_id=f.id WHERE u.id=$1`, [user.id]);
    return { data: result.rows[0] ?? null };
  });
  app.post('/api/v1/parent/account/replacePhone', async (request: any) => {
    const user = await getAuthUser(app, request); const b = request.body ?? {};
    const phone = String(b.phone ?? b.newPhone ?? '').trim(); const code = String(b.code ?? b.captcha ?? '').trim();
    if (!phone || !code || !(await verifyCaptcha(phone, code, config.allowFixedCaptcha, config.fixedCaptcha))) return { error: '验证码错误或已过期' };
    await query('UPDATE users SET phone=$1,updated_at=now() WHERE id=$2', [phone, user.id]);
    return { data: true };
  });
  app.delete('/api/v1/parent/account/logoff', async (request: any) => {
    const user = await getAuthUser(app, request);
    await query('UPDATE children SET active=false,updated_at=now() WHERE family_id=$1', [user.familyId]);
    await query('DELETE FROM families WHERE id=$1', [user.familyId]);
    await query('DELETE FROM users WHERE id=$1', [user.id]);
    return { data: true };
  });
  app.get('/api/v1/parent/parentActiveCode/list', async (request: any) => {
    const user = await getAuthUser(app, request);
    const [codes, membership] = await Promise.all([
      query(`SELECT id,code,days,used_at AS "usedAt",created_at AS "createdAt",NULL::uuid AS "childId",NULL::varchar AS "childName",CASE WHEN used_by IS NULL THEN 1 ELSE 3 END AS status,NULL::timestamptz AS "expireTime",false AS "isMembership",false AS "isPermanent" FROM parent_active_codes WHERE used_by IS NULL OR used_by=$1 ORDER BY created_at DESC LIMIT 100`, [user.id]),
      query(`SELECT ('membership-'||c.id::text) AS id,('membership-'||c.id::text) AS code,0 AS days,NULL::timestamptz AS "usedAt",e.updated_at AS "createdAt",c.id AS "childId",CASE WHEN e.enabled AND e.expires_at IS NULL THEN COALESCE(NULLIF(c.name,''),'孩子'||right(u.phone,4))||'（永久会员）' WHEN e.enabled AND e.expires_at>now() THEN COALESCE(NULLIF(c.name,''),'孩子'||right(u.phone,4))||'（会员至'||to_char(e.expires_at AT TIME ZONE 'Asia/Shanghai','YYYY-MM-DD')||'）' ELSE COALESCE(NULLIF(c.name,''),'孩子'||right(u.phone,4))||'（会员已过期）' END AS "childName",COALESCE(NULLIF(c.name,''),'孩子'||right(u.phone,4)) AS "originalChildName",CASE WHEN e.enabled AND (e.expires_at IS NULL OR e.expires_at>now()) THEN 3 ELSE 4 END AS status,e.expires_at AS "expireTime",true AS "isMembership",(e.expires_at IS NULL) AS "isPermanent",e.granted_by AS "grantedBy",'会员管控权限' AS "membershipName" FROM parent_entitlements e JOIN families f ON f.id=e.family_id JOIN users u ON u.id=f.owner_user_id JOIN children c ON c.family_id=f.id AND c.active=true WHERE e.family_id=$1 ORDER BY c.created_at`, [user.familyId])
    ]);
    return { data: [...codes.rows, ...membership.rows] };
  });
  app.post('/api/v1/parent/parentActiveCode/use', async (request: any, reply) => {
    const user = await getAuthUser(app, request); const code = String((request.body ?? {}).code ?? '').trim();
    const result = await query(`UPDATE parent_active_codes SET used_by=$1,used_at=now() WHERE code=$2 AND used_by IS NULL RETURNING code,days,used_at AS "usedAt"`, [user.id, code]);
    if (!result.rows[0]) return reply.code(400).send({ message: '激活码无效或已使用' });
    return { data: { activated: true, ...result.rows[0] } };
  });

  app.get('/api/v1/parent/index/childUserList', async (request: any) => {
    const user = await getAuthUser(app, request);
    const result = await query(`SELECT c.id AS "childId",COALESCE(NULLIF(c.name,''),'孩子'||right(u.phone,4)) AS name,COALESCE(NULLIF(c.name,''),'孩子'||right(u.phone,4)) AS "nickName",COALESCE(NULLIF(c.name,''),'孩子'||right(u.phone,4)) AS "childName",c.phone,c.avatar_url AS "avatarUrl",d.id AS "deviceId",d.device_name AS "phoneName",d.brand,COALESCE(d.model,d.brand,d.device_name,'Android') AS model,COALESCE(d.model,d.brand,d.device_name,'Android') AS "phoneModel",d.android_version AS "androidVersion",d.client_version AS "clientVersion",d.online,CASE WHEN COALESCE(d.online,false) THEN 1 ELSE 0 END AS status,CASE WHEN COALESCE(d.online,false) THEN 1 ELSE 0 END AS "onLineStatus",d.battery,COALESCE(d.battery,0) AS "batteryPercent",d.last_seen_at AS "lastSeenAt",COALESCE(e.enabled,false) AND (e.expires_at IS NULL OR e.expires_at>now()) AS "isDeviceVip",COALESCE(e.enabled,false) AND (e.expires_at IS NULL OR e.expires_at>now()) AS "deviceVip" FROM children c JOIN families f ON f.id=c.family_id JOIN users u ON u.id=f.owner_user_id LEFT JOIN parent_entitlements e ON e.family_id=f.id LEFT JOIN LATERAL (SELECT * FROM devices x WHERE x.child_id=c.id ORDER BY x.updated_at DESC LIMIT 1) d ON true WHERE c.family_id=$1 AND c.active=true ORDER BY c.created_at`, [user.familyId]);
    return { data: result.rows };
  });

  app.get('/api/v1/parent/family/parentUserList', async (request: any) => {
    const user = await getAuthUser(app, request);
    const result = await query(`SELECT u.id AS "userId",u.phone,u.display_name AS "displayName",fm.role,fm.created_at AS "createdAt" FROM family_members fm JOIN users u ON u.id=fm.user_id WHERE fm.family_id=$1 ORDER BY fm.created_at`, [user.familyId]);
    return { data: result.rows };
  });
  app.get('/api/v1/parent/family/parentUser/:userId', async (request: any, reply: any) => {
    const user = await getAuthUser(app, request);
    const result = await query(`SELECT u.id AS "userId",u.phone,u.display_name AS "displayName",fm.role,fm.created_at AS "createdAt" FROM family_members fm JOIN users u ON u.id=fm.user_id WHERE fm.family_id=$1 AND u.id=$2`, [user.familyId, request.params.userId]);
    if (!result.rows[0]) return reply.code(404).send({ message: '家庭成员不存在' });
    return { data: result.rows[0] };
  });
  app.post('/api/v1/parent/family/parentUser', async (request: any) => {
    const user = await getAuthUser(app, request); const b = request.body ?? {}; const phone = String(b.phone ?? '').trim();
    if (!phone) return { error: 'phone is required' };
    const member = await ensureUserAndFamily(phone);
    await query('INSERT INTO family_members(family_id,user_id,role) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING', [user.familyId, member.id, b.role ?? 'parent']);
    return { data: { userId: member.id, phone } };
  });
  app.put('/api/v1/parent/family/parentUser', async (request: any) => {
    const user = await getAuthUser(app, request); const b = request.body ?? {};
    await query(`UPDATE users u SET display_name=COALESCE($1,u.display_name) FROM family_members fm WHERE u.id=fm.user_id AND fm.family_id=$2 AND u.id=$3`, [b.displayName ?? b.name ?? null, user.familyId, b.userId]);
    await query('UPDATE family_members SET role=COALESCE($1,role) WHERE family_id=$2 AND user_id=$3', [b.role ?? null, user.familyId, b.userId]);
    return { data: true };
  });
  app.delete('/api/v1/parent/family/quit', async (request: any) => {
    const user = await getAuthUser(app, request); await query('DELETE FROM family_members WHERE family_id=$1 AND user_id=$2', [user.familyId, user.id]); return { data: true };
  });

  app.post('/api/v1/parent/index/getDeviceInfo', async (request: any) => {
    const user = await getAuthUser(app, request); const childId = String((request.body ?? {}).childId ?? '');
    const result = await query(`SELECT d.id AS "deviceId",d.child_id AS "childId",d.device_name AS "deviceName",d.brand,d.model,d.android_version AS "androidVersion",d.client_version AS "clientVersion",d.battery,COALESCE(d.battery,0) AS "batteryPercent",d.network_type AS "networkType",d.online,CASE WHEN COALESCE(d.online,false) THEN 1 ELSE 0 END AS status,CASE WHEN COALESCE(d.online,false) THEN 1 ELSE 0 END AS "onLineStatus",d.last_heartbeat_at AS "lastHeartbeatAt",d.last_seen_at AS "lastSeenAt",d.permissions,d.metadata,d.step_count AS "stepCount",d.current_app_package AS "currentAppPackage",d.current_app_name AS "currentAppName",d.control_status AS "controlStatus",d.last_location_at AS "lastLocationAt",d.last_usage_sync_at AS "lastUsageAt",d.last_apps_sync_at AS "lastAppsSyncAt" FROM devices d JOIN children c ON c.id=d.child_id WHERE d.child_id=$1 AND c.family_id=$2 ORDER BY d.updated_at DESC LIMIT 1`, [childId, user.familyId]);
    return { data: result.rows[0] ?? null };
  });

  app.get('/api/v1/parent/index/getChildNewLocation', async (request: any) => {
    const user = await getAuthUser(app, request); const childId = String((request.query as any)?.childId ?? '');
    const result = await query(`SELECT l.latitude,l.longitude,l.accuracy,l.address,l.address_details AS "addressDetails",l.city,l.location_msg AS "locationMsg",l.recorded_at AS "recordedAt",l.source FROM location_records l JOIN children c ON c.id=l.child_id WHERE l.child_id=$1 AND c.family_id=$2 ORDER BY l.recorded_at DESC LIMIT 1`, [childId, user.familyId]);
    const row: any = result.rows[0];
    if (!row) return { data: { list: [], lastTrailDetail: null }, list: [] };
    const location = { lat: String(row.latitude), lng: String(row.longitude), pointTime: row.recordedAt, createTime: row.recordedAt, address: row.address, addressDetails: row.addressDetails, city: row.city, locationMsg: row.locationMsg, accuracy: row.accuracy, source: row.source };
    return { data: { list: [{ createTime: row.recordedAt, locationList: [location] }], lastTrailDetail: location, ...row }, list: [{ createTime: row.recordedAt, locationList: [location] }] };
  });

  app.get('/api/v1/parent/app/childStatusInfo/:childId', async (request: any) => {
    const user = await getAuthUser(app, request); const childId = request.params.childId;
    const result = await query(`SELECT c.id AS "childId",d.online,CASE WHEN COALESCE(d.online,false) THEN 1 ELSE 0 END AS status,CASE WHEN COALESCE(d.online,false) THEN 1 ELSE 0 END AS "onLineStatus",d.battery,COALESCE(d.battery,0) AS "batteryPercent",d.last_seen_at AS "lastSeenAt",d.client_version AS "clientVersion" FROM children c LEFT JOIN LATERAL (SELECT * FROM devices WHERE child_id=c.id ORDER BY updated_at DESC LIMIT 1) d ON true WHERE c.id=$1 AND c.family_id=$2`, [childId, user.familyId]);
    return { data: result.rows[0] ?? null };
  });
  app.get('/api/v1/parent/app/settings', async (request: any) => {
    const user = await getAuthUser(app, request); const childId = String((request.query as any)?.childId ?? '');
    const result = await query(`SELECT s.* FROM child_app_settings s JOIN children c ON c.id=s.child_id WHERE s.child_id=$1 AND c.family_id=$2`, [childId, user.familyId]);
    return { data: result.rows[0] ?? null };
  });
  app.put('/api/v1/parent/app/settings', async (request: any) => {
    const user = await getAuthUser(app, request); const b = request.body ?? {}; const childId = String(b.childId ?? '');
    const child = await query('SELECT id FROM children WHERE id=$1 AND family_id=$2 AND active=true', [childId, user.familyId]); if (!child.rows[0]) return { error: 'child not found' };
    await query(`INSERT INTO child_app_settings(child_id,allow_new_apps,offline_mode,location_enabled,automatic_location_enabled,hotspot_enabled,show_app_management,reset_disabled,allow_call,allow_wechat,allow_qq,allow_phone,offline_lock_after_days) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT(child_id) DO UPDATE SET allow_new_apps=EXCLUDED.allow_new_apps,offline_mode=EXCLUDED.offline_mode,location_enabled=EXCLUDED.location_enabled,automatic_location_enabled=EXCLUDED.automatic_location_enabled,hotspot_enabled=EXCLUDED.hotspot_enabled,show_app_management=EXCLUDED.show_app_management,reset_disabled=EXCLUDED.reset_disabled,allow_call=EXCLUDED.allow_call,allow_wechat=EXCLUDED.allow_wechat,allow_qq=EXCLUDED.allow_qq,allow_phone=EXCLUDED.allow_phone,offline_lock_after_days=EXCLUDED.offline_lock_after_days,updated_at=now()`, [childId,b.allowNewApps ?? b.allow_new_apps ?? true,b.offlineMode ?? b.offline_mode ?? 'allow',b.locationEnabled ?? b.location_enabled ?? true,b.automaticLocationEnabled ?? b.automatic_location_enabled ?? true,b.hotspotEnabled ?? b.hotspot_enabled ?? true,b.showAppManagement ?? b.show_app_management ?? true,b.resetDisabled ?? b.reset_disabled ?? false,b.allowCall ?? b.allow_call ?? true,b.allowWechat ?? b.allow_wechat ?? true,b.allowQq ?? b.allow_qq ?? true,b.allowPhone ?? b.allow_phone ?? true,b.offlineLockAfterDays ?? b.offline_lock_after_days ?? null]);
    await dispatchPolicy(user.familyId, childId, 'device_owner_policy_update', b); return { data: true };
  });

  app.get('/api/v1/parent/app/childUseAppTimeRankList', async (request: any) => {
    const user = await getAuthUser(app, request); const q = request.query as any; const childId = q.childId;
    const result = await query(`SELECT u.package_name AS "packageName",max(u.app_name) AS "appName",sum(u.use_seconds)::integer AS "useTime" FROM usage_records u JOIN children c ON c.id=u.child_id WHERE u.child_id=$1 AND c.family_id=$2 AND u.day BETWEEN COALESCE($3::date,current_date-30) AND COALESCE($4::date,current_date) GROUP BY u.package_name ORDER BY "useTime" DESC`, [childId, user.familyId, q.beginDateTime ?? null, q.endDateTime ?? null]);
    return { data: result.rows };
  });

  app.get('/api/v1/parent/app/control/:childId', async (request: any) => {
    const user = await getAuthUser(app, request); const childId = request.params.childId;
    // The shipped parent client sends the selected list item back verbatim.
    // It needs both ids to save an app policy correctly.
    const result = await query(`SELECT a.id::text AS id,$1::text AS "childId",COALESCE(a.app_id,a.package_name) AS "appId",a.package_name AS "packageName",a.app_name AS "appName",a.icon_url AS icon,COALESCE(p.policy_type,1) AS type,COALESCE(p.policy_type,1) AS "useStatus",COALESCE(p.daily_limit_seconds,0) AS "useTime" FROM installed_apps a JOIN devices d ON d.id=a.device_id JOIN children c ON c.id=d.child_id LEFT JOIN app_policies p ON p.child_id=c.id AND p.package_name=a.package_name WHERE c.id=$1 AND c.family_id=$2 ORDER BY a.app_name`, [childId, user.familyId]);
    if (result.rows.length === 0) await requestAppsSync(user.familyId, childId);
    return { data: result.rows };
  });
  app.get('/api/v1/parent/childAppSource/childAppSourceList', async (request: any) => {
    const user = await getAuthUser(app, request); const childId = String((request.query as any)?.childId ?? '');
    const result = await query(`SELECT COALESCE(a.app_id,a.package_name) AS "appId",a.package_name AS "packageName",a.app_name AS "appName",a.version_name AS "versionName",a.version_code AS "versionCode",a.icon_url AS "iconUrl",a.icon_url AS icon,a.is_system AS "isSystem",a.last_seen_at AS "lastSeenAt",COALESCE(p.policy_type,1) AS type,COALESCE(p.policy_type,1) AS "useStatus",COALESCE(p.daily_limit_seconds,0) AS "useTime" FROM installed_apps a JOIN devices d ON d.id=a.device_id JOIN children c ON c.id=d.child_id LEFT JOIN app_policies p ON p.child_id=c.id AND p.package_name=a.package_name WHERE c.id=$1 AND c.family_id=$2 ORDER BY a.app_name`, [childId, user.familyId]);
    if (result.rows.length === 0) await requestAppsSync(user.familyId, childId);
    return { data: result.rows };
  });

  app.put('/api/v1/parent/app/control', async (request: any) => {
    const user = await getAuthUser(app, request);
    const body = request.body ?? {};
    const items = Array.isArray(body)
      ? body
      : Array.isArray(body.items)
        ? body.items
        : Array.isArray(body.appList)
          ? body.appList
          : body && typeof body === 'object'
            ? [body]
            : [];
    const defaultChildId = Array.isArray(body) ? undefined : body.childId ?? body.child_id;
    const changed = new Map<string, Record<string, unknown>[]>();

    for (const rawItem of items) {
      const item = rawItem as Record<string, any>;
      let childId = item.childId ?? item.child_id ?? defaultChildId;
      let packageName = item.packageName ?? item.package_name;
      // Older parent builds omit childId in the PUT payload. Resolve the item
      // against an app that belongs to the authenticated family instead of
      // silently reporting success without saving anything.
      if (!childId || !packageName) {
        const appIdentifier = String(item.id ?? item.appId ?? packageName ?? '').trim();
        if (appIdentifier) {
          const matched = await query<{ child_id: string; package_name: string; app_name: string }>(
            `SELECT d.child_id,a.package_name,a.app_name
               FROM installed_apps a
               JOIN devices d ON d.id=a.device_id
               JOIN children c ON c.id=d.child_id
              WHERE c.family_id=$1 AND c.active=true
                AND (a.id::text=$2 OR a.app_id=$2 OR a.package_name=$2)
              ORDER BY a.last_seen_at DESC
              LIMIT 1`,
            [user.familyId, appIdentifier]
          );
          if (matched.rows[0]) {
            childId ??= matched.rows[0].child_id;
            packageName ??= matched.rows[0].package_name;
            item.appName ??= matched.rows[0].app_name;
          }
        }
      }
      if (!childId || !packageName) continue;
      const child = await query('SELECT id FROM children WHERE id=$1 AND family_id=$2 AND active=true', [childId, user.familyId]);
      if (!child.rows[0]) continue;

      const requestedType = Number(item.type ?? item.policyType ?? item.useStatus ?? 1);
      const policyType = requestedType === 2 || requestedType === 3 ? requestedType : 1;
      const requestedLimit = item.useTime ?? item.dailyLimitSeconds ?? item.daily_limit_seconds ?? item.limitTime;
      const dailyLimitSeconds = policyType === 2 && Number.isFinite(Number(requestedLimit))
        ? Math.max(0, Math.floor(Number(requestedLimit)))
        : null;
      const policy = { packageName, appName: item.appName ?? null, type: policyType, useTime: dailyLimitSeconds };
      await query(`INSERT INTO app_policies(child_id,package_name,app_name,policy_type,daily_limit_seconds) VALUES ($1,$2,$3,$4,$5) ON CONFLICT(child_id,package_name) DO UPDATE SET app_name=EXCLUDED.app_name,policy_type=EXCLUDED.policy_type,daily_limit_seconds=EXCLUDED.daily_limit_seconds,updated_at=now()`, [childId, packageName, policy.appName, policyType, dailyLimitSeconds]);
      const childPolicies = changed.get(String(childId)) ?? [];
      childPolicies.push(policy);
      changed.set(String(childId), childPolicies);
    }

    for (const [childId, changedPolicies] of changed) {
      await dispatchPolicy(user.familyId, childId, COMMANDS.appPolicyUpdate, { items: changedPolicies });
    }
    return { data: { saved: Array.from(changed.values()).reduce((total, policies) => total + policies.length, 0) } };
  });
  app.get('/api/v1/parent/app/appFunctionControl', async (request: any) => {
    const user = await getAuthUser(app, request); const childId = String((request.query as any)?.childId ?? '');
    const result = await query('SELECT allow_call,allow_wechat,allow_qq,allow_phone FROM child_app_settings s JOIN children c ON c.id=s.child_id WHERE s.child_id=$1 AND c.family_id=$2', [childId, user.familyId]);
    const settings = result.rows[0] ?? { allow_call: true, allow_wechat: true, allow_qq: true, allow_phone: true };
    return { data: [
      { appId: 'wechat', appName: '微信功能', useStatus: settings.allow_wechat === false ? 1 : 0 },
      { appId: 'qq', appName: 'QQ功能', useStatus: settings.allow_qq === false ? 1 : 0 },
      { appId: 'phone', appName: '电话功能', useStatus: settings.allow_phone === false ? 1 : 0 },
      { appId: 'call', appName: '通话功能', useStatus: settings.allow_call === false ? 1 : 0 }
    ] };
  });
  app.put('/api/v1/parent/app/appFunctionControl', async (request: any) => {
    const user = await getAuthUser(app, request); const b = request.body ?? {}; const childId = String(b.childId ?? '');
    const child = await query('SELECT id FROM children WHERE id=$1 AND family_id=$2 AND active=true', [childId, user.familyId]); if (!child.rows[0]) return { error: 'child not found' };
    const items = Array.isArray(b.updateChildAppSystemUseStatusList) ? b.updateChildAppSystemUseStatusList : [];
    const itemValue = (names: string[], fallback: unknown) => {
      const item = items.find((x: any) => names.includes(String(x.appId ?? x.app_id ?? x.functionCode ?? '').toLowerCase()));
      return item ? Number(item.useStatus ?? item.status ?? 0) !== 1 : fallback;
    };
    const allowWechat = b.allowWechat ?? b.allow_wechat ?? itemValue(['wechat', '2'], true);
    const allowQq = b.allowQq ?? b.allow_qq ?? itemValue(['qq', '1'], true);
    const allowPhone = b.allowPhone ?? b.allow_phone ?? itemValue(['phone', '3'], true);
    const allowCall = b.allowCall ?? b.allow_call ?? itemValue(['call', '4'], true);
    await query(`INSERT INTO child_app_settings(child_id,allow_call,allow_wechat,allow_qq,allow_phone) VALUES ($1,$2,$3,$4,$5) ON CONFLICT(child_id) DO UPDATE SET allow_call=EXCLUDED.allow_call,allow_wechat=EXCLUDED.allow_wechat,allow_qq=EXCLUDED.allow_qq,allow_phone=EXCLUDED.allow_phone,updated_at=now()`, [childId,allowCall,allowWechat,allowQq,allowPhone]);
    for (const item of items) if (item.appId ?? item.app_id) await query(`INSERT INTO app_function_policies(child_id,package_name,function_code,disabled) VALUES ($1,$2,$3,$4) ON CONFLICT(child_id,package_name,function_code) DO UPDATE SET disabled=EXCLUDED.disabled,updated_at=now()`, [childId, String(item.appId ?? item.app_id), String(item.functionCode ?? 'legacy'), Number(item.useStatus ?? item.status ?? 0) === 1]);
    await dispatchPolicy(user.familyId, childId, 'function_policy_update', b); return { data: true };
  });

  app.get('/api/v1/parent/controlPolicy/getControlListByChildId/:childId', async (request: any) => {
    const user = await getAuthUser(app, request); const result = await query(`SELECT p.* FROM control_policies p JOIN children c ON c.id=p.child_id WHERE p.child_id=$1 AND c.family_id=$2`, [request.params.childId, user.familyId]);
    return { data: result.rows[0] ?? null };
  });

  app.put('/api/v1/parent/controlPolicy/setControlPolicy', async (request: any) => {
    const user = await getAuthUser(app, request); const b = request.body ?? {};
    const childId = b.childId; if (!childId) return { error: 'childId is required' };
    const child = await query('SELECT id FROM children WHERE id=$1 AND family_id=$2 AND active=true', [childId, user.familyId]); if (!child.rows[0]) return { error: 'child not found' };
    await query(`INSERT INTO control_policies(child_id,name,enabled,no_play_enabled,lock_enabled,allow_call,emergency_numbers,no_play_allowed_packages,periods,daily_limit_seconds,timezone) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9::jsonb,$10,$11) ON CONFLICT(child_id) DO UPDATE SET name=EXCLUDED.name,enabled=EXCLUDED.enabled,no_play_enabled=EXCLUDED.no_play_enabled,lock_enabled=EXCLUDED.lock_enabled,allow_call=EXCLUDED.allow_call,emergency_numbers=EXCLUDED.emergency_numbers,no_play_allowed_packages=EXCLUDED.no_play_allowed_packages,periods=EXCLUDED.periods,daily_limit_seconds=EXCLUDED.daily_limit_seconds,timezone=EXCLUDED.timezone,updated_at=now()`, [childId,b.name ?? '默认管控策略',b.enabled ?? true,b.noPlayEnabled ?? b.no_play_enabled ?? false,b.lockEnabled ?? b.lock_enabled ?? false,b.allowCall ?? true,JSON.stringify(b.emergencyNumbers ?? []),JSON.stringify(b.noPlayAllowedPackages ?? b.no_play_allowed_packages ?? []),JSON.stringify(b.periods ?? []),b.dailyLimitSeconds ?? null,b.timezone ?? 'Asia/Shanghai']);
    await replaceControlPeriods(String(childId), b.periods);
    await dispatchPolicy(user.familyId, String(childId), 'policy_update', b); return { data: true };
  });
  app.delete('/api/v1/parent/controlPolicy/removeControlPolicy', async (request: any) => {
    const user = await getAuthUser(app, request); const childId = String((request.body ?? {}).childId ?? (request.query as any)?.childId ?? '');
    await query('DELETE FROM control_policies p USING children c WHERE p.child_id=$1 AND c.id=p.child_id AND c.family_id=$2', [childId, user.familyId]);
    await dispatchPolicy(user.familyId, childId, 'unlock', {}); return { data: true };
  });
  app.get('/api/v1/parent/controlPolicy/periods', async (request: any) => {
    const user = await getAuthUser(app, request); const childId = String((request.query as any)?.childId ?? '');
    const result = await query(`SELECT p.* FROM control_periods p JOIN children c ON c.id=p.child_id WHERE p.child_id=$1 AND c.family_id=$2 ORDER BY p.priority,p.start_time`, [childId, user.familyId]); return { data: result.rows };
  });
  app.put('/api/v1/parent/controlPolicy/periods', async (request: any) => {
    const user = await getAuthUser(app, request); const b = request.body ?? {}; const childId = String(b.childId ?? ''); const items = Array.isArray(b.items) ? b.items : [];
    await replaceControlPeriods(childId, items);
    await dispatchPolicy(user.familyId, childId, 'periods_update', { items }); return { data: true };
  });

  app.get('/api/v1/parent/account/getBindQrcode', async (request: any) => {
    const user = await getAuthUser(app, request);
    const requestedChildId = String((request.query as any)?.childId ?? '').trim();
    let childId = requestedChildId;
    if (childId) {
      const child = await query<{ id: string }>('SELECT id FROM children WHERE id=$1 AND family_id=$2 AND active=true', [childId, user.familyId]);
      if (!child.rows[0]) childId = '';
    }

    // The bind page can request the code twice during its lifecycle. Reuse one
    // active code so opening the page does not create duplicate children/codes.
    const active = childId
      ? await query<{ token: string; child_id: string; expires_at: string }>(
        `SELECT b.token,b.child_id,b.expires_at FROM bind_tokens b JOIN children c ON c.id=b.child_id WHERE b.family_id=$1 AND b.used_at IS NULL AND b.expires_at>now() AND b.child_id=$2::uuid ORDER BY b.created_at DESC LIMIT 1`,
        [user.familyId, childId]
      )
      : await query<{ token: string; child_id: string; expires_at: string }>(
        `SELECT b.token,b.child_id,b.expires_at FROM bind_tokens b JOIN children c ON c.id=b.child_id WHERE b.family_id=$1 AND b.used_at IS NULL AND b.expires_at>now() ORDER BY b.created_at DESC LIMIT 1`,
        [user.familyId]
      );
    let token = active.rows[0]?.token ?? '';
    let expiresAt = active.rows[0]?.expires_at ?? '';
    if (active.rows[0]) childId = active.rows[0].child_id;
    if (!token) {
      for (let attempt = 0; attempt < 20; attempt += 1) {
        const candidate = String(Math.floor(100000 + Math.random() * 900000));
        const exists = await query('SELECT 1 FROM bind_tokens WHERE token=$1 AND expires_at>now()', [candidate]);
        if (!exists.rows[0]) { token = candidate; break; }
      }
      if (!token) throw new Error('暂时无法生成绑定码，请重试');
      if (!childId) {
        const child = await query<{ id: string }>('INSERT INTO children(family_id,name) VALUES ($1,$2) RETURNING id', [user.familyId, '孩子']);
        childId = child.rows[0].id;
      }
      const created = await query<{ expires_at: string }>(`INSERT INTO bind_tokens(token,family_id,child_id,expires_at) VALUES ($1,$2,$3,now()+interval '10 minutes') RETURNING expires_at`, [token,user.familyId,childId]);
      expiresAt = created.rows[0].expires_at;
    }
    const url = `guardian://bind?childId=${encodeURIComponent(childId)}&code=${token}`;
    const remaining = Math.max(1, Math.ceil((new Date(expiresAt).getTime() - Date.now()) / 1000));
    return { code: 0, data: { code: token, bindCode: token, childId, url, content: url, expiresIn: remaining, expiresAt } };
  });

  const removeDevice = async (request: any) => { const user = await getAuthUser(app, request); const b=request.body??{}; const childId=String(b.childId ?? (request.query as any)?.childId ?? ''); await query(`DELETE FROM devices d USING children c WHERE d.child_id=$1 AND c.id=d.child_id AND c.family_id=$2`,[childId,user.familyId]); return {data:true}; };
  app.delete('/api/v1/parent/user/removeDevice', removeDevice); app.get('/api/v1/parent/user/removeDevice', removeDevice);
  const updateChild = async (request: any) => { const user=await getAuthUser(app,request);const b=request.body??{}; await query(`UPDATE children c SET name=COALESCE($3,c.name),phone=COALESCE($4,c.phone),updated_at=now() FROM families f WHERE c.id=$1 AND c.family_id=f.id AND f.id=$2`,[b.childId,user.familyId,b.name,b.phone]); return {data:true}; };
  app.put('/api/v1/parent/user/updateChild', updateChild); app.post('/api/v1/parent/user/updateChild', updateChild);

  app.post('/api/v1/parent/app/deletetask', async (request: any, reply) => {
    const user = await getAuthUser(app, request); const b = firstObject(request.body); const childId = String(b.childId ?? '');
    const requestedIds = splitIds(b.appIds ?? b.appId ?? b.packageNames ?? b.packageName ?? b.package_name);
    if (!childId || requestedIds.length === 0) return reply.code(400).send({ message: 'childId and appIds are required' });
    const child = await query<{ id: string; device_id: string | null }>('SELECT c.id,d.id AS device_id FROM children c LEFT JOIN LATERAL (SELECT id FROM devices WHERE child_id=c.id ORDER BY updated_at DESC LIMIT 1) d ON true WHERE c.id=$1 AND c.family_id=$2', [childId, user.familyId]); if (!child.rows[0]) return reply.code(404).send({ message: 'child not found' });
    const installed = await query<{ app_id: string | null; package_name: string; app_name: string | null }>(`SELECT a.app_id,a.package_name,a.app_name FROM installed_apps a JOIN devices d ON d.id=a.device_id WHERE d.child_id=$1`, [childId]);
    const resolved = requestedIds.map((id) => installed.rows.find((item) => item.app_id === id || item.package_name === id) ?? { app_id: id, package_name: id, app_name: null });
    const taskSetId = randomUUID();
    const tasks: any[] = [];
    for (const item of resolved) {
      const packageName = item.package_name;
      const task = await query(`INSERT INTO delete_tasks(task_set_id,child_id,device_id,package_name,app_name,status,requested_by) VALUES ($1,$2,$3,$4,$5,'queued',$6) RETURNING id,status,requested_at AS "requestedAt"`, [taskSetId, childId, child.rows[0].device_id, packageName, item.app_name ?? b.appName ?? null, user.id]);
      tasks.push(task.rows[0]);
    }
    // The legacy child receives one task-set notification, fetches the full
    // list, then performs each uninstall locally with its policy controller.
    const commandPayload = { appIds: requestedIds.join(','), packageNames: resolved.map((item) => item.package_name), taskSetId };
    const commandId = await dispatchPolicy(user.familyId, childId, COMMANDS.uninstallApp, commandPayload);
    await query(`UPDATE delete_tasks SET command_id=$2,status=$3 WHERE task_set_id=$1`, [taskSetId, commandId, commandId ? 'queued' : 'failed']);
    for (const task of tasks) { task.commandId=commandId; task.status=commandId?'queued':'failed'; }
    // The original parent APK treats the response body as the task-set id string.
    return { data: taskSetId, taskSetId, tasks };
  });
  app.get('/api/v1/parent/app/deletetask/task', async (request: any) => {
    const user = await getAuthUser(app, request); const q = request.query as any; const childId = String(q?.childId ?? ''); const taskSetId = String(q?.taskSetId ?? q?.taskId ?? '');
    const result = await query(`SELECT t.id,t.task_set_id AS "taskSetId",t.package_name AS "packageName",t.app_name AS "appName",t.status,t.command_id AS "commandId",t.result,t.requested_at AS "requestedAt",t.completed_at AS "completedAt" FROM delete_tasks t JOIN children c ON c.id=t.child_id WHERE t.child_id=$1 AND c.family_id=$2 AND ($3='' OR t.task_set_id::text=$3 OR t.id::text=$3) ORDER BY t.requested_at DESC LIMIT 100`, [childId, user.familyId, taskSetId]);
    const rows = result.rows as any[];
    if (taskSetId && rows.length > 0 && rows.every((row) => row.status === 'succeeded')) return { data: null };
    return { data: taskSetId ? (rows[0] ?? null) : rows };
  });
  app.get('/api/v1/parent/app/getLatestAppVersion', async () => ({ data: { version: config.appVersion, versionName: config.appVersion, downloadUrl: null, forceUpdate: false } }));
  app.get('/api/v1/parent/application/getReleaseVersion', async () => ({ data: { version: config.appVersion, versionName: config.appVersion, downloadUrl: null } }));
  app.post('/api/v1/parent/device/operationLog', async (request: any) => { const user=await getAuthUser(app,request); const b=request.body??{}; await query('INSERT INTO operation_logs(family_id,user_id,child_id,device_id,action,detail) VALUES ($1,$2,$3,$4,$5,$6::jsonb)',[user.familyId,user.id,b.childId??null,b.deviceId??null,String(b.action??'parent_operation'),JSON.stringify(b)]); return {data:true}; });
  app.post('/api/v1/parent/device/systemLog', async (request: any) => { const user=await getAuthUser(app,request); const b=request.body??{}; await query('INSERT INTO operation_logs(family_id,user_id,child_id,device_id,action,detail) VALUES ($1,$2,$3,$4,$5,$6::jsonb)',[user.familyId,user.id,b.childId??null,b.deviceId??null,'system_log',JSON.stringify(b)]); return {data:true}; });

  app.post('/api/v1/device/register', async (request: any, reply) => {
    const b=request.body??{}; const bindToken=String(b.bindToken??b.bindCode??''); const token=String(b.deviceToken??b.token??randomUUID());
    const found=await query<{child_id:string;family_id:string}>('SELECT child_id,family_id FROM bind_tokens WHERE token=$1 AND used_at IS NULL AND expires_at>now()',[bindToken]);
    if(!found.rows[0]) return reply.code(400).send({message:'绑定码无效或已过期'});
    const row=await query<{id:string}>('INSERT INTO devices(child_id,device_token_hash,device_name,brand,model,android_version,client_version,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb) RETURNING id',[found.rows[0].child_id,hashToken(token),b.deviceName??null,b.brand??null,b.model??null,b.androidVersion??null,b.clientVersion??null,JSON.stringify(b.metadata??{})]);
    await query(`UPDATE children c SET name='孩子'||right(u.phone,4),updated_at=now() FROM families f JOIN users u ON u.id=f.owner_user_id WHERE c.id=$1 AND c.family_id=f.id AND (c.name IS NULL OR trim(c.name)='' OR c.name='孩子')`, [found.rows[0].child_id]);
    await query('UPDATE bind_tokens SET used_at=now() WHERE token=$1',[bindToken]);
    // The original child APK parses the credential as `data.token` and stores
    // `data.deviceId`. Keep the newer aliases as well for our own clients.
    return {code:0,data:{deviceId:row.rows[0].id,token,deviceToken:token,childId:found.rows[0].child_id,childType:0,expires_in:0}};
  });

  app.post('/api/v1/device/bind', async (request:any,reply)=>app.inject({method:'POST',url:'/api/v1/device/register',payload:request.body}).then(r=>reply.code(r.statusCode).send(r.json())));
  app.post('/api/v1/device/heartbeat', async (request:any,reply)=>{const device=await findDevice(request);if(!device)return reply.code(401).send({message:'device unauthorized'});await markDevice(device.id,true,{lastHeartbeatAt:new Date().toISOString(),...(request.body??{})});return {data:{ok:true}};});
  app.post('/api/v1/device/uploadLocation', async (request:any,reply)=>{const device=await findDevice(request);if(!device)return reply.code(401).send({message:'device unauthorized'});await handleDeviceMessage(device.id,{type:'location',payload:request.body??{}});return {data:{ok:true}};});
  app.post('/api/v1/device/uploadUsage', async (request:any,reply)=>{const device=await findDevice(request);if(!device)return reply.code(401).send({message:'device unauthorized'});await handleDeviceMessage(device.id,{type:'usage',payload:request.body??{}});return {data:{ok:true}};});
  app.post('/api/v1/device/uploadApps', async (request:any,reply)=>{const device=await findDevice(request);if(!device)return reply.code(401).send({message:'device unauthorized'});await handleDeviceMessage(device.id,{type:'apps',payload:request.body??{}});return {data:{ok:true}};});

  const childDevice = async (request: any, reply: any) => { const device = await findDevice(request); if (!device) { await reply.code(401).send({ message: 'device unauthorized' }); return null; } return device; };
  app.post('/api/v1/child/childUser/bindChild', async (request: any, reply: any) => { const b=request.body??{}; const bindToken=String(b.bindToken??b.bindCode??b.code??''); const token=String(b.deviceToken??b.token??randomUUID()); const found=await query<{child_id:string}>('SELECT child_id FROM bind_tokens WHERE token=$1 AND used_at IS NULL AND expires_at>now()',[bindToken]); if(!found.rows[0])return reply.code(400).send({message:'绑定码无效或已过期'}); const row=await query<{id:string}>('INSERT INTO devices(child_id,device_token_hash,device_name,brand,model,android_version,client_version,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb) RETURNING id',[found.rows[0].child_id,hashToken(token),b.deviceName??null,b.brand??null,b.model??null,b.androidVersion??null,b.clientVersion??null,JSON.stringify(b.metadata??{})]); await query(`UPDATE children c SET name='孩子'||right(u.phone,4),updated_at=now() FROM families f JOIN users u ON u.id=f.owner_user_id WHERE c.id=$1 AND c.family_id=f.id AND (c.name IS NULL OR trim(c.name)='' OR c.name='孩子')`, [found.rows[0].child_id]); await query('UPDATE bind_tokens SET used_at=now() WHERE token=$1',[bindToken]); return {code:0,data:{deviceId:row.rows[0].id,token,deviceToken:token,childId:found.rows[0].child_id,childType:0,expires_in:0}}; });
  app.get('/api/v1/child/childUser/getChildToken', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; return {data:{deviceId:device.id,childId:device.child_id}}; });
  app.get('/api/v1/child/childUser/getChildInfo', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const result=await query(`SELECT c.id AS "childId",c.name,c.phone,c.family_id AS "familyId" FROM children c WHERE c.id=$1`,[device.child_id]); return {data:result.rows[0]??null}; });
  app.get('/api/v1/child/childUser/get/:id', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const result=await query(`SELECT c.id AS "childId",c.name,c.phone,c.avatar_url AS "avatarUrl",c.family_id AS "familyId" FROM children c WHERE c.id=$1 AND c.id=$2`,[device.child_id,request.params.id]); return {data:result.rows[0]??null}; });
  app.get('/api/v1/child/childUser/parent', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const result=await query(`SELECT u.id AS "parentId",u.phone,u.display_name AS "displayName",f.id AS "familyId",f.name AS "familyName" FROM children c JOIN families f ON f.id=c.family_id JOIN users u ON u.id=f.owner_user_id WHERE c.id=$1`,[device.child_id]); return {data:result.rows[0]??null}; });
  app.get('/api/v1/child/childUser/schoolChildDetail', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const result=await query(`SELECT c.id AS "childId",c.name,c.phone,c.avatar_url AS "avatarUrl" FROM children c WHERE c.id=$1`,[device.child_id]); return {data:result.rows[0]??null}; });
  app.put('/api/v1/child/childUser/updateChildInfo', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const b=request.body??{}; await query('UPDATE children SET name=COALESCE($2,name),phone=COALESCE($3,phone),updated_at=now() WHERE id=$1',[device.child_id,b.name??b.nickName??null,b.phone??null]); return {data:true}; });
  app.post('/api/v1/child/childUser/unBind', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; await query('DELETE FROM devices WHERE id=$1',[device.id]); return {data:true}; });
  app.post('/api/v1/child/childUser/changeChildPolicyInfo', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const b=request.body??{}; await query(`INSERT INTO control_policies(child_id,name,enabled,no_play_enabled,lock_enabled,allow_call,emergency_numbers,periods,daily_limit_seconds,timezone) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9,$10) ON CONFLICT(child_id) DO UPDATE SET enabled=EXCLUDED.enabled,no_play_enabled=EXCLUDED.no_play_enabled,lock_enabled=EXCLUDED.lock_enabled,allow_call=EXCLUDED.allow_call,emergency_numbers=EXCLUDED.emergency_numbers,periods=EXCLUDED.periods,daily_limit_seconds=EXCLUDED.daily_limit_seconds,timezone=EXCLUDED.timezone,updated_at=now()`,[device.child_id,b.name??'默认管控策略',b.enabled??true,b.noPlayEnabled??false,b.lockEnabled??false,b.allowCall??true,JSON.stringify(b.emergencyNumbers??[]),JSON.stringify(b.periods??[]),b.dailyLimitSeconds??null,b.timezone??'Asia/Shanghai']); return {data:true}; });
  app.get('/api/v1/child/childUser/getChildStatus', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const result=await query(`SELECT online,battery,network_type AS "networkType",last_seen_at AS "lastSeenAt",control_status AS "controlStatus",device_owner_enabled AS "deviceOwnerEnabled",dpm_restrictions AS "dpmRestrictions" FROM devices WHERE id=$1`,[device.id]); return {data:result.rows[0]??null}; });
  app.post('/api/v1/child/childUser/heartBeat', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; await markDevice(device.id,true,{lastHeartbeatAt:new Date().toISOString(),...(request.body??{})}); return {data:{ok:true}}; });
  app.post('/api/v1/child/mobile/uploadDeviceInfo', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; await markDevice(device.id,true,request.body??{}); return {data:{ok:true}}; });
  const updateBatteryPercent = async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const body=request.body??{}; const queryParams=request.query??{}; const raw=body.battery ?? body.batteryPercent ?? queryParams.battery ?? queryParams.batteryPercent; const battery=Number(raw); await markDevice(device.id,true,{battery:Number.isFinite(battery)?Math.max(0,Math.min(100,battery)):null}); return {data:{ok:true}}; };
  app.post('/api/v1/child/mobile/updateBatteryPercent', updateBatteryPercent);
  // The original child APK uses GET with batteryPercent as a query parameter.
  app.get('/api/v1/child/mobile/updateBatteryPercent', updateBatteryPercent);
  app.get('/api/v1/child/controlPolicy/getControlList', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const result=await query('SELECT * FROM control_policies WHERE child_id=$1',[device.child_id]); return {data:result.rows}; });
  app.get('/api/v1/child/controlPolicy/getPolicylistByChildId', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const result=await query('SELECT * FROM control_policies WHERE child_id=$1',[device.child_id]); return {data:result.rows}; });
  app.get('/api/v1/child/controlPolicy/getLocateStatus', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const result=await query('SELECT location_enabled AS "locationEnabled",automatic_location_enabled AS "automaticLocationEnabled" FROM child_app_settings WHERE child_id=$1',[device.child_id]); return {data:result.rows[0]??{locationEnabled:true,automaticLocationEnabled:true}}; });
  app.get('/api/v1/child/controlPolicy/getCallNumberListByChildId', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const result=await query('SELECT emergency_numbers AS "emergencyNumbers" FROM control_policies WHERE child_id=$1',[device.child_id]); return {data:result.rows[0]?.emergencyNumbers??[]}; });
  app.get('/api/v1/child/software/appcontrol', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const result=await query(`SELECT package_name AS "packageName",app_name AS "appName",policy_type AS type,daily_limit_seconds AS "useTime" FROM app_policies WHERE child_id=$1 ORDER BY app_name`,[device.child_id]); return {data:result.rows}; });
  app.post('/api/v1/child/software/appcontrol', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const items=Array.isArray((request.body??{}).items)?(request.body??{}).items:[request.body??{}]; for(const item of items) if(item.packageName) await query(`INSERT INTO app_policies(child_id,package_name,app_name,policy_type,daily_limit_seconds) VALUES ($1,$2,$3,$4,$5) ON CONFLICT(child_id,package_name) DO UPDATE SET policy_type=EXCLUDED.policy_type,daily_limit_seconds=EXCLUDED.daily_limit_seconds,updated_at=now()`,[device.child_id,item.packageName,item.appName??null,Number(item.type??item.policyType??1),item.useTime??item.dailyLimitSeconds??null]); return {data:true}; });
  app.get('/api/v1/child/software/getTimeList', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const result=await query('SELECT * FROM control_periods WHERE child_id=$1 AND enabled=true ORDER BY priority,start_time',[device.child_id]); return {data:result.rows}; });
  app.get('/api/v1/child/software/offLineList', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const result=await query('SELECT offline_mode AS "offlineMode",offline_lock_after_days AS "offlineLockAfterDays" FROM child_app_settings WHERE child_id=$1',[device.child_id]); return {data:result.rows[0]??{offlineMode:'allow'}}; });
  app.get('/api/v1/child/software/getUseTimeData', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const result=await query(`SELECT package_name AS "packageName",max(app_name) AS "appName",sum(use_seconds)::int AS "useTime",day FROM usage_records WHERE child_id=$1 GROUP BY package_name,day ORDER BY day DESC,"useTime" DESC LIMIT 500`,[device.child_id]); return {data:result.rows}; });
  app.get('/api/v1/child/software/verifyApp', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const packageName=String((request.query as any)?.packageName??''); const result=await query('SELECT policy_type AS type,daily_limit_seconds AS "useTime" FROM app_policies WHERE child_id=$1 AND package_name=$2',[device.child_id,packageName]); return {data:result.rows[0]??{type:1,useTime:0}}; });
  // CoreService posts its complete launcher list here on startup. The earlier
  // implementation exposed only the GET lookup and returned 404 for this
  // POST, so the parent application never received any installed apps.
  app.post('/api/v1/child/software/verifyApp', async (request: any, reply: any) => {
    const device=await childDevice(request,reply); if(!device)return;
    const count=await storeInstalledApps(device.id,'verify_app',request.body??{});
    return {code:0,data:{ok:true,count}};
  });
  app.post('/api/v1/child/software/unloadApp', async (request: any, reply: any) => {
    const device=await childDevice(request,reply); if(!device)return;
    const b=firstObject(request.body); const packageName=String(nonEmpty(b.packageName,b.package_name,b.package,b.pkg)??'').trim();
    if (packageName) {
      await query('DELETE FROM installed_apps WHERE device_id=$1 AND package_name=$2',[device.id,packageName]);
      await query(`UPDATE delete_tasks SET status='succeeded',result=$3::jsonb,completed_at=now() WHERE device_id=$1 AND package_name=$2 AND status IN ('queued','sent')`,[device.id,packageName,JSON.stringify({source:'child_unload_app',...b})]);
    }
    await recordDeviceEvent(device.id,'child_unload_app',b); return {code:0,data:{ok:true}};
  });
  app.post('/api/v1/child/software/uploadAppIcon', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const count=await storeInstalledApps(device.id,'child_upload_app_icon',request.body??{}); return {code:0,data:{ok:true,count}}; });
  app.post('/api/v1/child/software/appFunctionControl', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const b=request.body??{}; await query(`INSERT INTO child_app_settings(child_id,allow_call,allow_wechat,allow_qq,allow_phone) VALUES ($1,$2,$3,$4,$5) ON CONFLICT(child_id) DO UPDATE SET allow_call=EXCLUDED.allow_call,allow_wechat=EXCLUDED.allow_wechat,allow_qq=EXCLUDED.allow_qq,allow_phone=EXCLUDED.allow_phone,updated_at=now()`,[device.child_id,b.allowCall??true,b.allowWechat??true,b.allowQq??true,b.allowPhone??true]); return {data:true}; });
  app.post('/api/v1/child/software/uploadApp', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; await handleDeviceMessage(device.id,{type:'apps',payload:request.body??{}}); return {data:{ok:true}}; });
  app.post('/api/v1/child/software/uploadAppTime', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; await handleDeviceMessage(device.id,{type:'usage',payload:request.body??{}}); return {data:{ok:true}}; });
  app.post('/api/v1/child/software/usingApp', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; await handleDeviceMessage(device.id,{type:'current_app',payload:request.body??{}}); return {data:{ok:true}}; });
  app.get('/api/v1/child/software/getRankingChildInfo', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const result=await query(`SELECT package_name AS "packageName",max(app_name) AS "appName",sum(use_seconds)::int AS "useTime" FROM usage_records WHERE child_id=$1 GROUP BY package_name ORDER BY "useTime" DESC LIMIT 100`,[device.child_id]); return {data:result.rows}; });
  app.get('/api/v1/child/software/rankingList', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const result=await query(`SELECT package_name AS "packageName",max(app_name) AS "appName",sum(use_seconds)::int AS "useTime" FROM usage_records WHERE child_id=$1 GROUP BY package_name ORDER BY "useTime" DESC LIMIT 100`,[device.child_id]); return {data:result.rows}; });
  app.post('/api/v1/child/track/uploadLocation', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; await handleDeviceMessage(device.id,{type:'location',payload:request.body??{}}); return {data:{ok:true}}; });
  app.post('/api/v1/child/track/updateStepCount', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; await handleDeviceMessage(device.id,{type:'steps',payload:request.body??{}}); return {data:{ok:true}}; });
  app.get('/api/v1/child/appsettings', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const result=await query('SELECT * FROM child_app_settings WHERE child_id=$1',[device.child_id]); return {data:result.rows[0]??null}; });
  app.get('/api/v1/child/software/getLatestAppVersion', async () => ({data:{version:config.appVersion,versionName:config.appVersion,downloadUrl:null,forceUpdate:false}}));
  const childDeleteTaskSet = async (request: any, reply: any) => {
    const device=await childDevice(request,reply); if(!device)return;
    const taskSetId=String(request.params.id);
    const result=await query(`SELECT task_set_id AS "taskSetId",package_name AS "packageName",app_name AS "appName"
      FROM delete_tasks WHERE task_set_id::text=$1 AND child_id=$2 AND status IN ('queued','sent') ORDER BY requested_at`,[taskSetId,device.child_id]);
    if (request.method === 'DELETE') {
      await recordDeviceEvent(device.id,'child_delete_taskset_ack',{taskSetId,count:result.rows.length});
      return {code:0,data:true};
    }
    const data={childId:device.child_id,taskSetId,appList:result.rows.map((item:any)=>({appId:item.packageName,...item}))};
    // The original client calls JSONObject.getString("data") before Gson.
    return {code:0,data:JSON.stringify(data)};
  };
  app.get('/api/v1/child/deletetask/taskset/:id', childDeleteTaskSet);
  app.delete('/api/v1/child/deletetask/taskset/:id', childDeleteTaskSet);
  const childStatusInfo = async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const b=request.body??{}; if (request.method === 'POST' && (b.status || b.controlStatus)) await markDevice(device.id,true,{controlStatus:b.status??b.controlStatus}); const requestedId = request.params?.id ? String(request.params.id) : null; const result=await query('SELECT online,battery,network_type AS "networkType",last_seen_at AS "lastSeenAt",control_status AS "controlStatus" FROM devices WHERE id=$1 AND ($2 IS NULL OR id::text=$2)',[device.id,requestedId]); return {data:result.rows[0]??null}; };
  app.get('/api/v1/child/changeChildStatusInfo/:id', childStatusInfo); app.post('/api/v1/child/changeChildStatusInfo/:id', childStatusInfo);
  app.get('/api/v1/child/changeChildStatusInfo', childStatusInfo); app.post('/api/v1/child/changeChildStatusInfo', childStatusInfo);
  app.post('/api/v1/child/childActiveCode/claim', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const code=String((request.body??{}).code??(request.body??{}).activeCode??'').trim(); if(!code)return reply.code(400).send({message:'激活码不能为空'}); const owner=await query<{id:string}>('SELECT f.owner_user_id AS id FROM devices d JOIN children c ON c.id=d.child_id JOIN families f ON f.id=c.family_id WHERE d.id=$1',[device.id]); const result=await query(`UPDATE parent_active_codes SET used_by=$1,used_at=now() WHERE code=$2 AND used_by IS NULL RETURNING code,days,used_at AS "usedAt"`,[owner.rows[0]?.id??null,code]); if(!result.rows[0])return reply.code(400).send({message:'激活码无效或已使用'}); return {data:{activated:true,...result.rows[0]}}; });
  app.get('/api/v1/child/childActiveCode/device/getByUniqueCode', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; const code=String((request.query as any)?.code??(request.query as any)?.uniqueCode??'').trim(); const result=await query('SELECT code,days,used_at AS "usedAt" FROM parent_active_codes WHERE code=$1',[code]); return {data:result.rows[0]??null}; });
  const childPushMessage = async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; await recordDeviceEvent(device.id,'child_push_message',request.body??{}); return {code:0,data:{ok:true}}; };
  app.post('/api/v1/child/common/pushMessage', childPushMessage);
  app.put('/api/v1/child/common/pushMessage', childPushMessage);
  app.post('/api/v1/child/common/upload', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; await recordDeviceEvent(device.id,'child_common_upload',request.body??{}); return {data:{ok:true}}; });
  const childDownload = async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; return {data:{version:config.appVersion,downloadUrl:null}}; };
  app.get('/api/v1/child/common/childDownload', childDownload); app.post('/api/v1/child/common/childDownload', childDownload);
  app.post('/api/v1/child/mobile/tempContent', async (request: any, reply: any) => { const device=await childDevice(request,reply); if(!device)return; await recordDeviceEvent(device.id,'child_temp_content',request.body??{}); return {data:{ok:true}}; });

  app.get('/ws', { websocket: true }, (socket: any, request: any) => {
    let deviceId = '';
    // The vendor child client authenticates the WebSocket with the raw token
    // in the Authorization header and does not send a hello frame.
    void (async () => {
      try {
        const device = await findDevice(request);
        if (device) {
          deviceId = device.id;
          deviceSockets.set(deviceId, socket);
          await markDevice(deviceId, true, { lastHeartbeatAt: new Date().toISOString() });
          await flushQueuedCommands(deviceId);
        }
      } catch (error) {
        request.log.warn({ error }, 'legacy device websocket authentication failed');
      }
    })();
    socket.on('message', async (raw: Buffer) => {
      try {
        const text = raw.toString();
        // The original APK sends the literal Chinese heartbeat string every
        // ten seconds. Treat it as a heartbeat after header authentication.
        if (text === '心跳包' || text === 'heartbeat' || text === 'HEARTBEAT') {
          if (deviceId) await handleDeviceMessage(deviceId, { type: 'heartbeat', payload: {} });
          return;
        }
        const message = JSON.parse(text) as DeviceMessage;
        if (!deviceId && (message.type === 'device_hello' || message.type === 'hello' || message.type === 'register')) {
          const token = String((message.payload ?? {}).token ?? message.payload?.deviceToken ?? message.deviceId ?? '');
          const byId = message.deviceId ? await query<{id:string;device_token_hash:string}>('SELECT id,device_token_hash FROM devices WHERE id=$1',[message.deviceId]) : {rows:[]};
          const device = byId.rows[0] && hashToken(token) === byId.rows[0].device_token_hash ? byId.rows[0] : null;
          if (!device) { socket.close(4001, 'unauthorized'); return; }
          deviceId = device.id; deviceSockets.set(deviceId, socket); await markDevice(deviceId,true,{lastHeartbeatAt:new Date().toISOString(),clientVersion:(message.payload??{}).clientVersion});
          await flushQueuedCommands(deviceId);
          socket.send(JSON.stringify({type:'hello_ack',status:'success',deviceId})); return;
        }
        if (!deviceId) { socket.close(4001, 'hello required'); return; }
        await handleDeviceMessage(deviceId, message);
      } catch (error) { request.log.warn({error}, 'invalid device websocket message'); }
    });
    socket.on('close', async () => { if(deviceId){deviceSockets.delete(deviceId);await markDevice(deviceId,false);} });
    socket.on('error', () => { if(deviceId) deviceSockets.delete(deviceId); });
  });
}

async function findDevice(request:any) {
  const auth = String(request.headers.authorization ?? ''); const queryParams = request.query ?? {}; const body = request.body ?? {};
  const supplied = auth.replace(/^Bearer\s+/i,'') || String(body.deviceToken ?? body.token ?? queryParams.deviceToken ?? queryParams.token ?? request.headers['x-device-token'] ?? '');
  const deviceId = String(body.deviceId ?? queryParams.deviceId ?? request.headers['x-device-id'] ?? '');
  if(!supplied) return null;
  const result = deviceId
    ? await query<{id:string;child_id:string}>('SELECT d.id,d.child_id FROM devices d JOIN children c ON c.id=d.child_id WHERE d.id=$1 AND d.device_token_hash=$2',[deviceId,hashToken(supplied)])
    : await query<{id:string;child_id:string}>('SELECT d.id,d.child_id FROM devices d JOIN children c ON c.id=d.child_id WHERE d.device_token_hash=$1 LIMIT 1',[hashToken(supplied)]);
  return result.rows[0]??null;
}

async function dispatchPolicy(familyId:string, childId:string, command:string, payload:Record<string,unknown>) {
  const device = await query<{ id: string }>('SELECT d.id FROM devices d JOIN children c ON c.id=d.child_id WHERE c.id=$1 AND c.family_id=$2 ORDER BY d.updated_at DESC LIMIT 1', [childId, familyId]);
  if (!device.rows[0]) return null;
  const id = randomUUID();
  const online = isDeviceOnline(device.rows[0].id);
  await query(`INSERT INTO commands(id,device_id,child_id,command,payload,status,attempts,expires_at) VALUES($1,$2,$3,$4,$5::jsonb,'queued',0,now()+interval '24 hours')`, [id, device.rows[0].id, childId, command, JSON.stringify(payload)]);
  const sent = online && broadcastToDevice(device.rows[0].id, deviceWireMessage(command, id, payload));
  if (sent) await query(`UPDATE commands SET status='sent',attempts=1,sent_at=now(),updated_at=now() WHERE id=$1`, [id]);
  return id;
}

async function requestAppsSync(familyId: string, childId: string) {
  // Opening the parent app-management screen is the original APK's refresh
  // action. Avoid piling up duplicate commands while the child is responding.
  const pending = await query(
    `SELECT 1 FROM commands WHERE child_id=$1 AND command=$2 AND status IN ('queued','sent')
       AND created_at > now()-interval '2 minutes' LIMIT 1`,
    [childId, COMMANDS.syncApps]
  );
  if (!pending.rows[0]) await dispatchPolicy(familyId, childId, COMMANDS.syncApps, { reason: 'parent_app_list_open' });
}

async function replaceControlPeriods(childId: string, items: unknown) {
  if (!Array.isArray(items)) return;
  await query('DELETE FROM control_periods WHERE child_id=$1', [childId]);
  for (const raw of items) {
    const item = raw as Record<string, any>;
    if (!item.name || !(item.startTime ?? item.start_time) || !(item.endTime ?? item.end_time)) continue;
    await query(`INSERT INTO control_periods(child_id,name,weekdays,start_time,end_time,mode,daily_limit_seconds,allowed_packages,priority,enabled) VALUES ($1,$2,$3::smallint[],$4,$5,$6,$7,$8::jsonb,$9,$10)`, [childId, item.name, item.weekdays ?? [1,2,3,4,5,6,7], item.startTime ?? item.start_time, item.endTime ?? item.end_time, item.mode ?? 'allow', item.dailyLimitSeconds ?? item.daily_limit_seconds ?? null, JSON.stringify(item.allowedPackages ?? item.allowed_packages ?? []), item.priority ?? 100, item.enabled ?? true]);
  }
}

