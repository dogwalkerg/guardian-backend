import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { config } from './config.js';
import { query } from './db.js';
import { getAuthUser, ensureUserAndFamily, issueToken, verifyCaptcha, hashToken } from './auth.js';
import type { DeviceMessage } from './protocol.js';

const deviceSockets = new Map<string, any>();

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

async function markDevice(deviceId: string, online: boolean, patch: Record<string, unknown> = {}) {
  await query(
    `UPDATE devices SET online=$2, last_seen_at=now(), updated_at=now(),
      last_heartbeat_at=COALESCE($3::timestamptz, last_heartbeat_at),
      battery=COALESCE($4::integer, battery), network_type=COALESCE($5::varchar, network_type),
      client_version=COALESCE($6::varchar, client_version), metadata=COALESCE($7::jsonb, metadata)
     WHERE id=$1`,
    [deviceId, online, patch.lastHeartbeatAt ?? null, patch.battery ?? null, patch.networkType ?? null, patch.clientVersion ?? null, patch.metadata ? JSON.stringify(patch.metadata) : null]
  );
}

async function handleDeviceMessage(deviceId: string, message: DeviceMessage) {
  const payload = message.payload ?? message.result ?? {};
  if (message.type === 'heartbeat' || message.type === 'device_heartbeat' || message.type === 'HEARTBEAT') {
    await markDevice(deviceId, true, { lastHeartbeatAt: new Date().toISOString(), ...payload });
    return;
  }
  if (message.type === 'device_info' || message.type === 'CHILD_UPDATE_DEVICE') {
    await markDevice(deviceId, true, payload);
    return;
  }
  if (message.type === 'battery' || message.type === 'BATTERY_CHANGE') {
    await markDevice(deviceId, true, { battery: payload.battery, lastHeartbeatAt: new Date().toISOString() });
    return;
  }
  if (message.type === 'location' || message.type === 'location_upload' || message.type === 'CHILD_LOCATION_CHANGE') {
    const lat = Number(payload.latitude ?? payload.lat);
    const lng = Number(payload.longitude ?? payload.lng ?? payload.lon);
    if (Number.isFinite(lat) && Number.isFinite(lng)) {
      const device = await query<{ child_id: string }>('SELECT child_id FROM devices WHERE id=$1', [deviceId]);
      if (device.rows[0]) await query(
        `INSERT INTO location_records(device_id, child_id, latitude, longitude, accuracy, address, recorded_at, source)
         VALUES ($1,$2,$3,$4,$5,$6,COALESCE($7::timestamptz,now()),$8)`,
        [deviceId, device.rows[0].child_id, lat, lng, payload.accuracy ?? null, payload.address ?? null, payload.recordedAt ?? null, payload.source ?? 'device']
      );
    }
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
    return;
  }
  if (message.type === 'apps' || message.type === 'apps_upload' || message.type === 'CHILD_APP_SYSTEM_LIST') {
    const apps = Array.isArray(payload.apps) ? payload.apps : [];
    for (const item of apps) {
      const packageName = item.packageName ?? item.package_name;
      if (!packageName) continue;
      await query(
        `INSERT INTO installed_apps(device_id,package_name,app_name,version_name,version_code,icon_url,is_system,last_seen_at)
         VALUES ($1,$2,$3,$4,$5,$6,COALESCE($7,false),now())
         ON CONFLICT(device_id,package_name) DO UPDATE SET app_name=EXCLUDED.app_name,version_name=EXCLUDED.version_name,version_code=EXCLUDED.version_code,icon_url=EXCLUDED.icon_url,is_system=EXCLUDED.is_system,last_seen_at=now()`,
        [deviceId, packageName, item.appName ?? item.app_name ?? packageName, item.versionName ?? item.version_name ?? null, String(item.versionCode ?? item.version_code ?? ''), item.iconUrl ?? item.icon_url ?? null, item.isSystem ?? item.is_system ?? false]
      );
    }
    return;
  }
  if (message.type === 'command_result' || message.type === 'control_result' || message.status) {
    const messageId = message.messageId;
    if (!messageId) return;
    await query(
      `UPDATE commands SET status=$2, result=$3::jsonb, acknowledged_at=now(), updated_at=now()
       WHERE id=$1`,
      [messageId, message.status === 'success' ? 'succeeded' : 'failed', JSON.stringify(message.result ?? payload)]
    );
  }
}

async function authOrNull(app: FastifyInstance, request: any) {
  try { return await getAuthUser(app, request); } catch { return null; }
}

export async function registerRoutes(app: FastifyInstance) {
  app.get('/health', async () => ({ ok: true, service: 'guardian-backend', time: new Date().toISOString() }));
  app.get('/api/health', async () => ({ ok: true, service: 'guardian-backend', time: new Date().toISOString() }));

  app.post('/api/v1/auth/account/sendCaptcha', async (request: any) => {
    const body = request.body ?? {};
    const phone = String(body.phone ?? '').trim();
    if (!phone) return { error: 'phone is required' };
    const code = config.allowFixedCaptcha ? config.fixedCaptcha : String(Math.floor(100000 + Math.random() * 900000));
    await query(`INSERT INTO captcha_codes(phone,code,expires_at) VALUES ($1,$2,now()+interval '10 minutes') ON CONFLICT(phone) DO UPDATE SET code=EXCLUDED.code,expires_at=EXCLUDED.expires_at`, [phone, code]);
    request.log.info({ phone, code: config.allowFixedCaptcha ? code : '[redacted]' }, 'captcha issued');
    return { data: { sent: true, expiresIn: 600, ...(config.nodeEnv !== 'production' ? { devCode: code } : {}) } };
  });

  app.post('/api/v1/auth/account/captchaLogin', async (request: any, reply) => {
    const body = request.body ?? {};
    const phone = String(body.phone ?? '').trim();
    const code = String(body.code ?? body.captcha ?? '').trim();
    if (!phone || !code || !(await verifyCaptcha(phone, code, config.allowFixedCaptcha, config.fixedCaptcha))) return reply.code(401).send({ message: '验证码错误或已过期' });
    const record = await ensureUserAndFamily(phone);
    const token = await issueToken(app, { id: record.id, phone: record.phone, familyId: record.family_id });
    return { data: { token, accessToken: token, userId: record.id, familyId: record.family_id }, token };
  });

  app.get('/api/v1/auth/account/userAgreement', async () => ({ data: { title: '用户协议', content: '请在正式上线前补充用户协议内容。' } }));
  app.get('/api/v1/auth/account/privacyPolicy', async () => ({ data: { title: '隐私政策', content: '请在正式上线前补充隐私政策内容。' } }));

  app.get('/api/v1/parent/user/getUserInfo', async (request: any) => {
    const user = await getAuthUser(app, request);
    const result = await query(`SELECT u.id AS "parentId",u.phone,u.display_name AS "displayName",u.avatar_url AS "avatarUrl",f.id AS "familyId",f.name AS "familyName" FROM users u JOIN families f ON f.owner_user_id=u.id WHERE u.id=$1`, [user.id]);
    return { data: result.rows[0] ?? null };
  });

  app.get('/api/v1/parent/index/childUserList', async (request: any) => {
    const user = await getAuthUser(app, request);
    const result = await query(`SELECT c.id AS "childId",c.name,c.phone,c.avatar_url AS "avatarUrl",d.id AS "deviceId",d.device_name AS "phoneName",d.brand,d.model,d.android_version AS "androidVersion",d.client_version AS "clientVersion",d.online,d.battery,d.last_seen_at AS "lastSeenAt" FROM children c LEFT JOIN LATERAL (SELECT * FROM devices x WHERE x.child_id=c.id ORDER BY x.updated_at DESC LIMIT 1) d ON true WHERE c.family_id=$1 AND c.active=true ORDER BY c.created_at`, [user.familyId]);
    return { data: result.rows };
  });

  app.post('/api/v1/parent/index/getDeviceInfo', async (request: any) => {
    const user = await getAuthUser(app, request); const childId = String((request.body ?? {}).childId ?? '');
    const result = await query(`SELECT d.* FROM devices d JOIN children c ON c.id=d.child_id WHERE d.child_id=$1 AND c.family_id=$2 ORDER BY d.updated_at DESC LIMIT 1`, [childId, user.familyId]);
    return { data: result.rows[0] ?? null };
  });

  app.get('/api/v1/parent/index/getChildNewLocation', async (request: any) => {
    const user = await getAuthUser(app, request); const childId = String((request.query as any)?.childId ?? '');
    const result = await query(`SELECT l.* FROM location_records l JOIN children c ON c.id=l.child_id WHERE l.child_id=$1 AND c.family_id=$2 ORDER BY l.recorded_at DESC LIMIT 1`, [childId, user.familyId]);
    return { data: result.rows[0] ?? null };
  });

  app.get('/api/v1/parent/app/childStatusInfo/:childId', async (request: any) => {
    const user = await getAuthUser(app, request); const childId = request.params.childId;
    const result = await query(`SELECT c.id AS "childId",d.online,d.battery,d.last_seen_at AS "lastSeenAt",d.client_version AS "clientVersion" FROM children c LEFT JOIN LATERAL (SELECT * FROM devices WHERE child_id=c.id ORDER BY updated_at DESC LIMIT 1) d ON true WHERE c.id=$1 AND c.family_id=$2`, [childId, user.familyId]);
    return { data: result.rows[0] ?? null };
  });

  app.get('/api/v1/parent/app/childUseAppTimeRankList', async (request: any) => {
    const user = await getAuthUser(app, request); const q = request.query as any; const childId = q.childId;
    const result = await query(`SELECT u.package_name AS "packageName",max(u.app_name) AS "appName",sum(u.use_seconds)::integer AS "useTime" FROM usage_records u JOIN children c ON c.id=u.child_id WHERE u.child_id=$1 AND c.family_id=$2 AND u.day BETWEEN COALESCE($3::date,current_date-interval '30 day') AND COALESCE($4::date,current_date) GROUP BY u.package_name ORDER BY "useTime" DESC`, [childId, user.familyId, q.beginDateTime ?? null, q.endDateTime ?? null]);
    return { data: result.rows };
  });

  app.get('/api/v1/parent/app/control/:childId', async (request: any) => {
    const user = await getAuthUser(app, request); const childId = request.params.childId;
    const result = await query(`SELECT a.package_name AS "packageName",a.app_name AS "appName",COALESCE(p.policy_type,1) AS type,COALESCE(p.daily_limit_seconds,0) AS "useTime" FROM installed_apps a JOIN devices d ON d.id=a.device_id JOIN children c ON c.id=d.child_id LEFT JOIN app_policies p ON p.child_id=c.id AND p.package_name=a.package_name WHERE c.id=$1 AND c.family_id=$2 ORDER BY a.app_name`, [childId, user.familyId]);
    return { data: result.rows };
  });

  app.put('/api/v1/parent/app/control', async (request: any) => {
    const user = await getAuthUser(app, request); const items = Array.isArray(request.body) ? request.body : (request.body ?? {}).items ?? [];
    for (const item of items) {
      const childId = item.childId ?? (request.body ?? {}).childId; const packageName = item.packageName ?? item.package_name;
      if (!childId || !packageName) continue;
      await query(`INSERT INTO app_policies(child_id,package_name,app_name,policy_type,daily_limit_seconds) VALUES ($1,$2,$3,$4,$5) ON CONFLICT(child_id,package_name) DO UPDATE SET app_name=EXCLUDED.app_name,policy_type=EXCLUDED.policy_type,daily_limit_seconds=EXCLUDED.daily_limit_seconds,updated_at=now()`, [childId, packageName, item.appName ?? null, Number(item.type ?? item.policyType ?? 1), item.useTime ?? item.dailyLimitSeconds ?? null]);
      await dispatchPolicy(user.familyId, String(childId), 'app_policy_update', { app: item });
    }
    return { data: true };
  });

  app.get('/api/v1/parent/controlPolicy/getControlListByChildId/:childId', async (request: any) => {
    const user = await getAuthUser(app, request); const result = await query(`SELECT p.* FROM control_policies p JOIN children c ON c.id=p.child_id WHERE p.child_id=$1 AND c.family_id=$2`, [request.params.childId, user.familyId]);
    return { data: result.rows[0] ?? null };
  });

  app.put('/api/v1/parent/controlPolicy/setControlPolicy', async (request: any) => {
    const user = await getAuthUser(app, request); const b = request.body ?? {};
    const childId = b.childId; if (!childId) return { error: 'childId is required' };
    await query(`INSERT INTO control_policies(child_id,name,enabled,no_play_enabled,lock_enabled,allow_call,emergency_numbers,periods,daily_limit_seconds,timezone) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9,$10) ON CONFLICT(child_id) DO UPDATE SET name=EXCLUDED.name,enabled=EXCLUDED.enabled,no_play_enabled=EXCLUDED.no_play_enabled,lock_enabled=EXCLUDED.lock_enabled,allow_call=EXCLUDED.allow_call,emergency_numbers=EXCLUDED.emergency_numbers,periods=EXCLUDED.periods,daily_limit_seconds=EXCLUDED.daily_limit_seconds,timezone=EXCLUDED.timezone,updated_at=now()`, [childId,b.name ?? '默认管控策略',b.enabled ?? true,b.noPlayEnabled ?? b.no_play_enabled ?? false,b.lockEnabled ?? b.lock_enabled ?? false,b.allowCall ?? true,JSON.stringify(b.emergencyNumbers ?? []),JSON.stringify(b.periods ?? []),b.dailyLimitSeconds ?? null,b.timezone ?? 'Asia/Shanghai']);
    await dispatchPolicy(user.familyId, String(childId), 'policy_update', b); return { data: true };
  });

  app.get('/api/v1/parent/account/getBindQrcode', async (request: any) => {
    const user = await getAuthUser(app, request); const token = randomUUID().replaceAll('-', '');
    const child = await query<{ id: string }>('INSERT INTO children(family_id,name) VALUES ($1,$2) RETURNING id', [user.familyId, '孩子']);
    await query(`INSERT INTO bind_tokens(token,family_id,child_id,expires_at) VALUES ($1,$2,$3,now()+interval '10 minutes')`, [token,user.familyId,child.rows[0].id]);
    return { data: { bindCode: token, childId: child.rows[0].id, content: `guardian://bind?token=${token}`, expiresIn: 600 } };
  });

  app.delete('/api/v1/parent/user/removeDevice', async (request: any) => { const user = await getAuthUser(app, request); const childId=(request.body??{}).childId; await query(`DELETE FROM devices d USING children c WHERE d.child_id=$1 AND c.id=d.child_id AND c.family_id=$2`,[childId,user.familyId]); return {data:true}; });
  app.put('/api/v1/parent/user/updateChild', async (request: any) => { const user=await getAuthUser(app,request);const b=request.body??{}; await query(`UPDATE children c SET name=COALESCE($3,c.name),phone=COALESCE($4,c.phone),updated_at=now() FROM families f WHERE c.id=$1 AND c.family_id=f.id AND f.id=$2`,[b.childId,user.familyId,b.name,b.phone]); return {data:true}; });

  app.post('/api/v1/device/register', async (request: any, reply) => {
    const b=request.body??{}; const bindToken=String(b.bindToken??b.bindCode??''); const token=String(b.deviceToken??b.token??randomUUID());
    const found=await query<{child_id:string;family_id:string}>('SELECT child_id,family_id FROM bind_tokens WHERE token=$1 AND used_at IS NULL AND expires_at>now()',[bindToken]);
    if(!found.rows[0]) return reply.code(400).send({message:'绑定码无效或已过期'});
    const row=await query<{id:string}>('INSERT INTO devices(child_id,device_token_hash,device_name,brand,model,android_version,client_version,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb) RETURNING id',[found.rows[0].child_id,hashToken(token),b.deviceName??null,b.brand??null,b.model??null,b.androidVersion??null,b.clientVersion??null,JSON.stringify(b.metadata??{})]);
    await query('UPDATE bind_tokens SET used_at=now() WHERE token=$1',[bindToken]);
    return {data:{deviceId:row.rows[0].id,deviceToken:token,childId:found.rows[0].child_id}};
  });

  app.post('/api/v1/device/bind', async (request:any,reply)=>app.inject({method:'POST',url:'/api/v1/device/register',payload:request.body}).then(r=>reply.code(r.statusCode).send(r.json())));
  app.post('/api/v1/device/heartbeat', async (request:any,reply)=>{const device=await findDevice(request);if(!device)return reply.code(401).send({message:'device unauthorized'});await markDevice(device.id,true,{lastHeartbeatAt:new Date().toISOString(),...(request.body??{})});return {data:{ok:true}};});
  app.post('/api/v1/device/uploadLocation', async (request:any,reply)=>{const device=await findDevice(request);if(!device)return reply.code(401).send({message:'device unauthorized'});await handleDeviceMessage(device.id,{type:'location',payload:request.body??{}});return {data:{ok:true}};});
  app.post('/api/v1/device/uploadUsage', async (request:any,reply)=>{const device=await findDevice(request);if(!device)return reply.code(401).send({message:'device unauthorized'});await handleDeviceMessage(device.id,{type:'usage',payload:request.body??{}});return {data:{ok:true}};});
  app.post('/api/v1/device/uploadApps', async (request:any,reply)=>{const device=await findDevice(request);if(!device)return reply.code(401).send({message:'device unauthorized'});await handleDeviceMessage(device.id,{type:'apps',payload:request.body??{}});return {data:{ok:true}};});

  app.get('/ws', { websocket: true }, (socket: any, request: any) => {
    let deviceId = '';
    socket.on('message', async (raw: Buffer) => {
      try {
        const message = JSON.parse(raw.toString()) as DeviceMessage;
        if (!deviceId && (message.type === 'device_hello' || message.type === 'hello' || message.type === 'register')) {
          const token = String((message.payload ?? {}).token ?? message.payload?.deviceToken ?? message.deviceId ?? '');
          const byId = message.deviceId ? await query<{id:string;device_token_hash:string}>('SELECT id,device_token_hash FROM devices WHERE id=$1',[message.deviceId]) : {rows:[]};
          const device = byId.rows[0] && hashToken(token) === byId.rows[0].device_token_hash ? byId.rows[0] : null;
          if (!device) { socket.close(4001, 'unauthorized'); return; }
          deviceId = device.id; deviceSockets.set(deviceId, socket); await markDevice(deviceId,true,{lastHeartbeatAt:new Date().toISOString(),clientVersion:(message.payload??{}).clientVersion});
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
  const auth = String(request.headers.authorization ?? ''); const supplied = auth.replace(/^Bearer\s+/i,'') || String((request.body??{}).deviceToken ?? (request.body??{}).token ?? '');
  const deviceId = String(request.body?.deviceId ?? request.headers['x-device-id'] ?? '');
  if(!supplied || !deviceId) return null;
  const result=await query<{id:string;child_id:string}>('SELECT d.id,d.child_id FROM devices d JOIN children c ON c.id=d.child_id WHERE d.id=$1 AND d.device_token_hash=$2',[deviceId,hashToken(supplied)]); return result.rows[0]??null;
}

async function dispatchPolicy(familyId:string, childId:string, command:string, payload:Record<string,unknown>) {
  const device=await query<{id:string}>('SELECT d.id FROM devices d JOIN children c ON c.id=d.child_id WHERE c.id=$1 AND c.family_id=$2 ORDER BY d.updated_at DESC LIMIT 1',[childId,familyId]); if(!device.rows[0]) return null;
  const id=randomUUID(); await query(`INSERT INTO commands(id,device_id,child_id,command,payload,expires_at) VALUES($1,$2,$3,$4,$5::jsonb,now()+interval '24 hours')`,[id,device.rows[0].id,childId,command,JSON.stringify(payload)]);
  broadcastToDevice(device.rows[0].id,{type:'command',messageId:id,command,payload}); return id;
}

