export const DEVICE_EVENTS = {
  CONTROL_POLICY_UPDATE: 'CONTROL_POLICY_UPDATE',
  CONTROL_POLICY_LOCK: 'CONTROL_POLICY_LOCK',
  CONTROL_POLICY_REMOVE_LOCK: 'CONTROL_POLICY_REMOVE_LOCK',
  PHONE_MOBILE_UNBIND: 'PHONE_MOBILE_UNBIND',
  CONTROL_APPSYSTEM_CHANGE: 'CONTROL_APPSYSTEM_CHANGE',
  EMERGENCY_NUMBER_UPDATE: 'EMERGENCY_NUMBER_UPDATE',
  AUTOMATIC_POSITIONING_UPDATE: 'AUTOMATIC_POSITIONING_UPDATE',
  LOCATION_NOTIFICAT: 'LOCATION_NOTIFICAT',
  CLIENT_VERSION_UP: 'CLIENT_VERSION_UP',
  REMOTE_UNINSTALL_APPLICATION: 'REMOTE_UNINSTALL_APPLICATION',
  CONTROL_APP_SETTING_CHANGE: 'CONTROL_APP_SETTING_CHANGE',
  BATTERY_CHANGE: 'BATTERY_CHANGE',
  CHILD_REMOVE_DEVICE: 'CHILD_REMOVE_DEVICE',
  CHILD_UPDATE_DEVICE: 'CHILD_UPDATE_DEVICE',
  INLINE_STATUS_CHANGE: 'INLINE_STATUS_CHANGE',
  CHILD_LOCATION_CHANGE: 'CHILD_LOCATION_CHANGE',
  CHILD_UPDATE_APP_USE_TIME: 'CHILD_UPDATE_APP_USE_TIME',
  CHILD_CONTROL_STATUS_CHANGE: 'CHILD_CONTROL_STATUS_CHANGE'
} as const;

export type DeviceMessage = {
  type: string | number;
  msgId?: number | string;
  content?: string;
  messageId?: string;
  command?: string;
  deviceId?: string;
  payload?: Record<string, any>;
  status?: string;
  result?: Record<string, any>;
};

/**
 * Contract for a child Android client using DevicePolicyManager. The cloud
 * queues these commands, but only the provisioned Device Owner can apply the
 * restrictions on-device and must report a `device_owner_status` event.
 */
export type DeviceOwnerPolicy = {
  deviceOwnerRequired?: boolean;
  restrictions?: {
    noConfigTethering?: boolean;
    noConfigLocation?: boolean;
    noFactoryReset?: boolean;
    removeSettingsMenus?: boolean;
    allowAppManagement?: boolean;
  };
  applicationPolicies?: Array<{
    packageName: string;
    policyType: 1 | 2 | 3;
    dailyLimitSeconds?: number | null;
  }>;
  periods?: Array<{
    weekdays: number[];
    startTime: string;
    endTime: string;
    mode: 'allow' | 'forbid' | 'lock';
    allowedPackages?: string[];
  }>;
  offline?: { mode: 'allow' | 'deny'; lockAfterDays?: number | null };
};
