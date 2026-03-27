import { config } from '../../config/env';

export interface DeviceContext {
  isNewDevice: boolean;
  daysSinceLastSeen: number | null;
}

export interface SecurityContext {
  hasTOTP: boolean;
}

export interface TwoFactorEnforcementResult {
  requires2FA: boolean;
  method: 'totp' | 'email' | 'none';
  isNewDevice: boolean; // Retained for alerting logic
}

/**
 * Encapsulates the business rules for 2FA enforcement during login,
 * adhering to the Single Responsibility Principle and Open-Closed Principle.
 */
export class TwoFactorEnforcementPolicy {
  /**
   * Evaluates the device and security context and returns the 2FA enforcement decision.
   */
  static evaluate(
    device: DeviceContext,
    security: SecurityContext
  ): TwoFactorEnforcementResult {
    // Requirement 2: If user has setup totp, enforce totp on EVERY login.
    if (security.hasTOTP) {
      return {
        requires2FA: true,
        method: 'totp',
        isNewDevice: device.isNewDevice,
      };
    }

    // Requirement 1: If no totp, enforce email otp if new device or > 30 days inactive
    if (
      device.isNewDevice ||
      (device.daysSinceLastSeen !== null &&
        device.daysSinceLastSeen > config.inactivity2faDays)
    ) {
      return {
        requires2FA: true,
        method: 'email',
        isNewDevice: device.isNewDevice,
      };
    }

    // Default: No 2FA required (known device, < 30 days)
    return {
      requires2FA: false,
      method: 'none',
      isNewDevice: device.isNewDevice,
    };
  }
}
