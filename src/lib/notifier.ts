import { publishEvent } from './kafka';

/**
 * notifier.ts — auth-service notification helper
 *
 * Instead of calling SMTP directly, auth-service publishes to Kafka
 * topic `notification.send`. The notification-service picks it up and
 * handles delivery (email, push, SMS).
 *
 * This keeps auth-service SMTP-free and makes login never block on email.
 *
 * Usage:
 *   void notify.otp(email, '483920', 'Login', 5);
 *   void notify.newDeviceLogin(email, 'Chrome on Windows', '1.2.3.4');
 */

type Priority = 'high' | 'normal' | 'low';

async function send(
  channel: 'email' | 'push' | 'sms',
  template: string,
  recipient: string,
  data: Record<string, unknown>,
  priority: Priority = 'normal',
): Promise<void> {
  await publishEvent('notification.send', recipient, {
    channel,
    template,
    priority,
    recipient,
    data,
    createdAt: new Date().toISOString(),
  });
}

// ── Auth events ───────────────────────────────────────────────────────────────

export const notify = {
  /** OTP for login 2FA, email verify, password reset */
  otp(email: string, otp: string, purpose: string, expiryMinutes: number): Promise<void> {
    return send('email', 'otp', email, { otp, purpose, expiryMinutes }, 'high');
  },

  /** Sent when a login is detected from a new device */
  newDeviceLogin(email: string, deviceInfo: string, ipAddress: string): Promise<void> {
    return send('email', 'new_device_login', email, {
      deviceInfo,
      ipAddress,
      timestamp: new Date().toUTCString(),
    }, 'high');
  },

  /** Sent after a successful password change */
  passwordChanged(email: string): Promise<void> {
    return send('email', 'password_changed', email, {
      timestamp: new Date().toUTCString(),
    }, 'high');
  },

  /** OTP for password reset flow */
  passwordReset(email: string, otp: string, expiryMinutes: number): Promise<void> {
    return send('email', 'password_reset', email, { otp, expiryMinutes }, 'high');
  },

  /** Welcome email after live account registration */
  welcomeLive(email: string, accountNumber: string): Promise<void> {
    return send('email', 'welcome_live', email, { accountNumber });
  },

  /** Welcome email after demo account registration */
  welcomeDemo(email: string, accountNumber: string, demoBalance: number): Promise<void> {
    return send('email', 'welcome_demo', email, {
      accountNumber,
      demoBalance: demoBalance.toLocaleString(),
    });
  },
};
