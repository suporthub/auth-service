import { z } from 'zod';

export const liveRegisterSchema = z.object({
  email:       z.string().email(),
  phoneNumber: z.string().min(7).max(20),
  password:    z.string().min(8, 'Password must be at least 8 characters'),
  groupName:   z.string().default('Standard'),
  country:     z.string().length(2).transform((v) => v.toUpperCase()).pipe(
    z.string().regex(/^[A-Z]{2}$/, 'country must be a valid ISO-2 country code (e.g. "IN", "AE", "US")')
  ),
  // Optional — defaults applied downstream (USD, 100)
  currency:     z.string().default('USD'),
  leverage:     z.number().int().positive().default(100),
  referralCode: z.string().optional(),
});

export type LiveRegisterInput = z.infer<typeof liveRegisterSchema>;

export const liveLoginSchema = z.object({
  email:             z.string().email(),
  password:          z.string().min(1),
  deviceFingerprint: z.string().optional(),
  deviceLabel:       z.string().optional(),
});

export type LiveLoginInput = z.infer<typeof liveLoginSchema>;

export const openLiveAccountSchema = z.object({
  accountName:     z.string().min(1),
  group:           z.string().min(1),
  accountVariant:  z.enum(['cent', 'usd']),
  currency:        z.string().default('USD'),
  leverage:        z.number().int().positive().default(100),
  tradingPassword: z.string().min(8).optional(),
});

export type OpenLiveAccountInput = z.infer<typeof openLiveAccountSchema>;

export const openDemoAccountSchema = openLiveAccountSchema.extend({
  initialBalance:  z.number().int().positive().default(10000),
});

export type OpenDemoAccountInput = z.infer<typeof openDemoAccountSchema>;

export const selectAccountSchema = z.object({
  accountNumber:     z.string(),
  deviceFingerprint: z.string().optional(),
  deviceLabel:       z.string().optional(),
});

export type SelectAccountInput = z.infer<typeof selectAccountSchema>;
