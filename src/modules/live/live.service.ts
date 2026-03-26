import { prismaWrite, prismaRead } from '../../lib/prisma';
import { hashPassword, verifyPassword, sha256, hashFingerprint } from '../../utils/hash';
import { signTokenPair, signLoginPendingToken, signPortalTokenPair } from '../../utils/jwt';
import { generateAccountNumber } from '../../utils/accountNumber';
import { createOtp } from '../../utils/otp';
import { notify } from '../../lib/notifier';
import { publishEvent } from '../../lib/kafka';
import { config } from '../../config/env';
import { LiveRegisterInput, LiveLoginInput } from './live.schema';
import { AppError } from '../../utils/errors';
import { logger } from '../../lib/logger';


// ── Register ──────────────────────────────────────────────────────────────────

export async function registerLiveUser(input: LiveRegisterInput) {
  const accountNumber       = await generateAccountNumber('LU');
  const masterPasswordHash  = await hashPassword(input.password);
  // Auto-generate a secure random MT5 trading password (shown once in welcome email)
  const tradingPassword     = generateSecurePassword();
  const tradingPasswordHash = await hashPassword(tradingPassword);

  // ── Pre-flight checks (Phone & Referral) ────────────────────────────────────
  // Check before Kafka so user gets an immediate 400/409 instead of silent drop.
  try {
    const phoneResp = await fetch(
      `${process.env.USER_SERVICE_INTERNAL_URL}/internal/users/check-phone/${encodeURIComponent(input.phoneNumber)}?ownerEmail=${encodeURIComponent(input.email)}`,
      { headers: { 'x-service-secret': process.env.INTERNAL_SERVICE_SECRET! } },
    );
    if (phoneResp.ok) {
      const { available } = await phoneResp.json() as { available: boolean };
      if (!available) {
        throw new AppError('PHONE_ALREADY_REGISTERED', 409, 'This phone number is already registered to another account.');
      }
    }
  } catch (err) {
    if (err instanceof AppError) throw err;
    logger.warn({ err }, '[register] Phone pre-flight check failed — proceeding');
  }

  // ── Referral Code pre-flight check ──────────────────────────────────────────
  if (input.referralCode) {
    try {
      const refResp = await fetch(
        `${process.env.USER_SERVICE_INTERNAL_URL}/internal/users/check-referral/${encodeURIComponent(input.referralCode)}`,
        { headers: { 'x-service-secret': process.env.INTERNAL_SERVICE_SECRET! } }
      );
      if (refResp.ok) {
        const { valid } = await refResp.json() as { valid: boolean };
        if (!valid) throw new AppError('INVALID_REFERRAL_CODE', 400, 'The referral code you entered is invalid.');
      }
    } catch (err) {
      if (err instanceof AppError) throw err;
      logger.warn({ err }, '[register] Referral pre-flight check failed — proceeding without referral');
    }
  }

  // ── Email Duplicate Pre-flight Check ────────────────────────────────────────
  try {
    const emailResp = await fetch(
      `${process.env.USER_SERVICE_INTERNAL_URL}/internal/users/by-email`,
      {
        method:  'POST',
        headers: { 'Content-Type': 'application/json', 'x-service-secret': process.env.INTERNAL_SERVICE_SECRET! },
        body:    JSON.stringify({ email: input.email }),
      }
    );
    if (emailResp.ok) {
      const existingProfile = await emailResp.json() as { isVerified: boolean; accounts?: { accountNumber: string }[] };
      if (existingProfile.isVerified) {
        throw new AppError('EMAIL_ALREADY_REGISTERED', 409, 'An account with this email already exists. Please log in.');
      } else {
        // Unverified User — proactively re-send OTP against their exact existing account number
        const existingAccount = existingProfile.accounts?.[0]?.accountNumber;
        if (existingAccount) {
          const otp = await createOtp(existingAccount, 'email_verify');
          void notify.otp(input.email, otp, 'Email Verification', config.otpExpiresInMinutes);
        }
        throw new AppError('EMAIL_PENDING_VERIFICATION', 409, 'An unverified account with this email already exists. A new verification code has been sent to your email.');
      }
    }
  } catch (err) {
    if (err instanceof AppError) throw err;
    logger.warn({ err }, '[register] Email pre-flight check failed — proceeding');
  }

  // Publish to Kafka — user-service will create the UserProfile + LiveUser
  await publishEvent('user.register', accountNumber, {
    type:               'LIVE_USER_REGISTER',
    accountNumber,
    masterPasswordHash,
    tradingPasswordHash,
    email:              input.email,
    phoneNumber:        input.phoneNumber,
    country:            input.country,
    groupName:          input.groupName,
    currency:           input.currency,
    leverage:           input.leverage,
    isSelfTrading:      true,
    ...(input.referralCode !== undefined && { referredByCode: input.referralCode }),
  });


  // OTP keyed by accountNumber to support multiple accounts per email
  const otp = await createOtp(accountNumber, 'email_verify');
  // Fire-and-forget — email verify OTP via notification-service
  void notify.otp(input.email, otp, 'Email Verification', config.otpExpiresInMinutes);

  return {
    accountNumber,
    message: 'Account created. Please verify your email.',
  };
}

// ── Login Flow ────────────────────────────────────────────────────────────────

/**
 * Portal context returned by user-service for email-based login.
 * Contains the UserProfile data + list of trading accounts.
 */
interface PortalContext {
  profileId:          string;
  email:              string;
  masterPasswordHash: string;
  isVerified:         boolean;
  accounts: Array<{
    accountNumber: string;
    type:          string;
    currency:      string;
    leverage:      number;
    groupName:     string;
    isActive:      boolean;
  }>;
}

/**
 * Trading account context used to mint a specific account's Trading JWT.
 */
export interface LoginContext {
  userId:        string;
  profileId?:    string;
  userType:      'live';
  accountNumber: string;
  groupName:     string;
  currency:      string;
  passwordHash:  string;
  isActive:      boolean;
}

async function getPortalContext(email: string): Promise<PortalContext | null> {
  try {
    const resp = await fetch(
      `${process.env.USER_SERVICE_INTERNAL_URL}/internal/users/by-email`,
      {
        method:  'POST',
        headers: { 'Content-Type': 'application/json', 'x-service-secret': config.internalSecret },
        body:    JSON.stringify({ email, userType: 'live' }),
      },
    );
    if (!resp.ok) return null;
    return (await resp.json()) as PortalContext;
  } catch {
    return null;
  }
}

async function getLiveAccountContext(accountNumber: string): Promise<LoginContext | null> {
  try {
    const resp = await fetch(
      `${process.env.USER_SERVICE_INTERNAL_URL}/internal/users/by-account/${encodeURIComponent(accountNumber)}`,
      { headers: { 'x-service-secret': config.internalSecret } },
    );
    if (!resp.ok) return null;
    const ctx = await resp.json() as LoginContext & { profileId: string; userType: 'live' | 'demo' };
    return ctx;
  } catch {
    return null;
  }
}

export async function loginLiveUser(
  input:     LiveLoginInput,
  ipAddress: string,
  userAgent: string,
) {
  // 1. Fetch the UserProfile (not the trading account — master password lives here)
  const portal = await getPortalContext(input.email);
  if (!portal) throw new AppError('INVALID_CREDENTIALS', 401);

  // 2. Verify master (web portal) password
  const passwordOk = await verifyPassword(input.password, portal.masterPasswordHash);
  if (!passwordOk) throw new AppError('INVALID_CREDENTIALS', 401);

  // 3. Email must be verified before any token is issued for Live accounts.
  //    Check AFTER password so we don't leak whether the email exists.
  //    Demo-only users (who bypass verification initially) are allowed into the Portal.
  const hasLiveAccounts = portal.accounts.some(a => a.type === 'live');
  if (!portal.isVerified && hasLiveAccounts) {
    throw new AppError(
      'EMAIL_NOT_VERIFIED',
      403,
      'Please verify your email address before logging in. Check your inbox or request a new code.',
    );
  }

  const activeAccounts = portal.accounts.filter(a => a.isActive);

  // 3. Multi-account check: if user has multiple active live accounts, issue
  //    a Portal JWT token pair so the frontend can display the dashboard and account picker.
  if (activeAccounts.length > 1) {
    const tokens = signPortalTokenPair(portal.profileId);
    
    await prismaWrite.session.create({
      data: {
        id:          tokens.sessionId,
        userId:      portal.profileId,
        userType:    'live', // Treated as a live user session
        tokenHash:   sha256(tokens.accessJti),
        refreshHash: sha256(tokens.refreshJti),
        expiresAt:   tokens.refreshExpiresAt,
        ipAddress,
        userAgent,
      },
    });

    return {
      status:             'account_selection_required',
      portalToken:        tokens.accessToken,
      portalRefreshToken: tokens.refreshToken,
      sessionId:          tokens.sessionId,
      expiresIn:          15 * 60, // 15 mins (default jwtExpiresIn) matches runDeviceCheckAndIssueTokens
      accounts:           activeAccounts,
      message:            'Select an account to continue',
    };
  }

  // 4. Single account — proceed with device check + session creation
  if (activeAccounts.length === 0) throw new AppError('NO_ACTIVE_ACCOUNTS', 403);

  const accountCtx = await getLiveAccountContext(activeAccounts[0]!.accountNumber);
  if (!accountCtx) throw new AppError('INVALID_CREDENTIALS', 401);

  return await runDeviceCheckAndIssueTokens(
    accountCtx,
    portal.email,
    {
      ...(input.deviceFingerprint !== undefined && { deviceFingerprint: input.deviceFingerprint }),
      ...(input.deviceLabel !== undefined && { deviceLabel: input.deviceLabel }),
    },
    ipAddress,
    userAgent,
  );
}

// ── Account selection (after portal login) ────────────────────────────────────

/**
 * Called from POST /api/live/select-account.
 * Validates the Portal JWT owns the requested account, then issues a Trading JWT.
 */
export async function selectAccount(
  profileId:     string,
  accountNumber: string,
  input:         { deviceFingerprint?: string; deviceLabel?: string },
  ipAddress:     string,
  userAgent:     string,
  email:         string,
) {
  const accountCtx = await getLiveAccountContext(accountNumber);
  if (!accountCtx) throw new AppError('ACCOUNT_NOT_FOUND', 404);
  if (accountCtx.profileId !== profileId) throw new AppError('ACCOUNT_FORBIDDEN', 403);

  return await runDeviceCheckAndIssueTokens(accountCtx, email, input, ipAddress, userAgent);
}

// ── Open new trading account (in-portal) ─────────────────────────────────────

export async function openNewAccount(
  profileId: string,
  options: { groupName: string; currency: string; leverage: number; tradingPassword?: string },
) {
  // Demo users can enter the portal unverified; but creating a live account strictly requires verification.
  const profileResp = await fetch(
    `${process.env.USER_SERVICE_INTERNAL_URL}/internal/profiles/${profileId}`,
    { headers: { 'x-service-secret': config.internalSecret } }
  );
  if (!profileResp.ok) throw new AppError('USER_NOT_FOUND', 404);
  const profile = await profileResp.json() as { isVerified?: boolean };
  if (!profile.isVerified) throw new AppError('EMAIL_NOT_VERIFIED', 403, 'Email verification required to open a live trading account.');

  const accountNumber       = await generateAccountNumber('LU');
  const rawPassword         = options.tradingPassword ?? generateSecurePassword();
  const tradingPasswordHash = await hashPassword(rawPassword);
  const showPassword        = !options.tradingPassword; // show if auto-generated

  await fetch(
    `${process.env.USER_SERVICE_INTERNAL_URL}/internal/accounts`,
    {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'x-service-secret': config.internalSecret },
      body:    JSON.stringify({
        profileId,
        accountNumber,
        tradingPasswordHash,
        groupName: options.groupName,
        currency:  options.currency,
        leverage:  options.leverage,
      }),
    },
  );

  return {
    accountNumber,
    ...(showPassword ? { tradingPassword: rawPassword, tradingPasswordNote: 'Save this — it will not be shown again.' } : {}),
  };
}

// ── Issue tokens ──────────────────────────────────────────────────────────────

export async function issueTokensAndCreateSession(
  ctx:           LoginContext,
  fingerprintHash: string | null,
  deviceLabel:   string | null,
  ipAddress:     string,
  userAgent:     string,
  isNewDevice:   boolean,
) {
  const tokens = signTokenPair(ctx.userId, ctx.userType, ctx.accountNumber, {
    groupName: ctx.groupName,
    currency:  ctx.currency,
  });

  await prismaWrite.session.create({
    data: {
      id:             tokens.sessionId,
      userId:         ctx.userId,
      userType:       'live',
      tokenHash:      sha256(tokens.accessJti),
      refreshHash:    sha256(tokens.refreshJti),
      expiresAt:      tokens.refreshExpiresAt,
      ipAddress,
      userAgent,
      fingerprintHash,
    },
  });

  if (fingerprintHash) {
    await prismaWrite.knownDevice.upsert({
      where:  { userId_userType_fingerprintHash: { userId: ctx.userId, userType: 'live', fingerprintHash } },
      create: { userId: ctx.userId, userType: 'live', fingerprintHash, label: deviceLabel },
      update: { lastSeenAt: new Date() },
    });
  }

  await publishEvent('user.journal.events', ctx.userId, {
    eventType: isNewDevice ? 'NEW_DEVICE_LOGIN' : 'LOGIN_SUCCESS',
    userId:    ctx.userId,
    userType:  'live',
    ipAddress,
  });

  return {
    status:       'success',
    accessToken:  tokens.accessToken,
    refreshToken: tokens.refreshToken,
    expiresIn:    15 * 60,
    tokenType:    'Bearer',
    sessionId:    tokens.sessionId,
  };
}

// ── Private helpers ───────────────────────────────────────────────────────────

async function runDeviceCheckAndIssueTokens(
  accountCtx: LoginContext,
  email:      string,
  input:      { deviceFingerprint?: string; deviceLabel?: string },
  ipAddress:  string,
  userAgent:  string,
) {
  const fingerprintHash = input.deviceFingerprint ? hashFingerprint(input.deviceFingerprint) : null;
  let requires2FA = false;
  let isNewDevice  = false;

  if (fingerprintHash) {
    const knownDevice = await prismaRead.knownDevice.findUnique({
      where: { userId_userType_fingerprintHash: { userId: accountCtx.userId, userType: 'live', fingerprintHash } },
    });
    if (!knownDevice) {
      isNewDevice  = true;
      requires2FA  = true;
    } else {
      const daysSinceLastSeen = (Date.now() - knownDevice.lastSeenAt.getTime()) / 86_400_000;
      if (daysSinceLastSeen > config.inactivity2faDays) requires2FA = true;
    }
  }

  if (requires2FA) {
    const totpRecord = await prismaRead.userTotpSecret.findUnique({
      where: { userId_userType: { userId: accountCtx.userId, userType: 'live' } },
    });
    const hasTOTP    = totpRecord?.isVerified ?? false;
    const loginToken = signLoginPendingToken(accountCtx.userId, 'live');

    if (!hasTOTP) {
      const otp = await createOtp(accountCtx.userId, 'login');
      void notify.otp(email, otp, 'Login Verification', config.otpExpiresInMinutes);
    }

    if (isNewDevice && config.newDeviceAlert) {
      void notify.newDeviceLogin(email, input.deviceLabel ?? userAgent, ipAddress);
    }

    return {
      status:     hasTOTP ? 'totp_required' : 'otp_required',
      loginToken,
      message:    hasTOTP ? 'Enter your authenticator code' : 'A verification code has been sent to your email',
    };
  }

  return await issueTokensAndCreateSession(accountCtx, fingerprintHash, input.deviceLabel ?? null, ipAddress, userAgent, isNewDevice);
}

/** Generate a secure random 12-char alphanumeric + symbol password */
function generateSecurePassword(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%';
  return Array.from({ length: 12 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}
