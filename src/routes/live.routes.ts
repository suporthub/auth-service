import { Router } from 'express';
import { registerController, loginController } from '../modules/live/live.controller';
import { validate } from '../middleware/validate';
import { loginRateLimit, registerRateLimit } from '../middleware/rateLimiter';
import { authenticate, authenticatePortal } from '../middleware/authenticate';
import {
  liveRegisterSchema,
  liveLoginSchema,
  openNewAccountSchema,
  selectAccountSchema,
} from '../modules/live/live.schema';
import { refreshSession, logoutSession, listSessions } from '../modules/shared/session.service';
import { regenerateViewPassword } from '../modules/shared/password.service';
import { openNewAccount, selectAccount } from '../modules/live/live.service';
import { AppError } from '../utils/errors';
import { Request, Response } from 'express';

const router = Router();

// POST /api/live/register
router.post('/register', registerRateLimit, validate(liveRegisterSchema), registerController);

// POST /api/live/login
router.post('/login', loginRateLimit, validate(liveLoginSchema), loginController);

// POST /api/live/refresh-token
router.post('/refresh-token', async (req: Request, res: Response) => {
  const { refreshToken } = req.body;
  if (!refreshToken) { res.status(400).json({ success: false, message: 'refreshToken is required' }); return; }
  const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ?? req.ip ?? '';
  const ua = req.headers['user-agent'] ?? '';
  const data = await refreshSession(refreshToken, ip, ua);
  res.json({ success: true, data });
});

// POST /api/live/logout  [auth required]
router.post('/logout', authenticate, async (req: Request, res: Response) => {
  await logoutSession(req.user!.sid);
  res.json({ success: true, message: 'Logged out successfully' });
});

// GET /api/live/sessions  [auth required]
router.get('/sessions', authenticate, async (req: Request, res: Response) => {
  const sessions = await listSessions(req.user!.sub, req.user!.userType);
  res.json({ success: true, data: sessions });
});

// DELETE /api/live/sessions/:id  [auth required]
router.delete('/sessions/:id', authenticate, async (req: Request, res: Response) => {
  await logoutSession(req.params.id!);
  res.json({ success: true, message: 'Session revoked' });
});

// POST /api/live/regenerate-view-password  [auth required]
router.post('/regenerate-view-password', authenticate, async (req: Request, res: Response) => {
  const result = await regenerateViewPassword(req.user!.sub, req.user!.userType);
  res.json({ success: true, data: result });
});

// ─────────────────────────────────────────────────────────────────────────────
// Master Portal — account selection and management
// ─────────────────────────────────────────────────────────────────────────────

/**
 * POST /api/live/select-account
 *
 * Called AFTER a login where status === 'account_selection_required'.
 * The frontend shows a picker and POSTs here with the chosen accountNumber.
 * Requires the short-lived Portal JWT (typ: 'portal').
 *
 * Body: { accountNumber, deviceFingerprint?, deviceLabel? }
 * Returns: full Trading JWT (same as a normal single-account login).
 */
router.post('/select-account', authenticatePortal, validate(selectAccountSchema), async (req: Request, res: Response) => {
  const { accountNumber, deviceFingerprint, deviceLabel } = req.body as {
    accountNumber: string; deviceFingerprint?: string; deviceLabel?: string;
  };
  const profileId = req.user!.sub; // Portal JWT carries profileId as sub

  // Fetch profile email for device alert emails
  const profileResp = await fetch(
    `${process.env.USER_SERVICE_INTERNAL_URL}/internal/users/by-account/${encodeURIComponent(accountNumber)}`,
    { headers: { 'x-service-secret': process.env.INTERNAL_SERVICE_SECRET! } },
  );
  if (!profileResp.ok) throw new AppError('ACCOUNT_NOT_FOUND', 404);
  const accountData = await profileResp.json() as { email?: string; profileId?: string };

  const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ?? req.ip ?? '';
  const ua = req.headers['user-agent'] ?? '';

  const result = await selectAccount(
    profileId,
    accountNumber,
    {
      ...(deviceFingerprint !== undefined && { deviceFingerprint }),
      ...(deviceLabel !== undefined && { deviceLabel }),
    },
    ip, ua,
    accountData.email ?? '',
  );
  res.json({ success: true, data: result });
});

/**
 * GET /api/live/accounts
 *
 * Returns all live AND demo trading accounts linked to the current user's profile.
 * Accepts both Portal JWT (typ: 'portal') and Trading JWT (typ: 'access').
 */
router.get('/accounts', authenticate, async (req: Request, res: Response) => {
  // For trading JWT: sub is userId (LiveUser.id). Resolve profileId first.
  // For portal JWT: sub is profileId directly.
  const token = req.user!;
  let profileId: string;

  if (token.typ === 'portal') {
    profileId = token.sub;
  } else {
    // Trading JWT — resolve the profile from the account
    const userResp = await fetch(
      `${process.env.USER_SERVICE_INTERNAL_URL}/internal/users/${token.sub}?userType=${token.userType}`,
      { headers: { 'x-service-secret': process.env.INTERNAL_SERVICE_SECRET! } },
    );
    if (!userResp.ok) throw new AppError('USER_NOT_FOUND', 404);
    const userData = await userResp.json() as { profileId?: string };
    if (!userData.profileId) throw new AppError('NO_PROFILE', 404);
    profileId = userData.profileId;
  }

  const accountsResp = await fetch(
    `${process.env.USER_SERVICE_INTERNAL_URL}/internal/accounts/${profileId}`,
    { headers: { 'x-service-secret': process.env.INTERNAL_SERVICE_SECRET! } },
  );
  const data = await accountsResp.json() as { success: boolean; data: unknown };
  res.json({ success: true, data: data.data });
});

/**
 * POST /api/live/accounts
 *
 * Opens a new live trading account under the current user's profile.
 * No email re-verification needed — profile is already verified.
 * Accepts both Portal JWT and Trading JWT.
 *
 * Body: { groupName?, currency?, leverage?, tradingPassword? }
 * Returns: { accountNumber, tradingPassword? (shown once if auto-generated) }
 */
router.post('/accounts', authenticate, validate(openNewAccountSchema), async (req: Request, res: Response) => {
  const token = req.user!;
  let profileId: string;

  if (token.typ === 'portal') {
    profileId = token.sub;
  } else {
    const userResp = await fetch(
      `${process.env.USER_SERVICE_INTERNAL_URL}/internal/users/${token.sub}?userType=${token.userType}`,
      { headers: { 'x-service-secret': process.env.INTERNAL_SERVICE_SECRET! } },
    );
    if (!userResp.ok) throw new AppError('USER_NOT_FOUND', 404);
    const userData = await userResp.json() as { profileId?: string };
    if (!userData.profileId) throw new AppError('NO_PROFILE', 404);
    profileId = userData.profileId;
  }

  const { groupName, currency, leverage, tradingPassword } = req.body as {
    groupName: string; currency: string; leverage: number; tradingPassword?: string;
  };

  const result = await openNewAccount(profileId, {
    groupName,
    currency,
    leverage,
    ...(tradingPassword !== undefined && { tradingPassword }),
  });
  res.status(201).json({ success: true, data: result });
});

export default router;
