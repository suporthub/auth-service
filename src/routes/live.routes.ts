import { Router, Request, Response } from 'express';
import { 
  registerController, 
  loginController,
  getMeController,
  getKycController,
  getAccountsController,
  selectAccountController,
  openLiveAccountController,
  openDemoAccountController
} from '../modules/live/live.controller';
import { validate } from '../middleware/validate';
import { loginRateLimit, registerRateLimit } from '../middleware/rateLimiter';
import { authenticate, authenticatePortal } from '../middleware/authenticate';
import {
  liveRegisterSchema,
  liveLoginSchema,
  openLiveAccountSchema,
  openDemoAccountSchema,
} from '../modules/live/live.schema';
import { refreshSession, logoutSession, listSessions } from '../modules/shared/session.service';
import { regenerateViewPassword } from '../modules/shared/password.service';

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
 * Called AFTER a login where status === 'account_selection_required'.
 */
router.post('/select-account', authenticatePortal, selectAccountController);

/**
 * GET /api/live/me
 * Returns core UserProfile details (identity).
 */
router.get('/me', authenticate, getMeController);

/**
 * GET /api/live/kyc
 * Returns detailed KYC status and proofs.
 */
router.get('/kyc', authenticate, getKycController);

/**
 * GET /api/live/accounts
 * Returns all live AND demo trading accounts linked to the current user.
 */
router.get('/accounts', authenticate, getAccountsController);

/**
 * POST /api/live/accounts
 * Opens a new live trading account under the current user's verified profile.
 */
router.post('/accounts', authenticate, validate(openLiveAccountSchema), openLiveAccountController);

/**
 * POST /api/live/accounts/demo
 * Opens a new demo trading account under the current user's profile. Doesn't require KYC.
 */
router.post('/accounts/demo', authenticate, validate(openDemoAccountSchema), openDemoAccountController);

export default router;
