import { Request, Response } from 'express';
import { registerLiveUser, loginLiveUser, selectAccount, openLiveAccount, openDemoAccount } from './live.service';
import { liveRegisterSchema, liveLoginSchema, selectAccountSchema, openLiveAccountSchema, openDemoAccountSchema } from './live.schema';
import { AppError } from '../../utils/errors';
import { config } from '../../config/env';
import { safeFetch } from '../../utils/fetch';

export async function registerController(req: Request, res: Response): Promise<void> {
  const input = liveRegisterSchema.parse(req.body);
  const result = await registerLiveUser(input);
  res.status(201).json({ success: true, ...result });
}

export async function loginController(req: Request, res: Response): Promise<void> {
  const input = liveLoginSchema.parse(req.body);
  const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ?? req.ip ?? '';
  const ua = req.headers['user-agent'] ?? '';
  const result = await loginLiveUser(input, ip, ua);
  res.json({ success: true, data: result });
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function resolveProfileId(token: any): Promise<string> {
  if (token.typ === 'portal') return token.sub;
  const userResp = await safeFetch(
    `${process.env.USER_SERVICE_INTERNAL_URL}/internal/users/${token.sub}?userType=${token.userType}`,
    { headers: { 'x-service-secret': config.internalSecret } }
  );
  if (!userResp.ok) throw new AppError('USER_NOT_FOUND', 404);
  const userData = await userResp.json() as { profileId?: string };
  if (!userData.profileId) throw new AppError('NO_PROFILE', 404);
  return userData.profileId;
}

export async function getMeController(req: Request, res: Response): Promise<void> {
  const profileId = await resolveProfileId(req.user!);
  const meResp = await safeFetch(
    `${process.env.USER_SERVICE_INTERNAL_URL}/internal/profiles/me/${profileId}`, 
    { headers: { 'x-service-secret': config.internalSecret } }
  );
  if (!meResp.ok) throw new AppError('PROFILE_NOT_FOUND', 404);
  const data = await meResp.json();
  res.json({ success: true, data });
}

export async function getKycController(req: Request, res: Response): Promise<void> {
  const profileId = await resolveProfileId(req.user!);
  const kycResp = await safeFetch(
    `${process.env.USER_SERVICE_INTERNAL_URL}/internal/profiles/kyc/${profileId}`, 
    { headers: { 'x-service-secret': config.internalSecret } }
  );
  if (!kycResp.ok) throw new AppError('KYC_NOT_FOUND', 404);
  const data = await kycResp.json();
  res.json({ success: true, data });
}

export async function getAccountsController(req: Request, res: Response): Promise<void> {
  const profileId = await resolveProfileId(req.user!);
  const accountsResp = await safeFetch(
    `${process.env.USER_SERVICE_INTERNAL_URL}/internal/accounts/${profileId}`,
    { headers: { 'x-service-secret': config.internalSecret } }
  );
  const data = await accountsResp.json() as { success: boolean; data: unknown };
  res.json({ success: true, data: data.data });
}

export async function selectAccountController(req: Request, res: Response): Promise<void> {
  const { accountNumber, deviceFingerprint, deviceLabel } = selectAccountSchema.parse(req.body);
  const profileId = req.user!.sub; // Portal JWT carries profileId as sub

  const profileResp = await safeFetch(
    `${process.env.USER_SERVICE_INTERNAL_URL}/internal/users/by-account/${encodeURIComponent(accountNumber)}`,
    { headers: { 'x-service-secret': config.internalSecret } }
  );
  if (!profileResp.ok) throw new AppError('ACCOUNT_NOT_FOUND', 404);
  await profileResp.json(); // exhaust the stream but ignore data since it's unused

  const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ?? req.ip ?? '';
  const ua = req.headers['user-agent'] ?? '';

  const result = await selectAccount(
    profileId,
    accountNumber,
    {
      ...(deviceFingerprint !== undefined && { deviceFingerprint }),
      ...(deviceLabel !== undefined && { deviceLabel }),
    },
    ip, ua
  );
  res.json({ success: true, data: result });
}

export async function openLiveAccountController(req: Request, res: Response): Promise<void> {
  const profileId = await resolveProfileId(req.user!);
  const options = openLiveAccountSchema.parse(req.body);
  const result = await openLiveAccount(profileId, options);
  res.status(201).json({ success: true, data: result });
}

export async function openDemoAccountController(req: Request, res: Response): Promise<void> {
  const profileId = await resolveProfileId(req.user!);
  const options = openDemoAccountSchema.parse(req.body);
  const result = await openDemoAccount(profileId, options);
  res.status(201).json({ success: true, data: result });
}
