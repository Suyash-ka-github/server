import { Request, Response } from 'express';
import { verifyGoogleIdToken } from '../services/googleAuthService';
import { hashIdentifierForLog } from '../utils/loginIdentifier';

export const verifyGoogleToken = async (req: Request, res: Response) => {
  try {
    const { idToken } = req.body;

    if (!idToken || typeof idToken !== 'string') {
      return res.status(400).json({
        success: false,
        message: 'ID token is required',
        error: 'Missing or invalid idToken in request body',
      });
    }

    const profile = await verifyGoogleIdToken(idToken);

    console.log(
      `[Google Auth] Token verified: googleId=${hashIdentifierForLog(profile.googleId)} email=${hashIdentifierForLog(profile.email)}`
    );

    return res.status(200).json({
      success: true,
      message: 'Google ID token verified',
      data: profile,
    });
  } catch (error) {
    console.error('[Google Auth] Token verification failed:', error);

    return res.status(401).json({
      success: false,
      message: 'Invalid Google ID token',
      error: error instanceof Error ? error.message : 'Verification failed',
    });
  }
};
