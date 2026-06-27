import { Router } from 'express';
import { verifyGoogleToken, googleLogin } from '../controllers/googleAuthController';

const router = Router();

router.post('/google/verify', verifyGoogleToken);
router.post('/google', googleLogin);

export default router;
