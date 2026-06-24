import { Router } from 'express';
import { verifyGoogleToken } from '../controllers/googleAuthController';

const router = Router();

// Step 3: verify-only endpoint for Postman/testing (login flow comes in Step 4)
router.post('/google/verify', verifyGoogleToken);

export default router;
