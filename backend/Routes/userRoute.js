import express from 'express';
import { changePassword, forgotPassword, loginUser, logoutUser, registerUser, verification, verifyOTP } from '../controllers/userController.js';
import { isAuthenticated } from '../middlewares/isAuthenticated.js';
import { validateUser, userSchema } from '../validators/userValidate.js';

const router = express.Router();

router.post('/register', validateUser(userSchema), registerUser);
router.post('/signup', validateUser(userSchema), registerUser);
router.post('/verify', verification);
router.post('/login', loginUser);
router.post('/logout', isAuthenticated, logoutUser);
router.post('/forgot-password', forgotPassword);
router.post('/verify-otp/:email', verifyOTP);
router.post('/change-password/:email', validateUser(userSchema), changePassword);

export default router;