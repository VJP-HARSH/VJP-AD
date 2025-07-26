const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');
const multer = require('multer');
const auth = require('../middleware/auth');

// Multer setup for photo upload
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'backend/uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage });

// Registration route (photo upload supported)
router.post('/register', upload.single('photo'), adminController.register);

// Login route
router.post('/login', adminController.login);

// Get current admin profile
router.get('/me', auth, adminController.getMe);

// Approve admin (Super Admin only)
router.put('/approve/:adminId', auth, adminController.approveAdmin);

// List pending admins (Super Admin only)
router.get('/pending', auth, adminController.listPendingAdmins);

// Reject admin (Super Admin only)
router.delete('/reject/:adminId', auth, adminController.rejectAdmin);

module.exports = router; 