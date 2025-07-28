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

// Get all approved students (for teacher dashboard)
router.get('/all', auth, adminController.getAllStudents);

// Get dashboard statistics
router.get('/stats', auth, adminController.getDashboardStats);

// Get all approved teachers (Super Admin only)
router.get('/teachers', auth, adminController.getAllTeachers);

// Test authentication endpoint
router.get('/test-auth', auth, adminController.testAuth);

// User management routes
router.get('/users', auth, adminController.getAllUsers); // supports search/filter
router.post('/users', auth, adminController.addUser);
router.put('/users/:id', auth, adminController.editUser);
router.patch('/users/:id/status', auth, adminController.toggleUserStatus);
router.delete('/users/:id', auth, adminController.deleteUser);
router.post('/users/bulk', auth, adminController.bulkAction);
router.get('/users/export', adminController.exportUsers);

// Update user (teacher/student) details
router.put('/update/:id', auth, upload.single('photo'), adminController.updateAdmin);

// Add change password route
router.post('/change-password', auth, adminController.changePassword);

// 2FA routes
router.post('/2fa/setup', auth, adminController.setup2FA);
router.post('/2fa/verify', auth, adminController.verify2FA);
router.post('/2fa/disable', auth, adminController.disable2FA);

// Photo upload for About Us staff
router.post('/upload', upload.single('photo'), (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'No file uploaded.' });
  res.json({ filename: req.file.filename });
});

module.exports = router; 