const express = require('express');
const router = express.Router();
const aboutStaffController = require('../controllers/aboutStaffController');
const auth = require('../middleware/auth');

// Public: Get all staff
router.get('/staff', aboutStaffController.getAllStaff);
// Protected: Update all staff
router.post('/staff', auth, aboutStaffController.updateAllStaff);

module.exports = router; 