const express = require('express');
const router = express.Router();
const contactController = require('../controllers/contactController');
const auth = require('../middleware/auth');

// Public route for submitting contact form
router.post('/submit', contactController.submitContact);

// Admin routes (require authentication)
router.get('/', auth, contactController.getAllContacts);
router.get('/:id', auth, contactController.getContact);
router.patch('/:id/status', auth, contactController.updateContactStatus);
router.post('/:id/reply', auth, contactController.replyToContact);
router.delete('/:id', auth, contactController.deleteContact);
router.post('/bulk-delete', auth, contactController.bulkDeleteContacts);
router.get('/export/csv', auth, contactController.exportContacts);

module.exports = router; 