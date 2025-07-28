const AboutStaff = require('../models/aboutStaff');

// Get all staff (teachers and admins)
exports.getAllStaff = async (req, res) => {
  try {
    const staff = await AboutStaff.find();
    res.json(staff);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch staff.' });
  }
};

// Replace all staff (bulk update)
exports.updateAllStaff = async (req, res) => {
  try {
    const { staff } = req.body;
    if (!Array.isArray(staff)) return res.status(400).json({ message: 'Staff must be an array.' });
    // Remove all existing
    await AboutStaff.deleteMany({});
    // Insert new
    await AboutStaff.insertMany(staff);
    res.json({ message: 'Staff updated successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update staff.' });
  }
}; 