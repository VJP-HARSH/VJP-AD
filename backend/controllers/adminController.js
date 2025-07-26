const Admin = require('../models/admin');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Register a new admin (not Super Admin)
exports.register = async (req, res) => {
  try {
    const { email, mobile, password, fullName, adminType, dob, gender, address } = req.body;
    if (!['ADMIN', 'TEACHER', 'STUDENT'].includes(adminType)) {
      return res.status(400).json({ message: 'Invalid admin type. Only ADMIN, TEACHER, or STUDENT allowed.' });
    }
    const existing = await Admin.findOne({ $or: [{ email }, { mobile }] });
    if (existing) {
      return res.status(400).json({ message: 'Email or mobile already registered.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    let photo = req.file ? req.file.filename : 'default.png';
    const admin = new Admin({
      photo,
      email,
      mobile,
      password: hashedPassword,
      fullName,
      adminType,
      dob,
      gender,
      address,
      isApproved: false
    });
    await admin.save();
    res.status(201).json({ message: 'Registration successful. Awaiting approval.' });
  } catch (err) {
    res.status(500).json({ message: 'Registration failed.', error: err.message });
  }
};

// Login for admin (email or mobile)
exports.login = async (req, res) => {
  try {
    const { identifier, password } = req.body;
    const admin = await Admin.findOne({ $or: [{ email: identifier }, { mobile: identifier }] });
    if (!admin) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }
    if (admin.adminType !== 'Super Admin' && !admin.isApproved) {
      return res.status(403).json({ message: 'Account not approved by Super Admin.' });
    }
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }
    const token = jwt.sign({ id: admin._id, adminType: admin.adminType }, process.env.JWT_SECRET || 'your_jwt_secret', { expiresIn: '1d' });
    res.json({ token, admin: { id: admin._id, fullName: admin.fullName, adminType: admin.adminType, photo: admin.photo } });
  } catch (err) {
    res.status(500).json({ message: 'Login failed.', error: err.message });
  }
};

// Super Admin approves an admin
exports.approveAdmin = async (req, res) => {
  try {
    const { adminId } = req.params;
    const { rollNo } = req.body;
    const requester = await Admin.findById(req.user.id);
    if (!requester || (requester.adminType !== 'Super Admin' && requester.adminType !== 'TEACHER')) {
      return res.status(403).json({ message: 'Only Super Admin or Teacher can approve.' });
    }
    const admin = await Admin.findById(adminId);
    if (!admin) {
      return res.status(404).json({ message: 'Admin not found.' });
    }
    // Only Super Admin can approve admins/teachers, Teacher can only approve students
    if (requester.adminType === 'TEACHER') {
      if (admin.adminType !== 'STUDENT') {
        return res.status(403).json({ message: 'Teachers can only approve students.' });
      }
      if (!rollNo) {
        return res.status(400).json({ message: 'Roll number is required.' });
      }
      // Check uniqueness
      const existingRoll = await Admin.findOne({ rollNo });
      if (existingRoll) {
        return res.status(400).json({ message: 'Roll number already exists.' });
      }
      admin.rollNo = rollNo;
    }
    admin.isApproved = true;
    await admin.save();
    res.json({ message: 'Admin approved successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Approval failed.', error: err.message });
  }
};

// List all pending admins (for Super Admin)
exports.listPendingAdmins = async (req, res) => {
  try {
    const requester = await Admin.findById(req.user.id);
    if (!requester || (requester.adminType !== 'Super Admin' && requester.adminType !== 'TEACHER')) {
      return res.status(403).json({ message: 'Only Super Admin or Teacher can view pending students.' });
    }
    let pending;
    if (requester.adminType === 'Super Admin') {
      pending = await Admin.find({ isApproved: false, adminType: { $ne: 'Super Admin' } });
    } else if (requester.adminType === 'TEACHER') {
      pending = await Admin.find({ isApproved: false, adminType: 'STUDENT' });
    }
    res.json(pending);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch pending admins.', error: err.message });
  }
};

// Super Admin rejects (deletes) an admin request
exports.rejectAdmin = async (req, res) => {
  try {
    const { adminId } = req.params;
    const requester = await Admin.findById(req.user.id);
    if (!requester || (requester.adminType !== 'Super Admin' && requester.adminType !== 'TEACHER')) {
      return res.status(403).json({ message: 'Only Super Admin or Teacher can reject.' });
    }
    const admin = await Admin.findById(adminId);
    if (!admin) {
      return res.status(404).json({ message: 'Admin not found.' });
    }
    // Only Super Admin can reject admins/teachers, Teacher can only reject students
    if (requester.adminType === 'TEACHER' && admin.adminType !== 'STUDENT') {
      return res.status(403).json({ message: 'Teachers can only reject students.' });
    }
    await admin.deleteOne();
    res.json({ message: 'Admin request rejected and deleted.' });
  } catch (err) {
    res.status(500).json({ message: 'Rejection failed.', error: err.message });
  }
};

// Get current admin profile
exports.getMe = async (req, res) => {
  try {
    const admin = await Admin.findById(req.user.id).select('-password');
    if (!admin) {
      return res.status(404).json({ message: 'Admin not found.' });
    }
    res.json(admin);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch profile.', error: err.message });
  }
};

// Get all approved students (for teacher dashboard)
exports.getAllStudents = async (req, res) => {
  try {
    const requester = await Admin.findById(req.user.id);
    if (!requester || (requester.adminType !== 'Super Admin' && requester.adminType !== 'TEACHER')) {
      return res.status(403).json({ message: 'Only Super Admin or Teacher can view all students.' });
    }
    const students = await Admin.find({ adminType: 'STUDENT', isApproved: true });
    res.json(students);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch students.', error: err.message });
  }
}; 