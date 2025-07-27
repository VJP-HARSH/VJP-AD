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
    if (!requester || (requester.adminType !== 'Super Admin' && requester.adminType !== 'TEACHER' && requester.adminType !== 'ADMIN')) {
      return res.status(403).json({ message: 'Only Super Admin, Teacher, or Admin can approve.' });
    }
    const admin = await Admin.findById(adminId);
    if (!admin) {
      return res.status(404).json({ message: 'Admin not found.' });
    }
    // Only Super Admin can approve admins/teachers, Teacher can only approve students, Admin can approve students and teachers
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
    } else if (requester.adminType === 'ADMIN') {
      if (admin.adminType === 'STUDENT' && !rollNo) {
        return res.status(400).json({ message: 'Roll number is required for students.' });
      }
      if (admin.adminType === 'STUDENT' && rollNo) {
        // Check uniqueness for students
        const existingRoll = await Admin.findOne({ rollNo });
        if (existingRoll) {
          return res.status(400).json({ message: 'Roll number already exists.' });
        }
        admin.rollNo = rollNo;
      }
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
    if (!requester || (requester.adminType !== 'Super Admin' && requester.adminType !== 'TEACHER' && requester.adminType !== 'ADMIN')) {
      return res.status(403).json({ message: 'Only Super Admin, Teacher, or Admin can view pending requests.' });
    }
    let pending;
    if (requester.adminType === 'Super Admin') {
      pending = await Admin.find({ isApproved: false, adminType: { $ne: 'Super Admin' } });
    } else if (requester.adminType === 'TEACHER') {
      pending = await Admin.find({ isApproved: false, adminType: 'STUDENT' });
    } else if (requester.adminType === 'ADMIN') {
      pending = await Admin.find({ isApproved: false, adminType: { $in: ['STUDENT', 'TEACHER'] } });
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
    if (!requester || (requester.adminType !== 'Super Admin' && requester.adminType !== 'TEACHER' && requester.adminType !== 'ADMIN')) {
      return res.status(403).json({ message: 'Only Super Admin, Teacher, or Admin can reject.' });
    }
    const admin = await Admin.findById(adminId);
    if (!admin) {
      return res.status(404).json({ message: 'Admin not found.' });
    }
    // Only Super Admin can reject admins/teachers, Teacher can only reject students, Admin can reject students and teachers
    if (requester.adminType === 'TEACHER' && admin.adminType !== 'STUDENT') {
      return res.status(403).json({ message: 'Teachers can only reject students.' });
    }
    if (requester.adminType === 'ADMIN' && admin.adminType === 'Super Admin') {
      return res.status(403).json({ message: 'Admins cannot reject Super Admin accounts.' });
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
    console.log('User ID from token:', req.user.id);
    const requester = await Admin.findById(req.user.id);
    console.log('Requester found:', requester ? 'Yes' : 'No');
    if (requester) {
      console.log('Requester adminType:', requester.adminType);
      console.log('Requester isApproved:', requester.isApproved);
    }
    
    if (!requester) {
      return res.status(403).json({ message: 'User not found in database.' });
    }
    
    if (!requester.isApproved && requester.adminType !== 'Super Admin') {
      return res.status(403).json({ message: 'Your account is not approved yet.' });
    }
    
    if (requester.adminType !== 'Super Admin' && requester.adminType !== 'TEACHER' && requester.adminType !== 'ADMIN') {
      return res.status(403).json({ 
        message: 'Only Super Admin, Teacher, or Admin can view all students.',
        userType: requester.adminType 
      });
    }
    
    const students = await Admin.find({ adminType: 'STUDENT', isApproved: true });
    console.log('Students found:', students.length);
    res.json(students);
  } catch (err) {
    console.error('Error in getAllStudents:', err);
    res.status(500).json({ message: 'Failed to fetch students.', error: err.message });
  }
};

// Get dashboard statistics
exports.getDashboardStats = async (req, res) => {
  try {
    console.log('Dashboard Stats - User ID from token:', req.user.id);
    const requester = await Admin.findById(req.user.id);
    console.log('Dashboard Stats - Requester found:', requester ? 'Yes' : 'No');
    if (requester) {
      console.log('Dashboard Stats - Requester adminType:', requester.adminType);
      console.log('Dashboard Stats - Requester isApproved:', requester.isApproved);
    }
    
    if (!requester) {
      return res.status(403).json({ message: 'User not found in database.' });
    }
    
    if (!requester.isApproved && requester.adminType !== 'Super Admin') {
      return res.status(403).json({ message: 'Your account is not approved yet.' });
    }
    
    if (requester.adminType !== 'Super Admin' && requester.adminType !== 'TEACHER' && requester.adminType !== 'ADMIN') {
      return res.status(403).json({ 
        message: 'Only Super Admin, Teacher, or Admin can view dashboard stats.',
        userType: requester.adminType 
      });
    }

    // Get counts for different user types
    const totalStudents = await Admin.countDocuments({ adminType: 'STUDENT', isApproved: true });
    const totalTeachers = await Admin.countDocuments({ adminType: 'TEACHER', isApproved: true });
    const totalAdmins = await Admin.countDocuments({ adminType: 'ADMIN', isApproved: true });
    
    // Get pending requests based on user type
    let pendingRequests;
    if (requester.adminType === 'Super Admin') {
      pendingRequests = await Admin.countDocuments({ isApproved: false, adminType: { $ne: 'Super Admin' } });
    } else if (requester.adminType === 'TEACHER') {
      pendingRequests = await Admin.countDocuments({ isApproved: false, adminType: 'STUDENT' });
    } else if (requester.adminType === 'ADMIN') {
      pendingRequests = await Admin.countDocuments({ isApproved: false, adminType: { $in: ['STUDENT', 'TEACHER'] } });
    } else {
      pendingRequests = 0;
    }

    // Calculate approved users
    const approvedUsers = totalStudents + totalTeachers + totalAdmins;

    res.json({
      totalStudents,
      totalTeachers,
      totalAdmins,
      pendingRequests,
      approvedUsers
    });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch dashboard statistics.', error: err.message });
  }
};

// Get all approved teachers
exports.getAllTeachers = async (req, res) => {
  try {
    const requester = await Admin.findById(req.user.id);
    if (!requester || (requester.adminType !== 'Super Admin' && requester.adminType !== 'ADMIN')) {
      return res.status(403).json({ message: 'Only Super Admin or Admin can view all teachers.' });
    }
    const teachers = await Admin.find({ adminType: 'TEACHER', isApproved: true });
    res.json(teachers);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch teachers.', error: err.message });
  }
};

// Test endpoint to check authentication and user status
exports.testAuth = async (req, res) => {
  try {
    console.log('Test Auth - User ID from token:', req.user.id);
    const requester = await Admin.findById(req.user.id);
    
    if (!requester) {
      return res.status(404).json({ 
        message: 'User not found in database.',
        tokenUserId: req.user.id 
      });
    }
    
    res.json({
      message: 'Authentication successful',
      user: {
        id: requester._id,
        fullName: requester.fullName,
        email: requester.email,
        adminType: requester.adminType,
        isApproved: requester.isApproved,
        createdAt: requester.createdAt
      }
    });
  } catch (err) {
    console.error('Error in testAuth:', err);
    res.status(500).json({ message: 'Test failed.', error: err.message });
  }
};

// Get all users (Super Admin only)
exports.getAllUsers = async (req, res) => {
  try {
    const requester = await Admin.findById(req.user.id);
    if (!requester || requester.adminType !== 'Super Admin') {
      return res.status(403).json({ message: 'Only Super Admin can view all users.' });
    }
    
    const users = await Admin.find({ 
      adminType: { $ne: 'Super Admin' },
      isApproved: true 
    }).select('-password');
    
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch users.', error: err.message });
  }
}; 