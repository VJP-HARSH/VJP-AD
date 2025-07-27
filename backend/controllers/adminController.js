const Admin = require('../models/admin');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const { Parser } = require('json2csv');

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
    // Do not return password
    res.json({
      fullName: admin.fullName,
      email: admin.email,
      mobile: admin.mobile,
      photo: admin.photo
    });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch profile.', error: err.message });
  }
};

// Update admin/teacher/student details (name, email, mobile, photo)
exports.updateAdmin = async (req, res) => {
  try {
    const { id } = req.params;
    const { fullName, email, mobile } = req.body;
    let photo = req.file ? req.file.filename : undefined;
    const requester = await Admin.findById(req.user.id);
    if (!requester || (requester.adminType !== 'Super Admin' && requester.adminType !== 'ADMIN' && requester._id.toString() !== id)) {
      return res.status(403).json({ message: 'Not authorized to update this user.' });
    }
    const admin = await Admin.findById(id);
    if (!admin) {
      return res.status(404).json({ message: 'User not found.' });
    }
    if (fullName) admin.fullName = fullName;
    if (email) admin.email = email;
    if (mobile) admin.mobile = mobile;
    if (photo) admin.photo = photo;
    await admin.save();
    const updated = await Admin.findById(id).select('-password');
    res.json({ message: 'Profile updated successfully.', user: updated });
  } catch (err) {
    res.status(500).json({ message: 'Update failed.', error: err.message });
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

// List all users with search/filter
exports.getAllUsers = async (req, res) => {
  try {
    const { search = '', role = '', status = '' } = req.query;
    const requester = await Admin.findById(req.user.id);
    if (!requester || (requester.adminType !== 'Super Admin' && requester.adminType !== 'ADMIN')) {
      return res.status(403).json({ message: 'Only Super Admin or Admin can view all users.' });
    }
    let query = { adminType: { $ne: 'Super Admin' } };
    if (role) query.adminType = role;
    if (status) query.isApproved = status === 'active';
    if (search) {
      query.$or = [
        { fullName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }
    const users = await Admin.find(query).select('-password');
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch users.', error: err.message });
  }
};
// Add new user
exports.addUser = async (req, res) => {
  try {
    const { fullName, email, mobile, adminType, password } = req.body;
    if (!fullName || !email || !adminType || !password) return res.status(400).json({ message: 'Missing required fields.' });
    const existing = await Admin.findOne({ email });
    if (existing) return res.status(400).json({ message: 'Email already exists.' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new Admin({ fullName, email, mobile, adminType, password: hashedPassword, isApproved: true });
    await user.save();
    res.status(201).json({ message: 'User added successfully.', user });
  } catch (err) {
    res.status(500).json({ message: 'Failed to add user.', error: err.message });
  }
};
// Edit user
exports.editUser = async (req, res) => {
  try {
    const { id } = req.params;
    const { fullName, email, mobile, adminType, isApproved, password } = req.body;
    const user = await Admin.findById(id);
    if (!user) return res.status(404).json({ message: 'User not found.' });
    if (fullName) user.fullName = fullName;
    if (email) user.email = email;
    if (mobile) user.mobile = mobile;
    if (adminType) user.adminType = adminType;
    if (typeof isApproved === 'boolean') user.isApproved = isApproved;
    if (password) user.password = await bcrypt.hash(password, 10);
    await user.save();
    res.json({ message: 'User updated successfully.', user });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update user.', error: err.message });
  }
};
// Enable/Disable user
exports.toggleUserStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const { isApproved } = req.body;
    const user = await Admin.findById(id);
    if (!user) return res.status(404).json({ message: 'User not found.' });
    user.isApproved = !!isApproved;
    await user.save();
    res.json({ message: `User ${isApproved ? 'enabled' : 'disabled'} successfully.`, user });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update status.', error: err.message });
  }
};
// Delete user
exports.deleteUser = async (req, res) => {
  try {
    const { id } = req.params;
    const user = await Admin.findById(id);
    if (!user) return res.status(404).json({ message: 'User not found.' });
    await user.deleteOne();
    res.json({ message: 'User deleted successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to delete user.', error: err.message });
  }
};
// Bulk actions
exports.bulkAction = async (req, res) => {
  try {
    const { ids, action } = req.body;
    if (!Array.isArray(ids) || !action) return res.status(400).json({ message: 'Invalid request.' });
    let result;
    if (action === 'delete') {
      result = await Admin.deleteMany({ _id: { $in: ids } });
    } else if (action === 'enable' || action === 'disable') {
      result = await Admin.updateMany({ _id: { $in: ids } }, { isApproved: action === 'enable' });
    }
    res.json({ message: 'Bulk action completed.', result });
  } catch (err) {
    res.status(500).json({ message: 'Bulk action failed.', error: err.message });
  }
};
// Export users as CSV
exports.exportUsers = async (req, res) => {
  try {
    // Accept token from header or query
    const authHeader = req.headers.authorization;
    let token = null;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    } else if (req.query.token) {
      token = req.query.token;
    }
    if (!token) {
      return res.status(401).json({ message: 'No token provided.' });
    }
    // Verify token
    const jwt = require('jsonwebtoken');
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    } catch (err) {
      return res.status(401).json({ message: 'Invalid token.' });
    }
    req.user = decoded;
    // Only allow Super Admin or Admin
    const AdminModel = require('../models/admin');
    const requester = await AdminModel.findById(req.user.id);
    if (!requester || (requester.adminType !== 'Super Admin' && requester.adminType !== 'ADMIN')) {
      return res.status(403).json({ message: 'Only Super Admin or Admin can export users.' });
    }
    // Export selected or all users
    let users;
    if (req.query.ids) {
      const ids = req.query.ids.split(',');
      users = await AdminModel.find({ _id: { $in: ids } }).select('-password');
    } else {
      users = await AdminModel.find({ adminType: { $ne: 'Super Admin' } }).select('-password');
    }
    const fields = ['fullName', 'email', 'mobile', 'adminType', 'isApproved'];
    const { Parser } = require('json2csv');
    const parser = new Parser({ fields });
    const csv = parser.parse(users);
    res.header('Content-Type', 'text/csv');
    res.attachment('users.csv');
    return res.send(csv);
  } catch (err) {
    res.status(500).json({ message: 'Export failed.', error: err.message });
  }
};

// Change password endpoint
exports.changePassword = async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const admin = await Admin.findById(req.user.id);
    if (!admin) return res.status(404).json({ message: 'User not found.' });

    const isMatch = await bcrypt.compare(oldPassword, admin.password);
    if (!isMatch) return res.status(400).json({ message: 'Current password is incorrect.' });

    admin.password = await bcrypt.hash(newPassword, 10);
    await admin.save();
    res.json({ message: 'Password changed successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to change password.', error: err.message });
  }
}; 

// 2FA Setup: Generate secret and QR code
exports.setup2FA = async (req, res) => {
  try {
    const admin = await Admin.findById(req.user.id);
    if (!admin) return res.status(404).json({ message: 'User not found.' });
    const secret = speakeasy.generateSecret({ name: 'VJP-AD-' + admin.email });
    admin.twoFactorSecret = secret.base32;
    await admin.save();
    const qr = await qrcode.toDataURL(secret.otpauth_url);
    res.json({ otpauth_url: secret.otpauth_url, qr });
  } catch (err) {
    res.status(500).json({ message: '2FA setup failed.', error: err.message });
  }
};
// 2FA Verify: Enable 2FA after verifying code
exports.verify2FA = async (req, res) => {
  try {
    const { token } = req.body;
    const admin = await Admin.findById(req.user.id);
    if (!admin || !admin.twoFactorSecret) return res.status(400).json({ message: '2FA not set up.' });
    const verified = speakeasy.totp.verify({
      secret: admin.twoFactorSecret,
      encoding: 'base32',
      token
    });
    if (!verified) return res.status(400).json({ message: 'Invalid 2FA code.' });
    admin.twoFactorEnabled = true;
    await admin.save();
    res.json({ message: '2FA enabled successfully.' });
  } catch (err) {
    res.status(500).json({ message: '2FA verification failed.', error: err.message });
  }
};
// 2FA Disable
exports.disable2FA = async (req, res) => {
  try {
    const admin = await Admin.findById(req.user.id);
    if (!admin) return res.status(404).json({ message: 'User not found.' });
    admin.twoFactorEnabled = false;
    admin.twoFactorSecret = '';
    await admin.save();
    res.json({ message: '2FA disabled.' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to disable 2FA.', error: err.message });
  }
}; 