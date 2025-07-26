const Admin = require('../models/admin');
const bcrypt = require('bcryptjs');

const ensureSuperAdmin = async () => {
  const email = 'sadmin@gmail.com';
  const mobile = '1236547890';
  const password = '121212';
  const fullName = 'admin harsh';
  const adminType = 'Super Admin';
  const photo = 'default.png';

  const existing = await Admin.findOne({ email });
  if (!existing) {
    const hashedPassword = await bcrypt.hash(password, 10);
    await Admin.create({
      photo,
      email,
      mobile,
      password: hashedPassword,
      fullName,
      adminType,
      isApproved: true
    });
    console.log('Super Admin created');
  } else {
    console.log('Super Admin already exists');
  }
};

module.exports = ensureSuperAdmin; 