const mongoose = require('mongoose');

const adminSchema = new mongoose.Schema({
    photo: { type: String, default: 'default.png' },
    email: { type: String, required: true, unique: true },
    mobile: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    fullName: { type: String, required: true },
    dob: { type: Date },
    gender: { type: String, enum: ['Male', 'Female', 'Other'] },
    address: { type: String },
    rollNo: { type: String, unique: true, sparse: true },
    adminType: {
        type: String,
        enum: ['Super Admin', 'ADMIN', 'TEACHER', 'STUDENT'],
        required: true
    },
    isApproved: { type: Boolean, default: false },
    twoFactorEnabled: { type: Boolean, default: false },
    twoFactorSecret: { type: String, default: '' }
});

module.exports = mongoose.model('Admin', adminSchema);
