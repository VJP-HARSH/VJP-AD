const mongoose = require('mongoose');

const staffSchema = new mongoose.Schema({
  name: { type: String, required: true },
  position: { type: String, required: true },
  description: { type: String },
  photo: { type: String },
  contact: { type: String },
  role: { type: String, enum: ['Teacher', 'Admin'], required: true }
}, { timestamps: true });

module.exports = mongoose.model('AboutStaff', staffSchema); 