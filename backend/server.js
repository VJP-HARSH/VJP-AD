require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const connectDB = require('./config/db');
const adminRoutes = require('./routes/admin');
const ensureSuperAdmin = require('./config/superAdmin');

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, '../frontend')));

app.get('/api', (req, res) => {
  res.send({ status: 'API is running' });
});

app.use('/api/admin', adminRoutes);

const PORT = process.env.PORT || 5000;

connectDB().then(async () => {
  await ensureSuperAdmin();
  app.listen(PORT, () => {
    console.log('');
    console.log('================= Useful Links =================');
    console.log(`Frontend Home         http://localhost:${PORT}/`);
    console.log(`Register Page         http://localhost:${PORT}/auth/register.html`);
    console.log(`Login Page            http://localhost:${PORT}/auth/login.html`);
    console.log(`Super Admin Dashboard http://localhost:${PORT}/profile/superadmin.html`);
    console.log('');
    console.log(`API Health            [GET]    http://localhost:${PORT}/api`);
    console.log(`API Register          [POST]   http://localhost:${PORT}/api/admin/register`);
    console.log(`API Login             [POST]   http://localhost:${PORT}/api/admin/login`);
    console.log(`API Profile           [GET]    http://localhost:${PORT}/api/admin/me`);
    console.log(`API Pending Requests  [GET]    http://localhost:${PORT}/api/admin/pending`);
    console.log(`API Approve           [PUT]    http://localhost:${PORT}/api/admin/approve/:adminId`);
    console.log(`API Reject            [DELETE] http://localhost:${PORT}/api/admin/reject/:adminId`);
    console.log('================================================');
    console.log(`Server running on port ${PORT}`);
  });
});