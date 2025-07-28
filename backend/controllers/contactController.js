const Contact = require('../models/contact');

// Submit contact form
exports.submitContact = async (req, res) => {
  try {
    console.log('Submitting contact form:', req.body);
    const { name, email, subject, message } = req.body;
    
    if (!name || !email || !subject || !message) {
      return res.status(400).json({ message: 'All fields are required.' });
    }

    const contact = new Contact({
      name,
      email,
      subject,
      message
    });

    await contact.save();
    console.log('Contact saved successfully:', contact._id);
    res.status(201).json({ message: 'Message sent successfully!', contact });
  } catch (err) {
    console.error('Error submitting contact:', err);
    res.status(500).json({ message: 'Failed to send message.', error: err.message });
  }
};

// Get all contact messages (for admin)
exports.getAllContacts = async (req, res) => {
  try {
    console.log('Getting all contacts...');
    const { search, status, dateFilter } = req.query;
    let query = {};

    // Search filter
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { subject: { $regex: search, $options: 'i' } }
      ];
    }

    // Status filter
    if (status && status !== '') {
      query.status = status;
    }

    // Date filter
    if (dateFilter) {
      const now = new Date();
      let startDate;
      
      switch (dateFilter) {
        case 'today':
          startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate());
          break;
        case 'week':
          startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
          break;
        case 'month':
          startDate = new Date(now.getFullYear(), now.getMonth(), 1);
          break;
        default:
          startDate = null;
      }
      
      if (startDate) {
        query.date = { $gte: startDate };
      }
    }

    console.log('Query:', query);
    const contacts = await Contact.find(query).sort({ date: -1 });
    console.log('Found contacts:', contacts.length);
    res.json(contacts);
  } catch (err) {
    console.error('Error in getAllContacts:', err);
    res.status(500).json({ message: 'Failed to fetch contacts.', error: err.message });
  }
};

// Get single contact message
exports.getContact = async (req, res) => {
  try {
    const contact = await Contact.findById(req.params.id);
    if (!contact) {
      return res.status(404).json({ message: 'Contact message not found.' });
    }
    res.json(contact);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch contact.', error: err.message });
  }
};

// Update contact status
exports.updateContactStatus = async (req, res) => {
  try {
    const { status } = req.body;
    const contact = await Contact.findById(req.params.id);
    
    if (!contact) {
      return res.status(404).json({ message: 'Contact message not found.' });
    }

    contact.status = status;
    await contact.save();
    
    res.json({ message: 'Status updated successfully.', contact });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update status.', error: err.message });
  }
};

// Delete contact message
exports.deleteContact = async (req, res) => {
  try {
    const contact = await Contact.findByIdAndDelete(req.params.id);
    if (!contact) {
      return res.status(404).json({ message: 'Contact message not found.' });
    }
    res.json({ message: 'Contact message deleted successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to delete contact.', error: err.message });
  }
};

// Bulk delete contacts
exports.bulkDeleteContacts = async (req, res) => {
  try {
    const { ids } = req.body;
    if (!ids || !Array.isArray(ids)) {
      return res.status(400).json({ message: 'Invalid IDs provided.' });
    }

    const result = await Contact.deleteMany({ _id: { $in: ids } });
    res.json({ message: `${result.deletedCount} messages deleted successfully.` });
  } catch (err) {
    res.status(500).json({ message: 'Failed to delete messages.', error: err.message });
  }
};

// Reply to contact message
exports.replyToContact = async (req, res) => {
  try {
    const { to, subject, message, markAsReplied } = req.body;
    const contactId = req.params.id;
    
    if (!to || !subject || !message) {
      return res.status(400).json({ message: 'All fields are required.' });
    }

    const contact = await Contact.findById(contactId);
    if (!contact) {
      return res.status(404).json({ message: 'Contact message not found.' });
    }

    // Here you would typically send the email using a service like Nodemailer
    // For now, we'll just log the reply and update the status
    console.log('Sending reply email:', {
      to,
      subject,
      message,
      originalMessage: contact.message,
      originalSender: contact.name
    });

    // Update contact status if requested
    if (markAsReplied) {
      contact.status = 'replied';
      await contact.save();
    }

    // In a real implementation, you would:
    // 1. Send email using Nodemailer or similar service
    // 2. Store reply in database
    // 3. Update contact status
    
    res.json({ 
      message: 'Reply sent successfully!',
      emailDetails: {
        to,
        subject,
        message,
        sentAt: new Date()
      }
    });
  } catch (err) {
    console.error('Error sending reply:', err);
    res.status(500).json({ message: 'Failed to send reply.', error: err.message });
  }
};

// Export contacts to CSV
exports.exportContacts = async (req, res) => {
  try {
    const contacts = await Contact.find().sort({ date: -1 });
    
    // Simple CSV generation without external dependency
    let csv = 'Name,Email,Subject,Message,Status,Date\n';
    contacts.forEach(contact => {
      const name = `"${contact.name.replace(/"/g, '""')}"`;
      const email = `"${contact.email}"`;
      const subject = `"${contact.subject.replace(/"/g, '""')}"`;
      const message = `"${contact.message.replace(/"/g, '""')}"`;
      const status = `"${contact.status}"`;
      const date = `"${contact.date.toISOString()}"`;
      csv += `${name},${email},${subject},${message},${status},${date}\n`;
    });
    
    res.header('Content-Type', 'text/csv');
    res.attachment('contact-messages.csv');
    res.send(csv);
  } catch (err) {
    res.status(500).json({ message: 'Failed to export contacts.', error: err.message });
  }
}; 