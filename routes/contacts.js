// routes/contacts.js - Contact Routes

const express = require('express');
const router = express.Router();

const Contact = require('../models/Contact');
const Event = require('../models/Event');
const { authenticateToken } = require('../middleware/auth');
const { validators } = require('../middleware/validators');

// Get all contacts
router.get('/', authenticateToken, async (req, res) => {
  try {
    const contacts = await Contact.find({ userId: req.userId })
      .sort({ updatedAt: -1 })
      .limit(1000)
      .lean();
    res.json(contacts);
  } catch (error) {
    console.error('Get contacts error:', error.message);
    res.status(500).json({ error: 'Failed to get contacts' });
  }
});

// Sync contacts
router.post('/sync', authenticateToken, async (req, res) => {
  try {
    const { contacts } = req.body;

    if (!Array.isArray(contacts)) {
      return res.status(400).json({ error: 'Contacts must be an array' });
    }

    if (contacts.length > 500) {
      return res.status(400).json({ error: 'Too many contacts. Maximum 500 per sync.' });
    }

    const serverContacts = await Contact.find({ userId: req.userId });
    const serverContactMap = new Map(serverContacts.map(c => [c._id?.toString() || c.id, c]));

    const toUpdate = [];
    const toCreate = [];

    for (const clientContact of contacts) {
      const serverContact = serverContactMap.get(clientContact._id?.toString() || clientContact.id);

      if (!serverContact) {
        toCreate.push({ userId: req.userId, ...clientContact });
      } else {
        const clientUpdated = new Date(clientContact.updatedAt);
        const serverUpdated = new Date(serverContact.updatedAt);

        if (clientUpdated > serverUpdated) {
          const { _id, ...updateData } = clientContact;
          toUpdate.push({
            filter: { userId: req.userId, _id: clientContact._id },
            update: { $set: updateData }
          });
        }
      }
    }

    let createdCount = 0;
    let mergedCount = 0;
    
    if (toCreate.length > 0) {
      for (const contact of toCreate) {
        const safeName = validators.sanitizeString(contact.name, 200).toLowerCase();
        
        const existingByName = await Contact.findOne({ userId: req.userId, name: safeName });
        
        if (existingByName) {
          const existingTypes = (existingByName.paymentMethods || []).map(p => p.type);
          const newMethods = (contact.paymentMethods || []).filter(p => !existingTypes.includes(p.type));
          const mergedPaymentMethods = [...(existingByName.paymentMethods || []), ...newMethods];
          
          const updateData = {
            name: contact.name,
            phone: contact.phone || existingByName.phone,
            email: contact.email || existingByName.email,
            skills: [...new Set([...(existingByName.skills || []), ...(contact.skills || [])])].slice(0, 50),
            notes: [...(existingByName.notes || []), ...(contact.notes || [])].slice(0, 100),
            debts: [...(existingByName.debts || []), ...(contact.debts || [])].slice(0, 50),
            reminders: [...(existingByName.reminders || []), ...(contact.reminders || [])].slice(0, 50),
            paymentMethods: mergedPaymentMethods.slice(0, 20),
            metadata: contact.metadata || existingByName.metadata || {},
            updatedAt: new Date().toISOString()
          };
  
          await Contact.updateOne({ userId: req.userId, name: safeName }, { $set: updateData });
          mergedCount++;
        } else {
          await Contact.create(contact);
          createdCount++;
        }
      }
    }

    for (const { filter, update } of toUpdate) {
      await Contact.updateOne(filter, update);
    }

    const allContacts = await Contact.find({ userId: req.userId }).lean();

    await Event.create({
      userId: req.userId,
      event: 'contacts_synced',
      properties: { total: allContacts.length, created: createdCount, merged: mergedCount, updated: toUpdate.length }
    });

    res.json({
      contacts: allContacts,
      stats: { total: allContacts.length, created: createdCount, merged: mergedCount, updated: toUpdate.length }
    });
  } catch (error) {
    console.error('Sync error:', error.message);
    res.status(500).json({ error: 'Sync failed' });
  }
});

// Update contact
router.put('/:id', authenticateToken, async (req, res) => {
  try {
    if (!validators.isObjectId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid contact ID' });
    }

    const { _id, ...updateData } = req.body;
    
    const contact = await Contact.findOneAndUpdate(
      { userId: req.userId, _id: req.params.id },
      { $set: { ...updateData, updatedAt: new Date().toISOString() } },
      { new: true }
    );

    if (!contact) return res.status(404).json({ error: 'Contact not found' });
    res.json(contact);
  } catch (error) {
    console.error('Update error:', error.message);
    res.status(500).json({ error: 'Failed to update contact' });
  }
});

// Delete contact
router.delete('/:id', authenticateToken, async (req, res) => {
  try {
    if (!validators.isObjectId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid contact ID' });
    }

    const contact = await Contact.findOneAndDelete({ userId: req.userId, _id: req.params.id });
    if (!contact) return res.status(404).json({ error: 'Contact not found' });

    await Event.create({ userId: req.userId, event: 'contact_deleted' });
    res.json({ message: 'Contact deleted' });
  } catch (error) {
    console.error('Delete error:', error.message);
    res.status(500).json({ error: 'Failed to delete contact' });
  }
});

module.exports = router;