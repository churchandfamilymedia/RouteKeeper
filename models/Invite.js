// models/Invite.js
const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');

const InviteSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true, // Ensure only one active invite per email
        trim: true
    },
    role: {
        type: String,
        enum: ['rider', 'secretary', 'driver', 'admin'],
        default: 'rider'
    },
    token: {
        type: String,
        required: true,
        default: () => uuidv4(), // Generate a UUID for the token
        index: true
    },
    expiresAt: { type: Date, default: () => new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), index: { expires: '0' } }, // Expires in 7 days
    isUsed: { type: Boolean, default: false }
});

module.exports = mongoose.model('Invite', InviteSchema);