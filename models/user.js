const mongoose = require('mongoose');

// --- Student Schema (Nested in User)
const StudentSchema = new mongoose.Schema({
    name: { type: String, required: true },
});

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['driver', 'rider', 'secretary', 'admin'], required: true },
  parentName: { type: String }, // For riders
  phoneNumber: { type: String },
  address: { type: String },
  routeNumber: { type: Number, default: 1 },
  students: [StudentSchema], // Array of students for riders
  // Fields for Password Reset
  passwordResetToken: { type: String },
  passwordResetExpires: { type: Date },
  passwordHistory: { type: [String], default: [] }, // To store old password hashes
  temporaryAddressHistory: { type: [String], default: [] }, // Store last 3 temp addresses
  isDeleted: { type: Boolean, default: false, index: true }, // For soft deletes
  deletionDate: { type: Date } // To track when the user was soft-deleted
});

module.exports = mongoose.model('User', UserSchema);