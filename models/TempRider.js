const mongoose = require('mongoose');

const StudentSchema = new mongoose.Schema({
  name: { type: String, required: true }
});

const TempRiderSchema = new mongoose.Schema({
  parentName: { type: String, required: true },
  phoneNumber: { type: String },
  address: { type: String },
  students: [StudentSchema],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // admin who created the roster entry
  isDeleted: { type: Boolean, default: false },
  deletionDate: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('TempRider', TempRiderSchema);
