const mongoose = require('mongoose');

const NonOperationSchema = new mongoose.Schema({
  date: { type: Date, required: true, unique: true },
  occasion: { type: String, default: '' },
  groupId: { type: String },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('NonOperation', NonOperationSchema);
