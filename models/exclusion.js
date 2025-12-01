const mongoose = require('mongoose');

const ExclusionSchema = new mongoose.Schema({
  parentId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  studentId: { type: mongoose.Schema.Types.ObjectId }, // The specific child
  date: { type: Date, required: true }
});

module.exports = mongoose.model('Exclusion', ExclusionSchema);