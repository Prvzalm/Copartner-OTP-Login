const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  phoneNumber: { type: String, required: true, unique: true },
  otp: { type: String },
  token: { type: String }
});

module.exports = mongoose.model('User', userSchema);
