const mongoose = require('mongoose');
const nanoid = require('nanoid');

const affiliateLinkSchema = new mongoose.Schema({
  _id: { type: String, default: nanoid.nanoid },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  clicks: { type: Number, default: 0 },
});

module.exports = mongoose.model('AffiliateLink', affiliateLinkSchema);
