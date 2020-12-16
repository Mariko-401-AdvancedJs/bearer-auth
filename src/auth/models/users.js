'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const SECRET = process.env.SECRET;

const users = mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
}, { toJSON: { virtuals: true } });

// Adds a virtual field to the schema. We can see it, but it never persists
// So, on every user object ... this.token is now readable!
users.virtual('token').get(function () {
  let tokenObject = {
    username: this.username,
  }
  // return jwt.sign(tokenObject, SECRET)
  return jwt.sign(tokenObject, SECRET, { "expiresIn": "900000" })
});

users.pre('save', async function () {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
});

// BASIC AUTH
users.statics.authenticateBasic = async function (username, password) {
  const user = await this.findOne({ username })
  const valid = await bcrypt.compare(password, user.password)
  if (valid) { return user; }
  throw new Error('Invalid User');
}

// BEARER AUTH
users.statics.authenticateWithToken = async function (token) {
  // console.log('token', token);
  try {
    const parsedToken = await jwt.verify(token, SECRET);
    // console.log('parsed token', parsedToken);
    const user = this.findOne({ username: parsedToken.username })
    if (user) { return user; }
    throw new Error('User Not Found');
  } catch (e) {
    throw new Error(e.message)
  }
}


module.exports = mongoose.model('users', users);
