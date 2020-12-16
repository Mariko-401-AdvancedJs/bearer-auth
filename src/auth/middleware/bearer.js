'use strict';

const users = require('../models/users.js')

module.exports = async (req, res, next) => {
  // console.log('hitting bearer:', req.body);

  try {

    if (!req.headers.authorization) { next('Invalid Login') }
    // console.log('past if');
    const token = req.headers.authorization.split(' ').pop();
    // console.log('my token', token);
    const validUser = await users.authenticateWithToken(token);
    // console.log('valid user?', validUser);

    req.user = validUser;
    req.token = validUser.token;
    next();
  } catch (e) {
    res.status(403).send('Invalid Login');;
  }
}
