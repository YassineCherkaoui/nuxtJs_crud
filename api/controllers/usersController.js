const config = require('../config');
const User = require('../models/User');
const validator = require('express-validator');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// Register
module.exports.register = [
  // Validations rules
  validator.body('full_name', 'Please enter Full Name').isLength({ min: 1 }),
  validator.body('email', 'Please enter Email').isLength({ min: 1 }),
  validator.body('email').custom(value => {
    return User.findOne({ email: value }).then(user => {
      if (user !== null) {
        return Promise.reject('Email already in use');
      }
    });
  }),
  validator.body('password', 'Please enter Password').isLength({ min: 1 }),

  function (req, res) {
    // Throw validation errors
    const errors = validator.validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.mapped() });
    }

    // Initialize record
    const user = new User({
      full_name: req.body.full_name,
      email: req.body.email,
      password: req.body.password,
    });

    // Encrypt password
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(user.password, salt);
    user.password = hash;

    // Save record
    user.save()
      .then((savedUser) => {
        return res.json({
          message: 'saved',
          _id: savedUser._id,
        });
      })
      .catch((err) => {
        return res.status(500).json({
          message: 'Error saving record',
          error: err,
        });
      });
  },
];

// Login
module.exports.login = [
  // Validation rules
  validator.body('email', 'Please enter Email').isLength({ min: 1 }),
  validator.body('password', 'Please enter Password').isLength({ min: 1 }),

  function (req, res) {
    // Throw validation errors
    const errors = validator.validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.mapped() });
    }

    // Validate email and password are correct
    User.findOne({ email: req.body.email })
      .then(async (user) => {
        if (!user) {
          return res.status(500).json({
            message: 'Email address you entered is not found.',
          });
        }
        // Compare submitted password with password inside db
        const isMatched =  await bcrypt.compare(req.body.password, user.password);
        if (isMatched) {
          const generatedToken = jwt.sign({
            _id: user._id,
            email: user.email,
            full_name: user.full_name,
          }, config.authSecret);
          return res.json({
            user: {
              _id: user._id,
              email: user.email,
              full_name: user.full_name,
            },
            token: generatedToken
          });
        } else {
          return res.status(500).json({
            message: 'Invalid Email or Password entered.',
          });
        }
      })
      .catch((err) => {
        return res.status(500).json({
          message: 'Error logging in',
          error: err,
        });
      });
  },
];

// Get User
// module.exports.user = function (req, res) {
//   const token = req.headers.authorization;
//   if (token) {
//     const tokenResult  = token.replace(/^Bearer\s/, '');
//     const decodedToken = jwt.verify(tokenResult, config.authSecret);
//     console.log(decoded)
//     // Verifies secret and checks if the token is expired
//     jwt.verify(token.replace(/^Bearer\s/, ''), config.authSecret)
//       .then((decoded) => {
//         return res.json({ user: decoded });
//       })
//       .catch((err) => {
//         return res.status(401).json({ message: 'unauthorized' });
//       });
//   } else {
//     return res.status(401).json({ message: 'unauthorized' });
//   }
// };
module.exports.user = function (req, res) {
  const token = req.headers.authorization;
  if (token) {
    // Wrap jwt.verify in a promise
    new Promise((resolve, reject) => {
      jwt.verify(token.replace(/^Bearer\s/, ''), config.authSecret, (err, decoded) => {
        if (err) reject(err);
        else resolve(decoded);
      });
    })
      .then((decoded) => {
        return res.json({ user: decoded });
      })
      .catch((err) => {
        return res.status(401).json({ message: 'unauthorized' });
      });
  } else {
    return res.status(401).json({ message: 'unauthorized' });
  }
};