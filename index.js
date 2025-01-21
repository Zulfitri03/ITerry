  const express = require('express');
  const bodyParser = require('body-parser');
  const cors = require('cors');
  const jwt = require('jsonwebtoken');
  const bcrypt = require('bcrypt');
  const mongoose = require('mongoose');
  require('dotenv').config();  // Load environment variables from .env file

  const app = express();
  const port = process.env.PORT || 3000;
  const uri = process.env.MONGODB_URI || 'mongodb://localhost:27017';

  const jwtSecret = process.env.JWT_SECRET;
  const fs = require('fs');
  const x509CertificatePath = process.env.CERT_PATH;

  const helmet = require('helmet');
  app.use(helmet());

  app.use(cors());
  app.use(bodyParser.json());

  // Connect to MongoDB using mongoose
  mongoose.connect(uri, {
      tls: true,  // Use TLS (Transport Layer Security) for encrypted connection
      tlsCertificateKeyFile: x509CertificatePath, // Path to the X.509 certificate
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    }).then(() => {
      console.log('Connected to MongoDB using X.509 authentication');
      
      // Start the server
      app.listen(port, () => {
        console.log(`Server running on port ${port}`);
      });
    }).catch(err => {
      console.error('Failed to connect to MongoDB:', err);
      process.exit(1);  // Exit process on failure to connect to MongoDB
    });
    
  // Define Schemas and Models
  const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    historyPasswords: { type: [String], default: [] },
    failedLoginAttempts: { type: Number, default: 0 },  // Add this field
    lastFailedLogin: { type: Date, default: null },  // To store when the last failed attempt was made
  });

  const questionSchema = new mongoose.Schema({
    question: { type: String, required: true },
    options: { type: [String], required: true },
    correctAnswer: { type: String, required: true },
  });

  const scoreSchema = new mongoose.Schema({
    username: { type: String, required: true },
    score: { type: Number, required: true },
    date: { type: Date, default: Date.now },
  });

  const User = mongoose.model('User', userSchema);
  const Question = mongoose.model('Question', questionSchema);
  const Score = mongoose.model('Score', scoreSchema);

  const crypto = require('crypto');
  const encrypt = (data) => crypto.createCipher('aes-256-ctr', process.env.ENCRYPTION_KEY).update(data, 'utf8', 'hex');
  const decrypt = (data) => crypto.createDecipher('aes-256-ctr', process.env.ENCRYPTION_KEY).update(data, 'hex', 'utf8');

  // Middleware for authentication
  const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, jwtSecret, { algorithms: ['HS256'] }, (err, user) => {
      if (err) {
        console.error('JWT Verification Error:', err.message);
        return res.status(403).send({ error: err.message });
      }
      req.user = user;
      next();
    });
  };

  const rateLimit = require('express-rate-limit');

// Configure rate limiting
  const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests from this IP, please try again later.' },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  });

  app.use(apiLimiter);

  // Alternatively, apply the rate limiter only to specific routes
  const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login attempts per windowMs
  message: { error: 'Too many login attempts, please try again later in 15 minutes.' },
  });

  const accountLimiter = rateLimit({
    keyGenerator: (req) => req.body.username || req.ip,
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many login attempts. Try again later in 15 minutes.' },
  });

  // Password validation function
  const validatePassword = (password, username, historyPasswords) => {
  const errors = [];
  
  // Check if the password is strong enough
  const passwordMinLength = 8;
  const passwordMaxLength = 20;
  if (password.length < passwordMinLength || password.length > passwordMaxLength) {
    errors.push(`Password must be between ${passwordMinLength} and ${passwordMaxLength} characters.`);
  }
  
  // Ensure password doesn't contain the username
  if (password.includes(username)) {
    errors.push('Password cannot contain the username.');
  }
  
  // Check if password contains at least one number, one uppercase letter, and one special character
  const hasUpperCase = /[A-Z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  
  if (!hasUpperCase) errors.push('Password must contain at least one uppercase letter.');
  if (!hasNumber) errors.push('Password must contain at least one number.');
  if (!hasSpecialChar) errors.push('Password must contain at least one special character.');

  // Check if password matches any of the history passwords
  if (historyPasswords.includes(password)) {
    errors.push('Password cannot be the same as any of your previous passwords.');
  }

  return errors;
};

  // User routes
  app.post('/api/users/register', accountLimiter, async (req, res) => {
    const { username, password } = req.body;
  
    if (!username || !password) {
      return res.status(400).send({ error: 'Username and password are required' });
    }
  
    // Additional validation for username format
    const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/; // Only alphanumeric and underscores, length 3-20
    if (!usernameRegex.test(username)) {
      return res.status(400).send({ error: 'Username must be between 3-20 characters and can only contain alphanumeric characters and underscores.' });
    }
  
    // Validate password
    const passwordErrors = validatePassword(password, username, []);
    if (passwordErrors.length > 0) {
      return res.status(400).send({ error: passwordErrors.join(' ') });
    }
  
    try {
      const existingUser = await User.findOne({ username });
      if (existingUser) {
        return res.status(400).send({ error: 'Username is already taken.' });
      }
  
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new User({ username, password: hashedPassword });
      await newUser.save();
    
      res.status(201).send('User registered successfully.');
    } catch (error) {
      res.status(500).send({ error: 'Error registering user.' });
    }
  });  

  app.post('/api/users/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
  
    if (!username || !password) {
      return res.status(400).send({ error: 'Username and password are required' });
    }
  
    // Validate username format
    const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
    if (!usernameRegex.test(username)) {
      return res.status(400).send({ error: 'Username must be between 3-20 characters and can only contain alphanumeric characters and underscores.' });
    }
  
    try {
      const user = await User.findOne({ username });
  
      if (!user) {
        return res.status(401).send({ error: 'Authentication failed.' });
      }
  
      // Check if the account is locked due to too many failed attempts
      const maxFailedAttempts = 3; // Threshold for lockout
      const baseLockoutTime = 30 * 1000; // Base lockout increment: 30 seconds
  
      if (user.failedLoginAttempts >= maxFailedAttempts) {
        const timeSinceLastFailed = Date.now() - new Date(user.lastFailedLogin).getTime();
        const lockoutTime = baseLockoutTime * (user.failedLoginAttempts - maxFailedAttempts + 1); // Increment lockout time
  
        if (timeSinceLastFailed < lockoutTime) {
          const remainingTime = Math.ceil((lockoutTime - timeSinceLastFailed) / 1000); // Remaining time in seconds
          return res.status(403).send({
            error: `Too many failed login attempts. Please try again later in ${remainingTime} seconds.`,
          });
        }
      }
  
      // Validate the password
      const isPasswordCorrect = await bcrypt.compare(password, user.password);
      if (!isPasswordCorrect) {
        // Increment failed attempts counter
        user.failedLoginAttempts += 1;
        user.lastFailedLogin = Date.now();
        await user.save();
  
        return res.status(401).send({ error: 'Authentication failed.' });
      }
  
      // Reset failed attempts on successful login
      user.failedLoginAttempts = 0;
      user.lastFailedLogin = null;
      await user.save();
      
      // Generate and return JWT token
      const payload = { username: user.username, aud: 'your-app', iss: 'your-app' };
      const token = jwt.sign(payload, jwtSecret, { expiresIn: '30m' });

      res.cookie('token', token, {
      httpOnly: true,   // Prevents JavaScript from accessing the cookie
      secure: true,     // Ensures the cookie is only sent over HTTPS
      maxAge: 3600000,  // 1 hour (Expiration time)
      sameSite: 'Strict' // Prevents sending cookies with cross-site requests
    });

    // Respond with a success message (no token in response body)
    res.send({ message: 'Login successful' });
    } catch (error) {
      res.status(500).send({ error: 'An error occurred during login' });
    }
  });

   
  
  app.get('/api/users/:username', authenticateToken, async (req, res) => {
    const username = req.params.username;

    try {
      const user = await User.findOne({ username });
      if (!user) {
        return res.status(404).send({ error: 'User not found' });
      }
      res.send(user);
    } catch (error) {
      res.status(500).send({ error: 'An error occurred while fetching the user' });
    }
  });

 // Update user password
 app.patch('/api/users/:username', authenticateToken, async (req, res) => {
  const { username } = req.params;
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).send({ error: 'Current password and new password are required.' });
  }

  // Validate password format
  const passwordErrors = validatePassword(newPassword, username, []);
  if (passwordErrors.length > 0) {
    return res.status(400).send({ error: passwordErrors.join(' ') });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).send({ error: 'User not found.' });
    }

    // Verify the current password
    const isCurrentPasswordCorrect = await bcrypt.compare(currentPassword, user.password);
    if (!isCurrentPasswordCorrect) {
      return res.status(401).send({ error: 'Current password is incorrect.' });
    }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.historyPasswords.push(user.password); // Save the old password to history
      user.password = hashedPassword;
      await user.save();

    res.send({ message: 'Password updated successfully.' });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).send({ error: 'Error updating user. Please try again later.' });
  }
});

  
  app.delete('/api/users/:username', authenticateToken, async (req, res) => {
    const username = req.params.username;

    try {
      const result = await User.deleteOne({ username });
      if (result.deletedCount === 0) {
        return res.status(404).send({ error: 'User not found' });
      }
      res.send({ message: 'User deleted successfully' });
    } catch (error) {
      res.status(500).send({ error: 'An error occurred while deleting the user' });
    }
  });

  // Question routes
  app.post('/api/questions', authenticateToken, async (req, res) => {
    const { question, options, correctAnswer } = req.body;

    try {
      const newQuestion = new Question({ question, options, correctAnswer });
      const result = await newQuestion.save();
      res.status(201).send({ questionId: result._id });
    } catch (error) {
      res.status(500).send({ error: 'An error occurred while creating the question' });
    }
  });

  app.get('/api/questions', authenticateToken, async (req, res) => {
    try {
      const questions = await Question.find({}, { correctAnswer: 0, _id: 0 }).lean();
      res.send(questions);
    } catch (error) {
      res.status(500).send({ error: 'An error occurred while fetching the questions' });
    }
  });

  app.patch('/api/questions/:id', authenticateToken, async (req, res) => {
    const questionId = req.params.id;
    const { question, options, correctAnswer } = req.body;

    try {
      const result = await Question.updateOne(
        { _id: questionId },
        { $set: { question, options, correctAnswer } }
      );

      if (result.nModified === 0) {
        return res.status(404).send({ error: 'Question not found' });
      }

      res.send({ message: 'Question updated successfully' });
    } catch (error) {
      res.status(500).send({ error: 'An error occurred while updating the question' });
    }
  });

  app.delete('/api/questions/:id', authenticateToken, async (req, res) => {
    const questionId = req.params.id;

    try {
      const result = await Question.deleteOne({ _id: questionId });

      if (result.deletedCount === 0) {
        return res.status(404).send({ error: 'Question not found' });
      }

      res.send({ message: 'Question deleted successfully' });
    } catch (error) {
      res.status(500).send({ error: 'An error occurred while deleting the question' });
    }
  });

  // Score routes
  app.post('/api/scores', authenticateToken, async (req, res) => {
    const { username, score } = req.body;

    try {
      const newScore = new Score({ username, score });
      const result = await newScore.save();
      res.status(201).send({ scoreId: result._id });
    } catch (error) {
      res.status(500).send({ error: 'An error occurred while saving the score' });
    }
  });

  app.get('/api/score', authenticateToken, async (req, res) => {
    try {
      const scores = await Score.find({}, { _id: 0 }).lean();
      res.send(scores);
    } catch (error) {
      res.status(500).send({ error: 'An error occurred while fetching the scores' });
    }
  });

  app.patch('/api/scores/:username', authenticateToken, async (req, res) => {
    const username = req.params.username;
    const { score } = req.body;

    try {
      const result = await Score.updateOne({ username }, { $set: { score } });
      if (result.nModified === 0) {
        return res.status(404).send({ error: 'Score not found' });
      }
      res.send({ message: 'Score updated successfully' });
    } catch (error) {
      res.status(500).send({ error: 'An error occurred while updating the score' });
    }
  });

  app.delete('/api/scores/:username', authenticateToken, async (req, res) => {
    const username = req.params.username;

    try {
      const result = await Score.deleteOne({ username });

      if (result.deletedCount === 0) {
        return res.status(404).send({ error: 'Score not found' });
      }

      res.send({ message: 'Score deleted successfully' });
    } catch (error) {
      res.status(500).send({ error: 'An error occurred while deleting the score' });
    }
  });

  // Submit answers route
  app.post('/api/submit', authenticateToken, async (req, res) => {
    const { username, answers } = req.body;
    
    if (!username || !Array.isArray(answers)) {
      return res.status(400).send({ error: 'Username and answers are required, answers must be an array.' });
    }

    // Ensure that answers are not empty and match the number of questions
    try {
      // Fetch all questions
      const questions = await Question.find({}).lean();
      if (questions.length !== answers.length) {
        return res.status(400).send('Number of answers does not match number of questions');
      }

      // Calculate score
      let score = 0;
      for (let i = 0; i < questions.length; i++) {
        if (questions[i].correctAnswer === answers[i]) {
          score++;
        }
      }

      // Save score to the database
      const newScore = new Score({ username, score });
      await newScore.save();

      res.status(201).send({ message: 'Score submitted successfully', score });
    } catch (error) {
      res.status(500).send({ error: 'An error occurred while submitting the answers' });
    }
  });

  // Error handling middleware
  app.use((err, req, res, next) => {
    console.error('An error occurred:', err);
    res.status(500).send({ error: 'Internal Server Error' });
  });
