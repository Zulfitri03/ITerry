  const express = require('express');
  const bodyParser = require('body-parser');
  var cors = require('cors');
  var jwt = require('jsonwebtoken');
  const bcrypt = require('bcrypt');
  const mongoose = require('mongoose');
  require('dotenv').config();  // Load environment variables from .env file

  const app = express();
  const port = process.env.PORT || 3000;
  const uri = process.env.MONGODB_URI;
  const jwtSecret = process.env.JWT_SECRET;

  app.use(cors());
  app.use(bodyParser.json());

  // Connect to MongoDB using mongoose
  mongoose.connect(uri, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    }).then(() => {
      console.log('Connected to MongoDB');
      
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

  // Middleware for authentication
  const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, jwtSecret, (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  };

  // Helper function to validate password policy
  const isPasswordValid = (password, username) => {
  const passwordPolicy = {
    length: /^.{8,13}$/, // 8-13 characters
    containsNumber: /\d/, // At least one number
    containsUppercase: /[A-Z]/, // At least one uppercase letter
    containsLowercase: /[a-z]/, // At least one lowercase letter
    noUsername: (pwd, uname) => !pwd.toLowerCase().includes(uname.toLowerCase()), // No username
  };

  return (
    passwordPolicy.length.test(password) &&
    passwordPolicy.containsNumber.test(password) &&
    passwordPolicy.containsUppercase.test(password) &&
    passwordPolicy.containsLowercase.test(password) &&
    passwordPolicy.noUsername(password, username)
  );
};

  // Extend the user schema for password history
  userSchema.add({
  passwordHistory: { type: [String], default: [] },
});

  // User routes
  app.post('/api/users/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).send({ error: 'Username and password are required' });
    }

    if (!isPasswordValid(password, username)) {
      return res.status(400).send({
        error: 'Password must be 8-13 characters long, contain uppercase, lowercase, a number, and must not include the username.',
      });
    }
  
    try {
      // Check if user already exists
      const existingUser = await User.findOne({ username });
      if (existingUser) {
        return res.status(400).send({ error: 'User already exists' });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create new user
      const newUser = new User({ username, password: hashedPassword });
      await newUser.save();

      res.status(201).send('User registered successfully');
    } catch (error) {
      res.status(400).send('Error registering user');
    }
  });

  app.post('/api/users/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).send({ error: 'Username and password are required' });
    }

    try {
      const user = await User.findOne({ username });
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).send({ error: 'Invalid credentials' });
      }

      const token = jwt.sign({ username: user.username }, jwtSecret, { expiresIn: '1h' });
      res.json({ token });
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

  app.patch('/api/users/:username', authenticateToken, async (req, res) => {
    const { username } = req.params;
    const { password } = req.body;
  
    if (!password) {
      return res.status(400).send({ error: 'Password is required' });
    }
  
    try {
      const user = await User.findOne({ username });
      if (!user) {
        return res.status(404).send({ error: 'User not found' });
      }
  
      if (!isPasswordValid(password, username)) {
        return res.status(400).send({
          error: 'Password must be 8-13 characters long, contain uppercase, lowercase, a number, and must not include the username.',
        });
      }
  
      // Check if the password has been used before
      const hashedPassword = await bcrypt.hash(password, 10);
      if (user.passwordHistory.includes(hashedPassword)) {
        return res.status(400).send({ error: 'Password has been used before' });
      }
  
      // Update password and password history
      user.password = hashedPassword;
      user.passwordHistory.push(hashedPassword);
  
      // Limit password history to the last 5 passwords
      if (user.passwordHistory.length > 5) {
        user.passwordHistory.shift();
      }
  
      await user.save();
      res.send({ message: 'Password updated successfully' });
    } catch (error) {
      res.status(400).send({ error: error.message });
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
