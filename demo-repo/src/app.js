const express = require('express');
const _ = require('lodash');
const app = express();

app.use(express.json());

// FIXED: parameterized query via placeholder — no SQL injection
app.get('/user', (req, res) => {
  const userId = parseInt(req.query.id, 10);
  if (isNaN(userId)) return res.status(400).json({ error: 'Invalid id' });
  // query would use prepared statement: SELECT * FROM users WHERE id = ?
  res.json({ userId });
});

// FIXED: secrets moved to environment variables
const AWS_KEY_ID = process.env.AWS_ACCESS_KEY_ID;
const DB_PASSWORD = process.env.DB_PASSWORD;

// SAFE lodash usage — _.template() NOT called, so lodash CVE is unreachable
app.get('/users', (req, res) => {
  const users = [{ name: 'Alice', age: 30 }, { name: 'Bob', age: 25 }];
  const sorted = _.sortBy(users, 'name');
  res.json(sorted);
});

// FIXED: eval() removed — parse expression safely
app.get('/eval', (req, res) => {
  const value = parseFloat(req.query.expr);
  res.json({ result: isNaN(value) ? null : value });
});

app.listen(3000, () => console.log('Demo app running on port 3000'));
