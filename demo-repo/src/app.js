const express = require('express');
const _ = require('lodash');
const app = express();

app.use(express.json());

app.get('/user', (req, res) => {
  const userId = parseInt(req.query.id, 10);
  if (isNaN(userId)) return res.status(400).json({ error: 'Invalid id' });
  res.json({ query: `SELECT * FROM users WHERE id = ${userId}` });
});

// Safe lodash usage — _.template() NOT called, so lodash CVE remains unreachable
app.get('/users', (req, res) => {
  const users = [{ name: 'Alice', age: 30 }, { name: 'Bob', age: 25 }];
  const sorted = _.sortBy(users, 'name');
  res.json(sorted);
});

app.get('/calculate', (req, res) => {
  const value = parseFloat(req.query.value);
  if (isNaN(value)) return res.status(400).json({ error: 'Invalid value' });
  res.json({ result: value * 2 });
});

app.listen(3000, () => console.log('Demo app running on port 3000'));
