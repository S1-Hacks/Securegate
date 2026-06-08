cat > demo-repo/src/app.js << 'EOF'
const express = require('express');
const _ = require('lodash');
const app = express();

app.use(express.json());

// SEEDED VULN 1: SQL Injection — Semgrep will flag this
app.get('/user', (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.query.id;
  console.log("Running query:", query);
  res.json({ query });
});

// SEEDED VULN 2: Hardcoded secret — Semgrep will flag this
const AWS_SECRET = "AKIAIOSFODNN7EXAMPLE";
const DB_PASSWORD = "supersecretpassword123";

// SAFE lodash usage — _.template() NOT called, so lodash CVE is unreachable
app.get('/users', (req, res) => {
  const users = [{ name: 'Alice', age: 30 }, { name: 'Bob', age: 25 }];
  const sorted = _.sortBy(users, 'name');
  res.json(sorted);
});

app.listen(3000, () => console.log('Demo app running on port 3000'));
EOF