const express = require("express");
const { users, posts } = require("./data/db");
const authenticate = require("./middleware/authenticate");
const authorize = require("./middleware/authorize");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("./config");

const app = express();

// Prisma setup with PostgreSQL adapter
require('dotenv').config();
const { PrismaClient } = require('@prisma/client');
const { PrismaPg } = require('@prisma/adapter-pg');
const prisma = new PrismaClient({
  adapter: new PrismaPg({ connectionString: process.env.DATABASE_URL })
});

// Endpoint to list all users
app.get('/users', async (req, res) => {
  try {
    const users = await prisma.user.findMany();
    res.json(users);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.get('/', (req, res) => {
  res.send('RBAC Demo API');
});

app.use(express.json());


app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }
  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "1h" });
  res.json({ token });
});


app.get("/profile", authenticate, (req, res) => {
  res.json({ message: "Your profile", user: req.user });
});

app.get("/reports", authenticate, authorize("moderator", "admin"), (req, res) => {
  res.json({ message: "Here are the flagged reports" });
});

app.delete("/users/:id", authenticate, authorize("admin"), (req, res) => {
  res.json({ message: `User ${req.params.id} deleted` });
});

app.delete("/posts/:id", authenticate, (req, res) => {
  const postId = parseInt(req.params.id, 10);
  const post = posts.find(p => p.id === postId);
  if (!post) {
    return res.status(404).json({ message: "Post not found" });
  }
  const user = req.user;
  if (user.role === "admin" || post.authorId === user.id) {
    const index = posts.findIndex(p => p.id === postId);
    if (index !== -1) {
      posts.splice(index, 1);
    }
    return res.json({ message: `Post ${postId} deleted` });
  } else {
    return res.status(403).json({ message: "Forbidden" });
  }
});

if (require.main === module) {
  const PORT = process.env.PORT || 3001;
  app.listen(PORT);
}

module.exports = app;
