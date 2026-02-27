// server/server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:5173',
  credentials: true
}));
app.use(express.json());

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'ghosted-server' });
});

const authRoutes = require('./routes/auth');
const scanRoutes = require('./routes/scan');
const ghostRoutes = require('./routes/ghost');
app.use('/auth', authRoutes);
app.use('/scan', scanRoutes);
app.use('/ghost', ghostRoutes);

app.listen(PORT, () => {
  console.log(`Ghosted server running on port ${PORT}`);
});

module.exports = app;
