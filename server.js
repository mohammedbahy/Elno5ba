const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/auth');

const app = express();
app.use(cors());
app.use(bodyParser.json());

app.get('/', (req, res) => {
  res.send('API is running');
});

app.use('/api/auth', authRoutes);

app.listen(5000, () => {
  console.log('Server is running on port 5000');
});
