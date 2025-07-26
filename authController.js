const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const usersFile = path.join(__dirname, 'users.json');
const JWT_SECRET = 'mySecretKey';

// Helper to read users
function readUsers() {
  if (!fs.existsSync(usersFile)) return [];
  try {
    const data = fs.readFileSync(usersFile, 'utf8');
    return JSON.parse(data);
  } catch {
    return [];
  }
}

// Helper to write users
function writeUsers(users) {
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2), 'utf8');
}

// Middleware: Authenticate JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Missing Authorization header.' });
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing token.' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
    req.user = user;
    next();
  });
}
exports.authenticateToken = authenticateToken;

exports.register = async (req, res) => {
  const { email, password, role } = req.body;
  if (!email || !password || !role) {
    return res.status(400).json({ error: 'يرجى إدخال جميع البيانات.' });
  }
  const users = readUsers();
  if (users.find(u => u.email === email)) {
    return res.status(409).json({ error: 'البريد الإلكتروني مستخدم بالفعل.' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { email, password: hashedPassword, role };
    users.push(newUser);
    writeUsers(users);
    res.json({ success: true, user: { email, role } });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في إنشاء الحساب.' });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'يرجى إدخال البريد الإلكتروني وكلمة السر.' });
  }
  const users = readUsers();
  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(401).json({ error: 'بيانات الدخول غير صحيحة.' });
  }
  try {
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'بيانات الدخول غير صحيحة.' });
    }
    // Generate JWT token
    const token = jwt.sign(
      { email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ success: true, user: { email: user.email, role: user.role }, token });
  } catch (err) {
    res.status(500).json({ error: 'خطأ أثناء تسجيل الدخول.' });
  }
};
