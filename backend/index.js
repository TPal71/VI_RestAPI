require('dotenv').config();
const rateLimit = require('express-rate-limit');
//alap
const express = require('express');
const cors = require('cors');
const { Sequelize, DataTypes } = require('sequelize'); // UniqueConstraintError removed as registration is gone
const jwt = require('jsonwebtoken'); // Corrected import name
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(express.json());

// Sequelize kapcsolat
const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {
  host: process.env.DB_HOST,
  dialect: 'mysql',
  logging: process.env.NODE_ENV === 'development' ? console.log : false,
});
// Rate limiter konfiguráció a login végponthoz
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 perc
  max: 10, // Maximum 10 kérés IP címenként 15 percen belül
  message: 'Too many login attempts from this IP, please try again after 15 minutes'
});

// Táblák
// Feltételezzük, hogy a User modell továbbra is szükséges a bejelentkezéshez
const User = sequelize.define('users', {
  email: { type: DataTypes.STRING, unique: true, allowNull: false, validate: { isEmail: true } },
  password: { type: DataTypes.STRING, allowNull: false },
});

const Data = sequelize.define('data', {
  name: { type: DataTypes.STRING, allowNull: false },
  city: { type: DataTypes.STRING, allowNull: false },
  country: { type: DataTypes.STRING, allowNull: false },
});

// Tábla szinkronizálás
sequelize.sync()
  .then(() => console.log('Database synchronized'))
  .catch(err => console.error('Error synchronizing database:', err));

// JWT Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN"

  if (!token) {
    return res.status(401).json({ message: 'Access token is missing or invalid' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, userPayload) => {
    if (err) {
      console.error('JWT verification error:', err.name);
      return res.status(403).json({ message: 'Token is not valid or has expired' });
    }
    req.user = userPayload; // Tartalmazza pl. { userId, email }
    next();
  });
}

// Bejelentkezés
app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }

    const user = await User.findOne({ where: { email } });
    if (!user) {
      // Fontos: Ne adjunk túl specifikus hibaüzenetet, hogy nehezítsük a felhasználói fiókok felderítését
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email }, // A payloadba tehetünk bármilyen azonosító adatot
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '1h' } // Token lejárati idő, .env-ből olvasható
    );
    res.json({ token, userId: user.id, email: user.email });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Error logging in. Please try again.' });
  }
});

// Védett végpont: összes data rekord lekérdezése
app.get('/data', authenticateToken, async (req, res) => {
  try {
    // req.user tartalmazza a tokenből kinyert adatokat, pl. req.user.userId
    // Ezt felhasználhatjuk pl. felhasználóspecifikus adatok szűrésére, ha szükséges.
    console.log('Authenticated user accessing /data:', req.user);

    const allData = await Data.findAll();
    res.json(allData);
  } catch (err) {
    console.error('Error fetching data:', err);
    res.status(500).json({ message: 'Error fetching data. Please try again.' });
  }
});

// Új data rekord felvitele (védett)
app.post('/data', authenticateToken, async (req, res) => {
  try {
    const { name, city, country } = req.body;
    if (!name || !city || !country) {
      return res.status(400).json({ message: 'Name, city, and country are required.' });
    }

    // Itt is használhatjuk a req.user adatokat, ha pl. a létrehozott adathoz hozzá akarjuk rendelni a felhasználót
    // const newData = await Data.create({ name, city, country, UserId: req.user.userId });
    const newData = await Data.create({ name, city, country });
    res.status(201).json(newData);
  } catch (err) {
    if (err.name === 'SequelizeValidationError') {
        return res.status(400).json({ message: 'Validation error creating data.', errors: err.errors.map(e => e.message) });
    }
    console.error('Error creating data:', err);
    res.status(500).json({ message: 'Error creating data. Please try again.' });
  }
});

// Basic "Not Found" handler for unhandled routes
app.use((req, res, next) => {
  res.status(404).json({ message: 'Resource not found.' });
});

// General error handler
app.use((err, req, res, next) => {
  console.error('Unhandled application error:', err.stack);
  res.status(err.status || 500).json({
    message: err.message || 'An unexpected error occurred on the server.',
    ...(process.env.NODE_ENV === 'development' && { error: err.stack })
  });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  sequelize.authenticate()
    .then(() => console.log('Database connection has been established successfully.'))
    .catch(err => console.error('Unable to connect to the database:', err));
});
