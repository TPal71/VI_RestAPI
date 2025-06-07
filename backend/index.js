// .env fájlban lévő környezeti változók betöltése (pl. adatbázis kapcsolati adatok, titkos kulcsok)
require('dotenv').config();
// Kérések korlátozására szolgáló middleware (pl. brute-force támadások ellen a login végponton)
const rateLimit = require('express-rate-limit');
//alap Express.js keretrendszer importálása webalkalmazások és API-k készítéséhez
const express = require('express');
// CORS (Cross-Origin Resource Sharing) middleware engedélyezése, hogy a frontend más domainről is elérhesse az API-t
const cors = require('cors');
// Sequelize ORM (Object-Relational Mapper) importálása az adatbázis-műveletekhez
const { Sequelize, DataTypes } = require('sequelize');
// JSON Web Token (JWT) kezelésére szolgáló könyvtár importálása az autentikációhoz
const jwt = require('jsonwebtoken');
// Jelszavak biztonságos hashelésére szolgáló könyvtár (bcrypt) importálása
const bcrypt = require('bcryptjs');

// Verziószám (ezt akár a package.json-ból is beolvashatnád)
const APP_VERSION = "1.0.0";

console.log('Alkalmazás indul, modulok betöltve.');

// Express alkalmazás létrehozása
const app = express();
// CORS middleware használata az összes bejövő kérésre
app.use(cors());
console.log('CORS middleware beállítva.');
// Bejövő JSON típusú kérések body-jának (törzsének) feldolgozására szolgáló middleware
// Ez teszi elérhetővé a req.body objektumot a JSON adatokkal
app.use(express.json());
console.log('express.json middleware beállítva.');

// Sequelize kapcsolat konfigurálása és létrehozása a .env fájlban megadott adatok alapján
console.log('Sequelize kapcsolat konfigurálása...');
const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {
  host: process.env.DB_HOST, // Adatbázis szerver címe
  dialect: 'mysql',          // Használt adatbázis típusa (itt MySQL)
  // SQL lekérdezések naplózása a konzolra, csak fejlesztői ('development') módban
  logging: process.env.NODE_ENV === 'development' ? (msg) => console.log(`[SEQUELIZE] ${msg}`) : false,
});
console.log('Sequelize példány létrehozva.');

// Rate limiter konfigurációja kifejezetten a /login végponthoz
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // Időablak hossza: 15 perc (milliszekundumban)
  max: 10, // Maximálisan engedélyezett kérések száma egy IP címről az időablakon belül
  // Üzenet, amit a kliens kap, ha túllépi a limitet
  message: 'Too many login attempts from this IP, please try again after 15 minutes',
  handler: (req, res, next, options) => {
    console.warn(`Rate limit túllépés: IP: ${req.ip}, Útvonal: ${req.path}`);
    res.status(options.statusCode).json({ message: options.message });
  }
});
console.log('Login rate limiter konfigurálva.');

// Adatbázis táblák modellezése Sequelize segítségével
console.log('Adatbázis modellek definiálása...');
// 'users' tábla modellje
const User = sequelize.define('users', { // A tábla neve az adatbázisban 'users' lesz
  email: { type: DataTypes.STRING, unique: true, allowNull: false, validate: { isEmail: true } },
  password: { type: DataTypes.STRING, allowNull: false },
});

// 'data' tábla modellje
const Data = sequelize.define('data', { // A tábla neve az adatbázisban 'data' lesz
  name: { type: DataTypes.STRING, allowNull: false },
  city: { type: DataTypes.STRING, allowNull: false },
  country: { type: DataTypes.STRING, allowNull: false },
});
console.log('Adatbázis modellek definiálva.');

// Táblák szinkronizálása az adatbázissal a modellek alapján
console.log('Adatbázis szinkronizálás indítása...');
sequelize.sync()
  .then(() => console.log('Adatbázis sikeresen szinkronizálva.'))
  .catch(err => console.error('Hiba az adatbázis szinkronizálása közben:', err));

// JWT Autentikációs Middleware
function authenticateToken(req, res, next) {
  console.log(`[authenticateToken] Kérés érkezett: ${req.method} ${req.originalUrl}`);
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  console.log(`[authenticateToken] Auth header: ${authHeader}, Token: ${token ? 'Van' : 'Nincs'}`);

  if (!token) {
    console.log('[authenticateToken] Nincs token, 401 küldése.');
    return res.status(401).json({ message: 'Access token is missing or invalid' });
  }

  console.log('[authenticateToken] Token ellenőrzése...');
  jwt.verify(token, process.env.JWT_SECRET, (err, userPayload) => {
    if (err) {
      console.error('[authenticateToken] JWT ellenőrzési hiba:', err.name, err.message);
      console.log('[authenticateToken] Érvénytelen token, 403 küldése.');
      return res.status(403).json({ message: 'Token is not valid or has expired' });
    }
    console.log('[authenticateToken] Token sikeresen ellenőrizve. Payload:', userPayload);
    req.user = userPayload;
    console.log('[authenticateToken] next() hívása.');
    next();
  });
}

// Bejelentkezési végpont (POST /login)
app.post('/login', loginLimiter, async (req, res) => {
  console.log(`[POST /login] Kérés érkezett. Body:`, req.body);
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      console.log('[POST /login] Hiányzó email vagy jelszó. 400 küldése.');
      return res.status(400).json({ message: 'Email and password are required.' });
    }

    console.log(`[POST /login] Felhasználó keresése: ${email}`);
    const user = await User.findOne({ where: { email } });
    if (!user) {
      console.log(`[POST /login] Felhasználó nem található: ${email}. 401 küldése.`);
      return res.status(401).json({ message: 'Invalid credentials.' });
    }
    console.log(`[POST /login] Felhasználó megtalálva: ${email}. Jelszó ellenőrzése...`);

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      console.log(`[POST /login] Érvénytelen jelszó: ${email}. 401 küldése.`);
      return res.status(401).json({ message: 'Invalid credentials.' });
    }
    console.log(`[POST /login] Jelszó érvényes: ${email}. Token generálása...`);

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
    );
    console.log(`[POST /login] Token generálva. Válasz küldése...`);
    res.json({ token, userId: user.id, email: user.email });
  } catch (err) {
    console.error('[POST /login] Hiba a login végponton:', err);
    // Biztosítjuk, hogy a válasz elküldésre kerüljön, még ha a globális hibakezelő is aktív
    if (!res.headersSent) {
        res.status(500).json({ message: 'Error logging in. Please try again.' });
    }
  }
});

// Védett végpont: összes 'data' rekord lekérdezése (GET /data)
app.get('/data', authenticateToken, async (req, res) => {
  console.log(`[GET /data] Kérés érkezett. Authentikált felhasználó:`, req.user);
  try {
    console.log('[GET /data] Adatok lekérdezése az adatbázisból...');
    const allData = await Data.findAll();
    console.log('[GET /data] Adatok sikeresen lekérdezve. Válasz küldése...');
    res.json(allData);
  } catch (err) {
    console.error('[GET /data] Hiba a /data végponton:', err);
    if (!res.headersSent) {
        res.status(500).json({ message: 'Error fetching data. Please try again.' });
    }
  }
});

// Teszt végpont, ami egy verziószámot ad vissza (POST /test) - védett végpont
app.post('/test', authenticateToken, async (req, res) => {
  console.log(`[POST /test] Kérés érkezett. Authentikált felhasználó:`, req.user);
  try {
    // Itt nem használjuk a req.body-t, de logolhatjuk, ha szükséges
    // console.log(`[POST /test] Body:`, req.body);

    console.log('[POST /test] Verziószám visszaadása...');
    res.json({ version: APP_VERSION, message: "Test endpoint reached successfully." });
  } catch (err) {
    console.error('[POST /test] Hiba a /test végponton:', err);
    if (!res.headersSent) {
        res.status(500).json({ message: 'Error processing test request. Please try again.' });
    }
  }
});

// Új 'data' rekord felvitele (POST /data) - szintén védett végpont
app.post('/data', authenticateToken, async (req, res) => {
  console.log(`[POST /data] Kérés érkezett. Body:`, req.body, `Authentikált felhasználó:`, req.user);
  try {
    const { name, city, country } = req.body;
    if (!name || !city || !country) {
      console.log('[POST /data] Hiányzó adatok. 400 küldése.');
      return res.status(400).json({ message: 'Name, city, and country are required.' });
    }

    console.log('[POST /data] Új adat létrehozása az adatbázisban...');
    const newData = await Data.create({ name, city, country });
    console.log('[POST /data] Adat sikeresen létrehozva. Válasz küldése (201)...');
    res.status(201).json(newData);
  } catch (err) {
    console.error('[POST /data] Hiba a /data (POST) végponton:', err);
    if (err.name === 'SequelizeValidationError') {
      console.log('[POST /data] Sequelize validációs hiba. 400 küldése.');
      if (!res.headersSent) {
        return res.status(400).json({ message: 'Validation error creating data.', errors: err.errors.map(e => e.message) });
      }
    }
    if (!res.headersSent) {
        res.status(500).json({ message: 'Error creating data. Please try again.' });
    }
  }
});

// Alapvető "Not Found" (404) kezelő middleware
app.use((req, res, next) => {
  console.log(`[404 Kezelő] Nem található útvonal: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ message: 'Resource not found.' });
});

// Általános hibakezelő middleware
app.use((err, req, res, next) => {
  console.error('[ÁLTALÁNOS HIBAKEZELŐ] Elkapott hiba:', err);
  console.error(err.stack); // Teljes stack trace a hibához
  if (res.headersSent) {
    // Ha a válasz fejlécei már el lettek küldve, akkor a hibát a next()-nek kell továbbítania,
    // hogy az Express alapértelmezett hibakezelője kezelje (ami lezárja a kapcsolatot).
    console.error('[ÁLTALÁNOS HIBAKEZELŐ] A válasz fejlécei már elküldve, hiba továbbítása.');
    return next(err);
  }
  res.status(err.status || 500).json({
    message: err.message || 'An unexpected error occurred on the server.',
    ...(process.env.NODE_ENV === 'development' && { errorStack: err.stack }) // Fejlesztői módban stack is mehet
  });
});

// Szerver portjának beállítása és a szerver elindítása
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Szerver sikeresen elindult és figyel a ${PORT} porton.`);
  console.log('Adatbázis kapcsolat ellenőrzése indításkor...');
  sequelize.authenticate()
    .then(() => console.log('Adatbázis kapcsolat sikeresen létrejött.'))
    .catch(err => console.error('Hiba az adatbázis kapcsolódás ellenőrzésekor:', err));
});

// Globális kezeletlen ígéret-elutasítások elkapása (fontos a debuggoláshoz)
process.on('unhandledRejection', (reason, promise) => {
  console.error('-------------------------------------------------------------------');
  console.error('KEZELETLEN ÍGÉRET ELUTASÍTÁS (UNHANDLED REJECTION)! Alkalmazás leállhat!');
  console.error('Ok (Reason):', reason);
  console.error('Ígéret (Promise):', promise);
  console.error('-------------------------------------------------------------------');
  // Éles környezetben itt érdemes lehet a processzt leállítani és újraindítani egy process managerrel (pl. PM2)
  // process.exit(1); // Vagy ne állítsd le, ha a hibakezelőd elkapja és naplózza
});

// Globális kezeletlen kivételek elkapása (szinkron hibákhoz)
process.on('uncaughtException', (error) => {
  console.error('-------------------------------------------------------------------');
  console.error('KEZELETLEN KIVÉTEL (UNCAUGHT EXCEPTION)! Alkalmazás leállhat!');
  console.error('Hiba (Error):', error);
  console.error('-------------------------------------------------------------------');
  // Éles környezetben itt is érdemes lehet a processzt leállítani és újraindítani
  // process.exit(1);
});

console.log('Az index.js végére ért a feldolgozás (a szerver figyelése elindult).');
