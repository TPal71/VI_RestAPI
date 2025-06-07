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

// Express alkalmazás létrehozása
const app = express();
// CORS middleware használata az összes bejövő kérésre
app.use(cors());
// Bejövő JSON típusú kérések body-jának (törzsének) feldolgozására szolgáló middleware
// Ez teszi elérhetővé a req.body objektumot a JSON adatokkal
app.use(express.json());

// Sequelize kapcsolat konfigurálása és létrehozása a .env fájlban megadott adatok alapján
const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {
  host: process.env.DB_HOST, // Adatbázis szerver címe
  dialect: 'mysql',          // Használt adatbázis típusa (itt MySQL)
  // SQL lekérdezések naplózása a konzolra, csak fejlesztői ('development') módban
  logging: process.env.NODE_ENV === 'development' ? console.log : false,
});

// Rate limiter konfigurációja kifejezetten a /login végponthoz
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // Időablak hossza: 15 perc (milliszekundumban)
  max: 10, // Maximálisan engedélyezett kérések száma egy IP címről az időablakon belül
  // Üzenet, amit a kliens kap, ha túllépi a limitet
  message: 'Too many login attempts from this IP, please try again after 15 minutes'
});

// Adatbázis táblák modellezése Sequelize segítségével

// 'users' tábla modellje
const User = sequelize.define('users', { // A tábla neve az adatbázisban 'users' lesz
  // 'email' oszlop: string típusú, egyedi (unique), nem lehet null (allowNull: false),
  // és érvényes e-mail formátumúnak kell lennie (validate: { isEmail: true })
  email: { type: DataTypes.STRING, unique: true, allowNull: false, validate: { isEmail: true } },
  // 'password' oszlop: string típusú, nem lehet null
  password: { type: DataTypes.STRING, allowNull: false },
});

// 'data' tábla modellje
const Data = sequelize.define('data', { // A tábla neve az adatbázisban 'data' lesz
  // 'name' oszlop: string típusú, nem lehet null
  name: { type: DataTypes.STRING, allowNull: false },
  // 'city' oszlop: string típusú, nem lehet null
  city: { type: DataTypes.STRING, allowNull: false },
  // 'country' oszlop: string típusú, nem lehet null
  country: { type: DataTypes.STRING, allowNull: false },
});

// Táblák szinkronizálása az adatbázissal a modellek alapján
// Ha a táblák nem léteznek, létrehozza őket.
// FIGYELEM: Éles környezetben a `sequelize.sync()` helyett adatbázis migrációk használata javasolt
// (pl. sequelize-cli segítségével), hogy elkerüljük a véletlen adatvesztést vagy séma problémákat.
sequelize.sync()
  .then(() => console.log('Database synchronized')) // Sikeres szinkronizáció esetén üzenet a konzolra
  .catch(err => console.error('Error synchronizing database:', err)); // Hiba esetén hibaüzenet

// JWT Autentikációs Middleware
// Ez a middleware minden védett végpont előtt lefut, hogy ellenőrizze a JWT token érvényességét.
function authenticateToken(req, res, next) {
  // Token keresése az 'Authorization' HTTP header-ben (általában "Bearer TOKEN" formátumban)
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // A "Bearer " rész eltávolítása, csak a token marad

  // Ha nincs token, 401-es (Unauthorized) hibát küldünk vissza
  if (!token) {
    return res.status(401).json({ message: 'Access token is missing or invalid' });
  }

  // Token ellenőrzése a JWT_SECRET titkos kulccsal
  jwt.verify(token, process.env.JWT_SECRET, (err, userPayload) => {
    // Hiba esetén (pl. lejárt vagy érvénytelen token) 403-as (Forbidden) hibát küldünk
    if (err) {
      console.error('JWT verification error:', err.name); // Hiba naplózása a szerver konzoljára
      return res.status(403).json({ message: 'Token is not valid or has expired' });
    }
    // Sikeres ellenőrzés esetén a tokenből kinyert felhasználói adatokat (payload) hozzáadjuk a request objektumhoz
    req.user = userPayload; // Ez tartalmazza pl. a { userId, email } adatokat
    next(); // Továbbengedjük a kérést a következő middleware-re vagy a végpont kezelőjére
  });
}

// Bejelentkezési végpont (POST /login)
// A loginLimiter middleware itt kerül alkalmazásra, hogy korlátozza a bejelentkezési kísérleteket.
app.post('/login', loginLimiter, async (req, res) => {
  try {
    // E-mail és jelszó kinyerése a kérés törzséből (req.body)
    const { email, password } = req.body;
    // Alapvető validáció: e-mail és jelszó megadása kötelező
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }

    // Felhasználó keresése az adatbázisban e-mail cím alapján
    const user = await User.findOne({ where: { email } });
    // Ha nincs ilyen felhasználó, vagy a jelszó érvénytelen, általános hibaüzenetet küldünk
    // (biztonsági okokból nem specifikáljuk, hogy az e-mail vagy a jelszó volt-e hibás)
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // A megadott jelszó összehasonlítása az adatbázisban tárolt hashelt jelszóval
    const validPassword = await bcrypt.compare(password, user.password);
    // Ha a jelszavak nem egyeznek
    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // Sikeres bejelentkezés esetén JWT token generálása
    const token = jwt.sign(
      { userId: user.id, email: user.email }, // Payload: a tokenbe ágyazott adatok (pl. felhasználó azonosítója)
      process.env.JWT_SECRET,                  // Titkos kulcs a token aláírásához (a .env fájlból)
      // Token opciók: lejárati idő (itt a .env fájlból olvassa, vagy alapértelmezetten 1 óra)
      { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
    );
    // Token és opcionálisan egyéb felhasználói adatok visszaküldése a kliensnek JSON formátumban
    res.json({ token, userId: user.id, email: user.email });
  } catch (err) {
    // Általános hiba naplózása és 500-as (Internal Server Error) státusz küldése
    console.error('Login error:', err);
    res.status(500).json({ message: 'Error logging in. Please try again.' });
  }
});

// Védett végpont: összes 'data' rekord lekérdezése (GET /data)
// Az 'authenticateToken' middleware biztosítja, hogy csak érvényes tokennel rendelkező felhasználók érhessék el.
app.get('/data', authenticateToken, async (req, res) => {
  try {
    // A req.user objektum tartalmazza a tokenből kinyert adatokat (pl. req.user.userId)
    // Ezt fel lehet használni pl. felhasználóspecifikus adatok szűrésére.
    console.log('Authenticated user accessing /data:', req.user); // Naplózzuk, ki fért hozzá

    // Az összes rekord lekérdezése a 'Data' táblából
    const allData = await Data.findAll();
    // Az adatok visszaküldése JSON formátumban
    res.json(allData);
  } catch (err) {
    // Hiba esetén naplózás és 500-as hiba küldése
    console.error('Error fetching data:', err);
    res.status(500).json({ message: 'Error fetching data. Please try again.' });
  }
});

// Új 'data' rekord felvitele (POST /data) - szintén védett végpont
app.post('/data', authenticateToken, async (req, res) => {
  try {
    // Adatok kinyerése a kérés törzséből
    const { name, city, country } = req.body;
    // Alapvető validáció: minden mező kitöltése kötelező
    if (!name || !city || !country) {
      return res.status(400).json({ message: 'Name, city, and country are required.' });
    }

    // Új rekord létrehozása a 'Data' táblában a kapott adatokkal
    // Itt is használhatnánk a req.user adatokat, ha pl. a létrehozott adathoz hozzá akarnánk rendelni a felhasználót
    // pl. const newData = await Data.create({ name, city, country, UserId: req.user.userId });
    const newData = await Data.create({ name, city, country });
    // Sikeres létrehozás esetén 201-es (Created) státusz és az új adat visszaküldése
    res.status(201).json(newData);
  } catch (err) {
    // Sequelize validációs hiba esetén specifikusabb hibaüzenet küldése
    if (err.name === 'SequelizeValidationError') {
        return res.status(400).json({ message: 'Validation error creating data.', errors: err.errors.map(e => e.message) });
    }
    // Egyéb hiba esetén naplózás és 500-as hiba küldése
    console.error('Error creating data:', err);
    res.status(500).json({ message: 'Error creating data. Please try again.' });
  }
});

// Alapvető "Not Found" (404) kezelő middleware a nem létező útvonalakra
// Ez akkor fut le, ha egyetlen korábbi útvonal sem illeszkedett a kérésre.
app.use((req, res, next) => {
  res.status(404).json({ message: 'Resource not found.' });
});

// Általános hibakezelő middleware
// Ez a middleware a lánc végén helyezkedik el, és elkap minden olyan hibát,
// amit a korábbi middleware-ek vagy útvonalkezelők továbbítottak a next(err) hívással,
// vagy ami szinkron kódban keletkezett és nem lett lekezelve.
app.use((err, req, res, next) => {
  console.error('Unhandled application error:', err.stack); // Hiba teljes stack trace-ének naplózása
  // Hiba státuszkódjának beállítása (ha van a hiba objektumban, egyébként 500)
  // és hibaüzenet visszaküldése JSON formátumban.
  res.status(err.status || 500).json({
    message: err.message || 'An unexpected error occurred on the server.',
    // Fejlesztői módban a teljes hiba stack trace-t is visszaküldhetjük (opcionális)
    ...(process.env.NODE_ENV === 'development' && { error: err.stack })
  });
});

// Szerver portjának beállítása a .env fájlból, vagy alapértelmezetten 3001
const PORT = process.env.PORT || 3001;
// Szerver indítása a megadott porton
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`); // Üzenet a konzolra, hogy a szerver fut
  // Adatbázis kapcsolat ellenőrzése a szerver indulása után (opcionális, de hasznos)
  sequelize.authenticate()
    .then(() => console.log('Database connection has been established successfully.'))
    .catch(err => console.error('Unable to connect to the database:', err));
});
