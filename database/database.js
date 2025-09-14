const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require("crypto");

const dbPath = path.resolve(__dirname, 'database.db');

// Hashing functions
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.createHash("sha3-512").update(salt + password).digest("hex");
  return { salt, hash };
}

function verifyPassword(storedSalt, storedHash, passwordToCheck) {
  const hashToCheck = crypto.createHash("sha3-512").update(storedSalt + passwordToCheck).digest("hex");
  return hashToCheck === storedHash;
}

// Encryption function for 2FA secret
function encryptSecret(secret) {
  const key = crypto.scryptSync("supersecretkey", "salt", 32); // Ensure correct key length
  const iv = Buffer.alloc(16, 0); // 16-byte IV for AES-256-CBC
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(secret, "utf8", "hex");
  encrypted += cipher.final("hex");
  return encrypted;
}

// Database operations
const dbinit = () => {
  const db = new sqlite3.Database(dbPath);
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    salt TEXT NOT NULL,
    twoFactorSecret TEXT NOT NULL
  )`);
  return db;
};

const authenticate = ({ username, password }) => {
  const db = dbinit();
  return new Promise((resolve, reject) => {
    // Using parameterized query to prevent SQL injection
    const sql = 'SELECT * FROM users WHERE username = ?';
    
    db.all(sql, [username], (err, rows) => {
      db.close();
      if (err) return reject(err);
      
      if (rows.length === 0) return resolve([]);
      
      const user = rows[0];
      if (verifyPassword(user.salt, user.password, password)) {
        resolve([user]);
      } else {
        resolve([]);
      }
    });
  });
};

const signup = ({ username, password, twoFactorSecret }) => {
  const db = dbinit();
  const { salt, hash } = hashPassword(password);
  const encryptedSecret = encryptSecret(twoFactorSecret);
  
  return new Promise((resolve, reject) => {
    // Using parameterized query to prevent SQL injection
    const sql = 'INSERT INTO users (username, password, salt, twoFactorSecret) VALUES (?, ?, ?, ?)';
    
    db.run(sql, [username, hash, salt, encryptedSecret], function(err) {
      db.close();
      if (err) return reject(err);
      resolve(true);
    });
  });
};

module.exports = {
  authenticate,
  signup
};
