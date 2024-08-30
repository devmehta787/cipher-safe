require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const opener = require('opener');

const app = express();
const PORT = 3000;

const dbFile = 'passwords.db';
const secretKey = process.env.SECRET_KEY;

if (!secretKey) {
  console.error('SECRET_KEY is not set in the environment variables');
  process.exit(1);
}

const key = crypto.createHash('sha256').update(String(secretKey)).digest();

const db = new sqlite3.Database(dbFile, (err) => {
  if (err) {
    console.error('Error opening database', err);
  } else {
    console.log('Connected to the SQLite database.');
    db.run(`CREATE TABLE IF NOT EXISTS passwords (
      site_name TEXT PRIMARY KEY,
      encrypted_password TEXT NOT NULL
    )`);
  }
});

function generatePassword(length = 10) {
  const minLength = 10;
  const actualLength = Math.max(length, minLength);
  
  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const numbers = '0123456789';
  const special = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  const allChars = lowercase + uppercase + numbers + special;

  let password = '';
  
  password += lowercase[crypto.randomInt(lowercase.length)];
  password += uppercase[crypto.randomInt(uppercase.length)];
  password += numbers[crypto.randomInt(numbers.length)];
  password += special[crypto.randomInt(special.length)];

  for (let i = password.length; i < actualLength; i++) {
    password += allChars[crypto.randomInt(allChars.length)];
  }

  return password.split('').sort(() => 0.5 - Math.random()).join('');
}

function encryptPassword(password) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(password, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decryptPassword(encryptedPassword) {
  const [ivHex, encryptedHex] = encryptedPassword.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function checkPasswordIntegrity(encryptedPassword) {
  const parts = encryptedPassword.split(':');
  if (parts.length !== 2) {
    return false;
  }
  const [ivHex, encryptedHex] = parts;
  return ivHex.length === 32 && encryptedHex.length % 32 === 0;
}

app.use(express.json());
app.use(cors());

app.use(express.static('public'));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/generate', (req, res) => {
  const { siteName, length } = req.body;
  if (!siteName) {
    return res.status(400).json({ error: 'Site name is required' });
  }
  
  db.get('SELECT encrypted_password FROM passwords WHERE site_name = ?', [siteName], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Error checking existing password' });
    }
    
    if (row) {
      try {
        const decryptedPassword = decryptPassword(row.encrypted_password);
        return res.json({ siteName, password: decryptedPassword, message: 'Existing password retrieved' });
      } catch (decryptError) {
        console.error('Decryption error:', decryptError);
        return res.status(500).json({ error: 'Error decrypting existing password' });
      }
    } else {
      const password = generatePassword(length);
      const encryptedPassword = encryptPassword(password);
      
      db.run('INSERT INTO passwords (site_name, encrypted_password) VALUES (?, ?)', 
        [siteName, encryptedPassword], 
        function(err) {
          if (err) {
            return res.status(500).json({ error: 'Error storing password' });
          }
          res.json({ siteName, password, message: 'New password generated and stored' });
        }
      );
    }
  });
});

app.get('/password/:siteName', (req, res) => {
  const { siteName } = req.params;
  
  db.get('SELECT encrypted_password FROM passwords WHERE site_name = ?', [siteName], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Error retrieving password' });
    }
    if (row) {
      if (!checkPasswordIntegrity(row.encrypted_password)) {
        return res.status(500).json({ error: 'Stored password data is corrupted' });
      }
      try {
        const decryptedPassword = decryptPassword(row.encrypted_password);
        res.json({ siteName, password: decryptedPassword });
      } catch (decryptError) {
        console.error('Decryption error:', decryptError);
        res.status(500).json({ 
          error: 'Error decrypting password',
          details: decryptError.message,
          code: decryptError.code,
          storedData: row.encrypted_password
        });
      }
    } else {
      res.status(404).json({ error: 'Password not found for this site' });
    }
  });
});

app.put('/regenerate/:siteName', (req, res) => {
  const { siteName } = req.params;
  const { length } = req.body;
  
  const newPassword = generatePassword(length);
  const encryptedPassword = encryptPassword(newPassword);
  
  db.run('UPDATE passwords SET encrypted_password = ? WHERE site_name = ?', 
    [encryptedPassword, siteName], 
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Error updating password' });
      }
      if (this.changes > 0) {
        res.json({ siteName, password: newPassword });
      } else {
        res.status(404).json({ error: 'Site not found' });
      }
    }
  );
});

app.post('/reset-database', (req, res) => {
  db.run('DROP TABLE IF EXISTS passwords', (dropErr) => {
    if (dropErr) {
      console.error('Error dropping table:', dropErr);
      return res.status(500).json({ error: 'Failed to reset database' });
    }

    db.run(`CREATE TABLE passwords (
      site_name TEXT PRIMARY KEY,
      encrypted_password TEXT NOT NULL
    )`, (createErr) => {
      if (createErr) {
        console.error('Error creating table:', createErr);
        return res.status(500).json({ error: 'Failed to reset database' });
      }

      res.json({ message: 'Database reset successfully. All passwords have been deleted.' });
    });
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  
  try {
    opener(`http://localhost:${PORT}`);
  } catch (err) {
    console.error('Failed to open browser:', err);
  }
});
