const express = require("express");
const path = require("path");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const database = require("./database/database.js");
const crypto = require("crypto");

const app = express();
const port = 3000;

const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes window
  max: 5,                   // limit to 5 requests per windowMs
  delayMs: 5000,            // 5 seconds delay between requests
  message: "Too many login attempts from this IP, please try again later."
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static files
app.use('/', express.static(path.join(__dirname, 'public', 'login')));
app.use('/signup', express.static(path.join(__dirname, 'public', 'signup')));

// Decryption function for 2FA secret
function decryptSecret(encryptedSecret) {
  const key = crypto.scryptSync("supersecretkey", "salt", 32); // Ensure the correct key length
  const iv = Buffer.alloc(16, 0); // 16-byte IV for AES-256-CBC
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  let decrypted = decipher.update(encryptedSecret, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// Signup Route with 2FA
app.post('/submitSignup', async (req, res) => {
  const { username, password } = req.body;
  
  // Generate 2FA secret
  const secret = speakeasy.generateSecret({ length: 20 });
  console.log("Generated Secret (Signup):", secret.base32);

  try {
    // Create user with hashed password and encrypted 2FA secret
    await database.signup({ 
      username, 
      password, 
      twoFactorSecret: secret.base32 
    });

    console.log(`User ${username} registered with secret: ${secret.base32}`);

    // Generate QR code for 2FA setup
    const otpauth_url = `otpauth://totp/${username}?secret=${secret.base32}&issuer=SWE314-Assignment1`;
    QRCode.toDataURL(otpauth_url, (err, qrImage) => {
      if (err) {
        console.error("QR Code Error:", err);
        return res.status(500).json({ error: "Error generating QR code" });
      }
      res.json({ 
        message: "User created! Please scan the QR code with your authenticator app",
        qrImage,
        manualEntryCode: secret.base32 // For manual entry option
      });
    });
  } catch (err) {
    console.error("Signup Error:", err);
    res.redirect('/signup?error=true');
  }
});

// Login Route with 2FA Verification
app.post('/login', loginLimiter, async (req, res) => {
  const { username, password, token } = req.body;

  try {
    // First authenticate with username/password
    const user = await database.authenticate({ username, password });
    
    if (user.length > 0) {
      const encryptedSecret = user[0].twoFactorSecret;
      const secret = decryptSecret(encryptedSecret);
      console.log("<<THIS IS FOR DEBUGGING>>");
      console.log("Stored Secret (Decrypted):", secret);//for debugging
      console.log("Received Token:", token);//for debugging
      console.log(user[0]); //for debugging

      // Verify 2FA token
      const verified = speakeasy.totp.verify({
        secret,
        encoding: "base32",
        token,
        window: 0 // 30-second window
      });

      if (verified) {
        res.json({ 
          success: true, 
          message: "Login successful!",
          user: {
            id: user[0].id,
            username: user[0].username
          }
        });
      } else {
        res.redirect('/?error=true');
      }
    } else {
      res.redirect('/?error=true');
    }
  } catch (err) {
    console.error("Login Error:", err);
    res.redirect('/?error=true');
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
