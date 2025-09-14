# Secure-Login-Part-1-SWE314-project-phase-1-
This is a team based project in Software Security Engineering course (SWE314) in King Saud University, the project aims to provide secure login system.
This phase focus on basic security revolving around CIA triad.

1. Introduction 
Secure Authentication System 
This file analyzes security threats in a login/signup system, focusing on 
identifying vulnerabilities, exploiting a weakness, and implementing a 
secure authentication mechanism. We identify common attacks and their 
countermeasures. We demonstrate how an attacker can exploit a specific 
vulnerability to steal an admin password. Finally, we implement a 
defense-in-depth strategy to protect the system. 

** what you need to install before running the software:
** Rate limit : npm install express-rate-limit
** 2FA token  : npm install speakeasy
** QR code    : npm install qrcode

2. Threat Model
2.1 Possible Threats 
 
** Threat | Threat Description | Trust Boundary 
** Shoulder Surfing | Password is visible in plain text, 
allowing attackers to see it | User/ Web Server 
** Brute Force | Attackers can guess passwords by 
brute force. | User/ Web Server 
** SQL Injection | Attack User inputs are directly inserted into 
SQL queries without sanitization | Web Server / Database 
** Distributed Denial of Service | Attackers flood the login system with 
excessive requests, making it 
unavailable.| User/ Web Server

2.2 Countering Threats 
2.2.1 Shoulder Surfing Attack 
● Enable password masking 
 
 2.2.2 Brute Force Attack 
● Implement rate-limiting: Max 5 attempts per 15 minutes 
● Two-Factor Authentication (2FA) 
 
 2.2.3 SQL Injection Attack  
● Use prepared statements (parameterized queries) 
● Validate and sanitize user inputs 
 
 
 2.2.4 Distributed Denial of Service (DDoS) Attack 
● Enable CAPTCHA to block bots 
● Implement rate-limiting for login attempts 

** Exploit Vulnerability 
Steal Admin password:
 Since the code isn’t secure, users’ passwords can be stolen, we can exploit more than one
 vulnerability to steal admin’s passwords, we can do that by:
 3.1 SQL Injection (SQLi) 
We can exploit the SQL statement in the code that reads directly from user input
 const sql = `SELECT * FROM users WHERE username = '${username}' AND 
password = '${password}'`; 
to inject a malicious input to make the code access to admin account without knowing the
 password, if we put username: admin’;-- and password: z (Or anything, it doesn’t matter)

 The code will act as: 
const sql = `SELECT * FROM users WHERE username = 'admin'’;--  
AND password = 'z'`; 
Everything in the second line won’t be executed because the input injected a sql statement where 
it selects the username admin, then end the statement with (;) and ignores everything after it with 
(--), in this case the code will ignore the password and login into admin account using username 
only, then steals the password. 
Possible solution
 A- Parameterized Queries      
B- Object Relational Mapping (ORM)

3.2 Brute Force attack  
A brute force attack systematically attempts all possible password combinations to gain 
unauthorized access to user accounts. Such attacks exploit systems that lack robust password 
security policies or fail to implement necessary protective mechanisms like rate limiting, 
CAPTCHAs, or account lockouts. 
How it Works: 
• An attacker uses automated tools to rapidly guess passwords. 
• The absence of login attempt limitations allows unlimited guesses. 
• Without CAPTCHA or similar verification methods, automated scripts can run continuously 
without interruption. 

Possible solutions: 
A- Strong Password Policies: Enforce a minimum length (e.g., 12+ characters) and complexity 
requirements (uppercase, lowercase, digits, special characters). 
B- Delay between login attempts (Rate Limiting) 
Rate limiting is a security technique that helps protect systems from brute force and Denial of 
Service (DoS) attacks by restricting the number of login attempts within a specific timeframe. 
C- CAPTCHA or reCAPTCHA 
Introduce visual or logic puzzles that humans can solve easily but that are difficult for bots to 
solve. 
D- Two-Factor Authentication (2FA) 
Two-factor authentication (2FA) is designed to add an extra layer of security to the basic login 
procedure.

3.3 Shoulder Surfing attack 
The simplest and oldest password stealing attack, by being behind the admin when he 
login, you can look at his screen to see the password and memorize it.
Possible solution: password masking

Implement Secure Authentication System 
4.1 Fix all possible vulnerabilities 
4.1.1 Rate Limiting 
const rateLimit = require('express-rate-limit'); 
const loginLimiter = rateLimit({ 
windowMs: 15 * 60 * 1000, // 15 minutes window 
max: 5,                   
delayMs: 5000,            
// limit to 5 requests per windowMs 
// 5 seconds delay between requests 
message: "Too many login attempts from this IP, please try again later." 
}); 
// Applied to login route 
app.post('/login', loginLimiter, async (req, res) => { 
// Login logic 
}); 
The rate limiter prevents brute force attacks and Distributed Denial of Service (DDoS) Attacks 
by limiting login attempts to 5 per IP address within a 15-minute window. After reaching this 
limit, further attempts are blocked with a 5-second delay between attempts. 
4.1.2 Password Masking 
Password masking is implemented using the HTML password input type, which displays 
asterisks or dots instead of the actual characters: 
<input type="password" id="password" name="password" required> 
This prevents shoulder surfing attacks where attackers might observe users typing their 
passwords.

4.1.3 SQL Injection Prevention  
Our system uses parameterized queries through a database abstraction layer: 
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
 });

 Sign up: 
  // Using parameterized query to prevent SQL injection
  const sql = 'INSERT INTO users (username, password, salt, twoFactorSecret) VALUES (?, ?, ?, ?)';

   This prevents SQL injection by separating SQL code from data, ensuring user inputs cannot be 
interpreted as SQL commands. 
4.1.4 Password Constraints 
Password requirements enforce strong passwords:
  <input type="password"
  title="Must contain at least one number, one uppercase and lowercase letter, and at 
  least 12 or more characters"
  id="password"
  name="password"
  required
  pattern="(?=.*\d) (?=.*[a-z])(?=.*[A-Z]).{12,}">

  The implemented constraints require: - Minimum length of 12 characters - At least one digit - At least one lowercase letter - At least one uppercase letter

  4.2 Implement defense in depth 
1. Two-factor authentication (TOTP) 
In our system, we use TOTP (Time-Based One-Time Password)  
authentication, which is compatible with standard authenticator  
apps such as: - Google Authenticator - Microsoft Authenticator - IOS Authenticator 
 
Since we use the speakeasy library for TOTP, our implementation follows the 
industry-standard RFC 6238, ensuring compatibility with most major  
authenticator apps.  
This document describes an extension of the algorithm : 
https://datatracker.ietf.org/doc/html/rfc6238 
 
TOTP functions as part of the Authentication Layers in a Defense in Depth strategy. 
While passwords provide something you know, TOTP adds something you have (the 
authenticator app) to prevent unauthorized access even if passwords are compromised. It 
generates a temporary six-digit code that changes every 30 seconds.



2. Encryption 
To securely store the TOTP secret in the database, we use AES-256-CBC 
encryption. This prevents unauthorized access to the raw secret and adds an extra layer of 
protection in our Defense in Depth strategy. Even if the database is compromised, 
attackers cannot use the secret without the encryption key. 
Encryption is applied to the 2FA secret before storing it in the database. During login, the 
encrypted secret is decrypted just in time to verify the user’s token. 
We use the crypto module in Node.js to handle encryption and decryption


3. Salting & hashing passwords 
Secure Authentication System 
In our system we used Hashing, unlike the Encryption Hashing is designed to be a 
one-way function which makes it impossible to reverse it and the Output of the hash function is a 
f
 ixed size, and Hashing is used to ensure data integrity and verifies data. 
Hashing function is used to store passwords securely Instead of storing the actual password, 
systems store the hash of the password, during authentication, the system compares the hash of 
the entered password with the stored hash, and if any password that has been hashed got leaked 
or stolen the attacker will only know the hash of the password not the actual password, the only 
problem with the hash function that the attacker may use pre-computed lookup tables (like 
rainbow tables) to crack the stored hashes since some passwords are common passwords (like 
Hello123)so, to solve this problem we add what we called Salting which is a random string that 
is added to the password before it is hashed which allow if multiple users have the same 
password the hash password of each one will be different because the unique salt that added to 
the passwords before hashing. 
Hashing function as part of the Authentication Layers in a Defense in Depth strategy: 
We use Secure Hash Algorithm 3 (SHA3-512)

Conclusion 
Secure Authentication System 
In this project, we have comprehensively secured our authentication system by thoroughly 
analyzing potential threats and implementing multiple layers of defense. We began by developing 
a detailed threat model and a Data Flow Diagram that clearly maps the flow of user data across 
the system, helping us to identify key vulnerabilities such as SQL injection, brute force attacks, 
and shoulder surfing. We demonstrated these vulnerabilities through targeted code examples and 
then implemented robust countermeasures such as parameterized queries, rate limiting, to 
effectively mitigate these risks. 
Furthermore, we enhanced our system by integrating two-factor authentication (TOTP) with 
encrypted storage of secrets. Each of these measures contributes to a defense-in-depth strategy 
that not only protects the integrity of user data but also ensures the overall resilience of the 
authentication process. 
Overall, our approach illustrates a practical and layered security solution that addresses both 
immediate vulnerabilities and long-term security challenges in modern web applications.
