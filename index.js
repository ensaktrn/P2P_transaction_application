// Gerekli paketleri yükleyin:
// npm init -y
// npm install express pg dotenv jsonwebtoken bcrypt cors

const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const dotenv = require("dotenv");
const cors = require("cors");

dotenv.config();
const app = express();
const port = process.env.PORT || 5001;

app.use(express.json());
app.use(cors());

// PostgreSQL bağlantısı
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT,
});

// Veritabanı tablolarını oluşturma
const createTables = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password TEXT NOT NULL
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS fake_cards (
        id SERIAL PRIMARY KEY,
        card_number VARCHAR(16) UNIQUE NOT NULL,
        cardholder_name VARCHAR(100) NOT NULL,
        cvv VARCHAR(3) NOT NULL,
        balance DECIMAL(10,2) NOT NULL
      );
    `);
    console.log("Database tables are set up");
  } catch (err) {
    console.error("Error creating tables", err);
  }
};
createTables();

// Kullanıcı kaydı (Sign-up)
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  
  try {
    const result = await pool.query(
      "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *",
      [username, hashedPassword]
    );
    res.json({ message: "User registered", user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Kullanıcı girişi (Login)
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    if (result.rows.length === 0) return res.status(400).json({ error: "User not found" });
    
    const user = result.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) return res.status(400).json({ error: "Invalid password" });
    
    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.json({ message: "Login successful", token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Kredi kartı ekleme (Fake kart ekleme)
app.post("/add-card", async (req, res) => {
  const { card_number, cardholder_name, cvv, balance } = req.body;
  try {
    await pool.query(
      "INSERT INTO fake_cards (card_number, cardholder_name, cvv, balance) VALUES ($1, $2, $3, $4)",
      [card_number, cardholder_name, cvv, balance]
    );
    res.json({ message: "Fake card added" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Kredi kartı doğrulama
app.post("/validate-card", async (req, res) => {
  const { card_number, cvv } = req.body;
  try {
    const result = await pool.query("SELECT * FROM fake_cards WHERE card_number = $1 AND cvv = $2", [card_number, cvv]);
    if (result.rows.length === 0) return res.status(400).json({ error: "Invalid card" });
    res.json({ message: "Card validated", card: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});