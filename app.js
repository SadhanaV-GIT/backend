// ====================== IMPORTS ======================
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const { rateLimit } = require("express-rate-limit");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");

// ====================== CONFIG ======================
dotenv.config();

const app = express();
const PORT = process.env.PORT;
const SECRETKEY = process.env.SECRETKEY;

// ====================== MIDDLEWARE ======================
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate Limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 55,               // max requests per IP
  standardHeaders: "draft-8",
  legacyHeaders: false
});

app.use(limiter);

// ====================== DATABASE CONNECTION ======================
async function connectDB() {
  try {
    await mongoose.connect(process.env.MONGODBURL);
    console.log("✅ MongoDB Connected Successfully");
  } catch (error) {
    console.error("❌ MongoDB Connection Failed:", error.message);
    process.exit(1);
  }
}

// ====================== USER SCHEMA & MODEL ======================
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const User = mongoose.model("User", userSchema);

// ====================== AUTH ROUTES ======================

// SIGNUP
app.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ msg: "All fields are required" });
    }

    const existingUser = await User.findOne({
      $or: [{ username }, { email }]
    });

    if (existingUser) {
      return res.status(409).json({ msg: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
      username,
      email,
      password: hashedPassword
    });

    res.status(201).json({ msg: "Registration successful" });

  } catch (error) {
    res.status(500).json({ msg: error.message });
  }
});

// SIGNIN
app.post("/signin", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ msg: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ msg: "Incorrect username or password" });
    }

    const token = jwt.sign(
      { username: user.username },
      SECRETKEY,
      { expiresIn: "1h" }
    );

    res.json({
      msg: "Login successful",
      token
    });

  } catch (error) {
    res.status(500).json({ msg: error.message });
  }
});

// ====================== PRODUCT SCHEMA & MODEL ======================
const productSchema = new mongoose.Schema({
  title: { type: String, required: true },
  price: { type: Number, required: true },
  img:   { type: String, required: true }
});

const Product = mongoose.model("Product", productSchema);

// ====================== PRODUCT ROUTES ======================

// GET ALL PRODUCTS
app.get("/products", async (req, res) => {
  try {
    const products = await Product.find();
    res.json({ products });
  } catch (error) {
    res.status(500).json({ msg: error.message });
  }
});

// ADD PRODUCT
app.post("/submitproduct", async (req, res) => {
  try {
    const { title, price, img } = req.body;

    if (!title || !price || !img) {
      return res.status(400).json({ msg: "All fields are required" });
    }

    const newProduct = new Product({ title, price, img });
    await newProduct.save();

    res.status(201).json({ msg: "Product added successfully" });

  } catch (error) {
    res.status(500).json({ msg: error.message });
  }
});

// ====================== TEST ROUTE ======================
app.get("/dummy", (req, res) => {
  const { name, age, location } = req.query;
  res.send(`My name is ${name}, age ${age}, from ${location}`);
});

// ====================== START SERVER ======================
app.listen(PORT, async () => {
  await connectDB();
  console.log(`🚀 Server running on port ${PORT}`);
});
