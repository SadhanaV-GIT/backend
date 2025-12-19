// ====================== IMPORTS ======================
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const rateLimit = require("express-rate-limit");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");

// ====================== CONFIG ======================
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const SECRETKEY = process.env.SECRETKEY;

if (!SECRETKEY) {
  throw new Error("❌ SECRETKEY not defined in environment variables");
}

// ====================== MIDDLEWARE ======================
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate Limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 55
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

// ====================== USER SCHEMA ======================
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});
const User = mongoose.model("User", userSchema);

// ====================== AUTH ROUTES ======================
app.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ msg: "All fields are required" });

    const existingUser = await User.findOne({
      $or: [{ username }, { email }]
    });
    if (existingUser)
      return res.status(409).json({ msg: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ username, email, password: hashedPassword });

    res.status(201).json({ msg: "Registration successful" });
  } catch (error) {
    res.status(500).json({ msg: error.message });
  }
});

app.post("/signin", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ msg: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ msg: "Incorrect credentials" });

    const token = jwt.sign({ id: user._id }, SECRETKEY, { expiresIn: "1h" });
    res.json({ msg: "Login successful", token });
  } catch (error) {
    res.status(500).json({ msg: error.message });
  }
});

// ====================== PRODUCT SCHEMA ======================
const productSchema = new mongoose.Schema({
  title: String,
  price: Number,
  img: String
});
const Product = mongoose.model("Product", productSchema);

// ====================== PRODUCT ROUTES ======================
app.get("/products", async (req, res) => {
  const products = await Product.find();
  res.json({ products });
});

app.post("/submitproduct", async (req, res) => {
  const { title, price, img } = req.body;
  if (!title || !price || !img)
    return res.status(400).json({ msg: "All fields required" });

  await Product.create({ title, price, img });
  res.status(201).json({ msg: "Product added successfully" });
});

// ====================== HEALTH CHECK ======================
app.get("/", (req, res) => {
  res.send("Backend running successfully 🚀");
});

// ====================== START SERVER ======================
(async () => {
  await connectDB();
  app.listen(PORT, () =>
    console.log(` Server running on port ${PORT}`)
  );
})();
