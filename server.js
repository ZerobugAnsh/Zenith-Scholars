require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const Razorpay = require("razorpay");
const cors = require("cors");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const formData = require("form-data");
const Mailgun = require("mailgun.js");

const app = express();

/* ================= CONFIG ================= */

app.use(cors({
  origin: "https://zerobugansh.github.io",
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());

/* ================= MONGODB ================= */

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.log("❌ MongoDB Error:", err));

/* ================= MAILGUN ================= */

const mailgun = new Mailgun(formData);
const mg = mailgun.client({
  username: "api",
  key: process.env.MAILGUN_API_KEY
});

/* ================= UTILITIES ================= */

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function extractToken(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return null;

  if (authHeader.startsWith("Bearer "))
    return authHeader.split(" ")[1];

  return authHeader;
}

/* ================= USER MODEL ================= */

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, default: "student" },
  isPaid: { type: Boolean, default: false },
  isVerified: { type: Boolean, default: false },
  otp: String,
  otpExpires: Date,
  payments: [
    {
      orderId: String,
      paymentId: String,
      amount: Number,
      paidAt: { type: Date, default: Date.now }
    }
  ]
});

const User = mongoose.model("User", userSchema);
/* ================= LIVE CLASS MODEL ================= */

const liveClassSchema = new mongoose.Schema({
  title: String,
  description: String,
  date: Date,
  meetLink: String,
  createdAt: { type: Date, default: Date.now }
});

const LiveClass = mongoose.model("LiveClass", liveClassSchema);

/* ================= REGISTER ================= */

app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });

    if (existingUser && existingUser.isVerified)
      return res.status(400).json({ error: "User already exists" });

    if (existingUser && !existingUser.isVerified)
      await User.deleteOne({ email });

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = generateOTP();

    await User.create({
      name,
      email,
      password: hashedPassword,
      otp,
      otpExpires: Date.now() + 5 * 60 * 1000
    });

    await mg.messages.create(process.env.MAILGUN_DOMAIN, {
      from: `Zenith Scholars <mailgun@${process.env.MAILGUN_DOMAIN}>`,
      to: [email],
      subject: "Zenith Scholars - Email Verification OTP",
      html: `<h2>Your OTP is:</h2><h1>${otp}</h1><p>Valid for 5 minutes.</p>`
    });

    res.json({ message: "OTP sent" });

  } catch (err) {
    console.log("REGISTER ERROR:", err);
    res.status(500).json({ error: "Registration failed" });
  }
});

/* ================= VERIFY OTP ================= */

app.post("/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "User not found" });

    if (user.otp !== otp)
      return res.status(400).json({ error: "Invalid OTP" });

    if (user.otpExpires < Date.now())
      return res.status(400).json({ error: "OTP expired" });

    user.isVerified = true;
    user.otp = null;
    user.otpExpires = null;
    await user.save();

    res.json({ message: "Email verified" });

  } catch (err) {
    res.status(500).json({ error: "OTP verification failed" });
  }
});

/* ================= LOGIN ================= */

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid email" });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword)
      return res.status(400).json({ error: "Invalid password" });

    if (!user.isVerified)
      return res.status(403).json({ error: "Email not verified" });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({ token });

  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});
/* ================= GET LIVE CLASSES ================= */

/* ================= GET LIVE CLASSES ================= */

app.get("/classes", async (req, res) => {
  try {
    const token = extractToken(req);
    if (!token) return res.status(401).json({ error: "No token" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(decoded.id);

    const classes = await LiveClass.find().sort({ date: 1 });

    // Attach paid status
    const updatedClasses = classes.map(cls => ({
      ...cls._doc,
      canJoin: user.isPaid
    }));

    res.json(updatedClasses);

  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
});
/* ================= DASHBOARD ================= */

app.get("/dashboard", async (req, res) => {
  try {
    const token = extractToken(req);
    if (!token) return res.status(401).json({ error: "No token" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    res.json({
      email: user.email,
      isPaid: user.isPaid
    });

  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
});

/* ================= ADMIN ================= */

app.get("/admin", async (req, res) => {
  try {
    const token = extractToken(req);
    if (!token) return res.status(401).json({ error: "No token" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== "admin")
      return res.status(403).json({ error: "Access denied" });

    const users = await User.find().select("-password");

    let totalRevenue = 0;
    users.forEach(user => {
      user.payments.forEach(p => totalRevenue += p.amount);
    });

    res.json({
      totalUsers: users.length,
      paidUsers: users.filter(u => u.isPaid).length,
      totalRevenue,
      students: users
    });

  } catch (err) {
    console.log("ADMIN ERROR:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/* ================= ADMIN ACTION ================= */

app.post("/admin/action", async (req, res) => {
  try {
    const token = extractToken(req);
    if (!token) return res.status(401).json({ error: "No token" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== "admin")
      return res.status(403).json({ error: "Access denied" });

    const { userId, action } = req.body;

    if (action === "delete")
      await User.findByIdAndDelete(userId);

    if (action === "togglePaid") {
      const user = await User.findById(userId);
      user.isPaid = !user.isPaid;
      await user.save();
    }

    if (action === "makeAdmin")
      await User.findByIdAndUpdate(userId, { role: "admin" });

    res.json({ message: "Action completed" });

  } catch (err) {
    res.status(500).json({ error: "Admin action failed" });
  }
});
/* ================= CREATE LIVE CLASS ================= */

app.post("/admin/create-class", async (req, res) => {
  try {
    const token = extractToken(req);
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.role !== "admin")
      return res.status(403).json({ error: "Access denied" });

    const { title, description, date, meetLink } = req.body;

    await LiveClass.create({
      title,
      description,
      date: new Date(date + ":00"),
      meetLink
    });

    res.json({ message: "Live class created" });

  } catch (err) {
    res.status(500).json({ error: "Failed to create class" });
  }
});

/* ================= RAZORPAY ================= */

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

app.post("/create-order", async (req, res) => {
  try {
    const order = await razorpay.orders.create({
      amount: 100,
      currency: "INR",
      receipt: "receipt_" + Date.now()
    });
    res.json(order);
  } catch {
    res.status(500).json({ error: "Order creation failed" });
  }
});

app.post("/verify-payment", async (req, res) => {
  try {
    const token = extractToken(req);
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    const body = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSignature = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(body)
      .digest("hex");

    if (expectedSignature !== razorpay_signature)
      return res.status(400).json({ status: "failure" });

    await User.findByIdAndUpdate(decoded.id, {
      isPaid: true,
      $push: {
        payments: {
          orderId: razorpay_order_id,
          paymentId: razorpay_payment_id,
          amount: 100,
          paidAt: new Date()
        }
      }
    });

    res.json({ status: "success" });

  } catch {
    res.status(400).json({ error: "Payment verification failed" });
  }
});

/* ================= SERVER ================= */

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});