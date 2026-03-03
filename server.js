require("dotenv").config();
const nodemailer = require("nodemailer");

const express = require("express");
const mongoose = require("mongoose");
const Razorpay = require("razorpay");
const cors = require("cors");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

/* ================= MONGODB ================= */
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("MongoDB Connected"))
.catch(err => console.log("MongoDB Error:", err));

/* ================= MIDDLEWARE ================= */
app.use(cors({
  origin: "https://zerobugansh.github.io",
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});
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

/* ================= AUTH ROUTES ================= */
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ error: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = generateOTP();

    await User.create({
      name,
      email,
      password: hashedPassword,
      otp,
      otpExpires: Date.now() + 5 * 60 * 1000
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Zenith Scholars - Email Verification OTP",
      html: `
        <h2>Email Verification</h2>
        <p>Your OTP is:</p>
        <h1>${otp}</h1>
        <p>This OTP is valid for 5 minutes.</p>
      `
    });
console.log("EMAIL_USER:", process.env.EMAIL_USER);
console.log("EMAIL_PASS length:", process.env.EMAIL_PASS?.length);
    res.json({ message: "OTP sent to email" });

  } catch (err) {
    res.status(500).json({ error: "Registration failed" });
  }
});
app.post("/verify-otp", async (req, res) => {
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

  res.json({ message: "Email verified successfully" });
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid email" });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: "Invalid password" });
    if (!user.isVerified)
  return res.status(403).json({ error: "Email not verified" });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({ token });

  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

/* ================= DASHBOARD ================= */
app.get("/dashboard", async (req, res) => {
  try {
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ error: "No token" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) return res.status(404).json({ error: "User not found" });

    res.json({
      email: user.email,
      isPaid: user.isPaid
    });

  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
});

/* ================= ADMIN DASHBOARD ================= */
app.get("/admin", async (req, res) => {
  try {
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ error: "No token" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.role !== "admin") {
      return res.status(403).json({ error: "Access denied" });
    }

    const users = await User.find().select("-password");

    let totalRevenue = 0;

    users.forEach(user => {
      if (user.payments && user.payments.length > 0) {
        user.payments.forEach(p => {
          totalRevenue += p.amount;
        });
      }
    });

    res.json({
      totalUsers: users.length,
      paidUsers: users.filter(u => u.isPaid).length,
      totalRevenue,
      students: users
    });

  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
});

/* ================= ADMIN ACTIONS ================= */
app.post("/admin/action", async (req, res) => {
  try {
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ error: "No token" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.role !== "admin") {
      return res.status(403).json({ error: "Access denied" });
    }

    const { userId, action } = req.body;

    if (action === "delete") {
      await User.findByIdAndDelete(userId);
      return res.json({ message: "User deleted" });
    }

    if (action === "togglePaid") {
      const user = await User.findById(userId);
      user.isPaid = !user.isPaid;
      await user.save();
      return res.json({ message: "Payment status updated" });
    }

    if (action === "makeAdmin") {
      await User.findByIdAndUpdate(userId, { role: "admin" });
      return res.json({ message: "User promoted to admin" });
    }

    res.status(400).json({ error: "Invalid action" });

  } catch (err) {
    res.status(500).json({ error: "Action failed" });
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

  } catch (error) {
    res.status(500).json({ error: "Order creation failed" });
  }
});

app.post("/verify-payment", async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ error: "No token" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const body = razorpay_order_id + "|" + razorpay_payment_id;

    const expectedSignature = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(body)
      .digest("hex");

    if (expectedSignature !== razorpay_signature) {
      return res.status(400).json({ status: "failure" });
    }

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

  } catch (err) {
    res.status(400).json({ error: "Payment verification failed" });
  }
});

/* ================= SERVER ================= */
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});