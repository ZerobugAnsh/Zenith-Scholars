require("dotenv").config();
require("dotenv").config();


console.log("KEY SECRET:", process.env.RAZORPAY_KEY_SECRET);
const express = require("express");
const Razorpay = require("razorpay");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());

// 🔑 Replace with your real keys "rzp_test_SLIGESsldVkADb"
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// Create Order
app.post("/create-order", async (req, res) => {
    try {
        const options = {
            amount: 100, // ₹500 (amount in paise)
            currency: "INR",
            receipt: "receipt_order_1"
        };
        console.log("Order created:", order.id);

        const order = await razorpay.orders.create(options);
        res.json(order);
    } catch (error) {
        res.status(500).json({ error: "Order creation failed" });
    }
});

// Verify Payment
app.post("/verify-payment", (req, res) => {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    const body = razorpay_order_id + "|" + razorpay_payment_id;

    const expectedSignature = crypto
        .createHmac("sha256", "YOUR_KEY_SECRET")
        .update(body)
        .digest("hex");

    if (expectedSignature === razorpay_signature) {
        res.json({ status: "success" });
    } else {
        res.status(400).json({ status: "failure" });
    }
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});