require("dotenv").config();

const express = require("express");
const Razorpay = require("razorpay");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
const cors = require("cors");

app.use(cors({
  origin: "https://zerobugansh.github.io",
  credentials: true
}));

app.options("*", cors());
app.use(express.json());

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

app.post("/create-order", async (req, res) => {
    try {
        const options = {
            amount: 100,
            currency: "INR",
            receipt: "receipt_order_1"
        };

      const order = await response.json();
      console.log("Order object:", order);
console.log("Order ID:", order.id);

        console.log("Order created:", order.id);

        res.json(order);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Order creation failed" });
    }
});

app.post("/verify-payment", (req, res) => {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    const body = razorpay_order_id + "|" + razorpay_payment_id;

    const expectedSignature = crypto
        .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
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