require('dotenv').config();
const express = require('express');
const Stripe = require('stripe');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// SUPABASE
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// ---------------- AUTH ----------------
app.post('/api/register', async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, 10);

  const { data } = await supabase
    .from('users')
    .insert([{ email: req.body.email, password: hash }])
    .select();

  res.json(data);
});

app.post('/api/login', async (req, res) => {
  const { data } = await supabase
    .from('users')
    .select('*')
    .eq('email', req.body.email)
    .single();

  if (!data) return res.status(400).send("No user");

  const ok = await bcrypt.compare(req.body.password, data.password);
  if (!ok) return res.status(400).send("Wrong password");

  const token = jwt.sign({ id: data.id }, process.env.JWT_SECRET);
  res.json({ token });
});

function auth(req, res, next) {
  try {
    const token = req.headers.authorization;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).send("Unauthorized");
  }
}

// ---------------- BOTS ----------------
const BOTS = {
  standard: { price: 5, xp: 100 },
  bronze: { price: 15, xp: 250 },
  silver: { price: 25, xp: 400 },
  gold: { price: 50, xp: 650 },
  premium: { price: 100, xp: 1000 },
  community1: { price: 300, xp: 2500 },
  community2: { price: 500, xp: 5000 }
};

// ---------------- BUY ----------------
app.post('/api/buy', auth, async (req, res) => {
  const bot = BOTS[req.body.type];

  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    mode: 'payment',
    line_items: [{
      price_data: {
        currency: 'usd',
        product_data: { name: req.body.type },
        unit_amount: bot.price * 100
      },
      quantity: 1
    }],
    metadata: {
      userId: req.userId,
      type: req.body.type,
      xp: bot.xp
    },
    success_url: process.env.CLIENT_URL,
    cancel_url: process.env.CLIENT_URL
  });

  res.json({ url: session.url });
});

// ---------------- WEBHOOK ----------------
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const event = stripe.webhooks.constructEvent(
    req.body,
    req.headers['stripe-signature'],
    process.env.STRIPE_WEBHOOK_SECRET
  );

  if (event.type === 'checkout.session.completed') {
    const s = event.data.object;

    await supabase.from('bots').insert([{
      user_id: s.metadata.userId,
      type: s.metadata.type,
      xp: parseInt(s.metadata.xp)
    }]);
  }

  res.json({ ok: true });
});

// ---------------- DASHBOARD ----------------
app.get('/api/dashboard', auth, async (req, res) => {
  const { data } = await supabase
    .from('users')
    .select('*')
    .eq('id', req.userId)
    .single();

  res.json(data);
});

// ---------------- WITHDRAW ----------------
app.post('/api/withdraw', auth, async (req, res) => {
  const { data } = await supabase
    .from('users')
    .select('*')
    .eq('id', req.userId)
    .single();

  const amount = data.xp * 0.01;

  await supabase.from('withdrawals').insert([{
    user_id: req.userId,
    amount
  }]);

  await supabase.from('users')
    .update({ xp: 0 })
    .eq('id', req.userId);

  res.json({ message: "Request sent" });
});

// ---------------- START ----------------
app.listen(5000, () => console.log("Running"));
