import User from "../models/user";
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

export const prices = async (req, res) => {
  const prices = await stripe.prices.list();
  //   console.log("prices", prices);
  res.json(prices.data.reverse());
};

export const createSubscription = async (req, res) => {
  // console.log(req.body);
  try {
    const user = await User.findById(req.user._id);

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      payment_method_types: ["card"],
      line_items: [
        {
          price: req.body.priceId,
          quantity: 1,
        },
      ],
      customer: user.stripe_customer_id,
      success_url: process.env.STRIPE_SUCCESS_URL,
      cancel_url: process.env.STRIPE_CANCEL_URL,
    });
    console.log("checkout session", session);
    res.json(session.url);
  } catch (err) {
    console.log(err);
  }
};

export const subscriptionStatus = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);

    const subscriptions = await stripe.subscriptions.list({
      customer: user.stripe_customer_id,
      status: "all",
      expand: ["data.default_payment_method"],
    });

    const updated = await User.findByIdAndUpdate(
      user._id,
      {
        subscriptions: subscriptions.data,
      },
      { new: true }
    );

    res.json(updated);
  } catch (err) {
    console.log(err);
  }
};

export const subscriptions = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);

    const subscriptions = await stripe.subscriptions.list({
      customer: user.stripe_customer_id,
      status: "all",
      expand: ["data.default_payment_method"],
    });

    res.json(subscriptions);
  } catch (err) {
    console.log(err);
  }
};

export const customerPortal = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    const portalSession = await stripe.billingPortal.sessions.create({
      customer: user.stripe_customer_id,
      return_url: process.env.STRIPE_SUCCESS_URL,
    });
    res.json(portalSession.url);
  } catch (err) {
    console.log(err);
  }
};
