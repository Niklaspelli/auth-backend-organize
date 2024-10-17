const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const app = express();
const { AUTH, AUTH_TYPES } = require("./config");
const authRoutes = {
  [AUTH_TYPES.BASIC]: require("./routes/authRoutes"),
};

const limiter = rateLimit({
  windows: 15 * 60 * 1000,
  max: 100,
});

app.use(limiter);
app.use(express.json());
app.use(helmet());

app.use("/api/auth", authRoutes[AUTH_TYPES.BASIC]);
app.use((req, res) => res.status(404).send("Not Foundz"));

module.exports = app;
