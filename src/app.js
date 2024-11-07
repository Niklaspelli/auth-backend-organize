const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const app = express();
const { AUTH, AUTH_TYPES } = require("./config");
const authRoutes = {
  [AUTH_TYPES.BASIC]: require("./routes/authRoutes"),
};

app.use(
  cors({
    origin: "http://localhost:5000", // Allow requests from this origin
    methods: ["GET", "POST", "PUT", "DELETE"], // Allowed methods
    credentials: true, // Allow cookies to be sent
  })
);

const limiter = rateLimit({
  windows: 15 * 60 * 1000,
  max: 100,
});

app.use(limiter);
app.use(express.json());
app.use(helmet());

const { handleHealthCheck } = require("@kunalnagarco/healthie");
app.use(handleHealthCheck());

app.use("/api/auth", authRoutes[AUTH_TYPES.BASIC]);
app.use((req, res) => res.status(404).send("Not Foundz"));

module.exports = app;
