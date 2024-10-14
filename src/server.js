const express = require("express");
const app = express();
const authRoutes = require("./routes/authRoutes");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

app.use(express.json());
app.use(helmet());

const limiter = rateLimit({
  windows: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

app.use("/", authRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`server running on port ${PORT}`);
});

/////
