require("dotenv").config();

module.exports = {
  JWT_SECRET: process.env.JWT_SECRET || "jensen",
  RECAPTCHA_SECRET: process.env.RECAPTCHA_SECRET,
};
