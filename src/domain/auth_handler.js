const { ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET } = require("../config");

const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const generateAccessToken = (user) => {
  return jwt.sign(user, ACCESS_TOKEN_SECRET, { expiresIn: "15m" });
};

const generateRefreshToken = (user) => {
  return jwt.sign(user, REFRESH_TOKEN_SECRET, { expiresIn: "7d" });
};

const generateCsrfToken = () => {
  return crypto.randomBytes(16).toString("hex");
};

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  generateCsrfToken,
};
