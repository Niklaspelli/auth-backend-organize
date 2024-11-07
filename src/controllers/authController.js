const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");

const { JWT_SECRET, RECAPTCHA_SECRET } = require("../config/keys");
const { SECURE, HTTP_ONLY, SAME_SITE } = require("../config");
const {
  generateAccessToken,
  generateRefreshToken,
  generateCsrfToken,
} = require("../domain/auth_handler");
const users = require("../models/userModel");
const usersFilePath = "./data/users.json";

// Read users from the file
const readUsersFromFile = () => {
  const fileData = fs.readFileSync(usersFilePath);
  return JSON.parse(fileData);
};

// Write users to the file
const writeUsersToFile = (users) => {
  fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
};

// Register a new user
exports.register = async (req, res) => {
  const { username, password } = req.body;
  const users = readUsersFromFile();

  if (users.find((user) => user.username === username)) {
    return res.status(400).json({ message: "Username already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { username, password: hashedPassword };

  users.push(newUser);
  writeUsersToFile(users);
  res.json({ message: "User registered!" });
};

// Login a user
exports.login = async (req, res) => {
  const { username, password, recaptchaToken } = req.body;
  console.log("Received username:", username);
  console.log("Received password:", password);
  console.log("Received reCAPTCHA Token:", recaptchaToken);

  // Verify the reCAPTCHA token with Google
  try {
    const recaptchaResponse = await axios.post(
      `https://www.google.com/recaptcha/api/siteverify`,
      null,
      {
        params: {
          secret: RECAPTCHA_SECRET,
          response: recaptchaToken,
        },
      }
    );

    const { success, "error-codes": errorCodes } = recaptchaResponse.data;
    console.log("reCAPTCHA Response:", recaptchaResponse.data);

    if (!success) {
      console.error("reCAPTCHA verification failed:", errorCodes);
      return res.status(400).json({ message: "reCAPTCHA verification failed" });
    }
  } catch (error) {
    console.error("Error verifying reCAPTCHA:", error);
    return res.status(500).json({ message: "Error verifying reCAPTCHA" });
  }

  // Find the user and validate the password
  const users = readUsersFromFile();
  const user = users.find((u) => u.username === username);

  console.log("User found:", user);

  if (user) {
    // Check the stored hashed password against the plain password
    const passwordMatch = await bcrypt.compare(password, user.password);
    console.log("Password match:", passwordMatch);

    if (passwordMatch) {
      // Passwords match, proceed with token generation
      const accessToken = generateAccessToken(user);
      const refreshToken = generateRefreshToken(user);
      const csrfToken = generateCsrfToken();

      // Send cookies for access and refresh tokens
      res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: SECURE, // Ensure this is true in production (HTTPS)
        maxAge: 15 * 60 * 1000, // 15 minutes
        sameSite: SAME_SITE,
      });

      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: SECURE, // Ensure this is true in production (HTTPS)
        maxAge: 30 * 60 * 1000, // 30 minutes
        sameSite: SAME_SITE,
      });

      res.json({ csrfToken });
    } else {
      console.log("Password comparison failed for user:", username);
      return res.status(401).json({ message: "Invalid credentials" });
    }
  } else {
    console.log("User not found:", username);
    return res.status(401).json({ message: "Invalid credentials" });
  }
};

// Logout function
exports.logout = (req, res) => {
  res.clearCookie("accessToken", {
    httpOnly: true,
    sameSite: "Strict",
    secure: SECURE,
  });
  res.clearCookie("refreshToken", {
    httpOnly: true,
    sameSite: "Strict",
    secure: SECURE,
  });
  return res.status(200).json({ message: "Logout successful" });
};
