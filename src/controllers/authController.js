const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../config/keys");
const { SECURE, HTTP_ONLY, SAME_SITE } = require("../config");
const {
  generateAccessToken,
  generateRefreshToken,
  generateCsrfToken,
} = require("../domain/auth_handler");
const users = require("../models/userModel");
const usersFilePath = "./data/users.json";

//################################################

const readUsersFromFile = () => {
  const fileData = fs.readFileSync(usersFilePath);
  return JSON.parse(fileData);
};

const writeUsersToFile = (users) => {
  fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
};

//##############################################

exports.register = async (req, res) => {
  const { username, password } = req.body;
  const users = readUsersFromFile();

  if (users.find((user) => user.username === username)) {
    return res.status(400).json({ message: "Username already exist" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { username, password: hashedPassword };

  users.push(newUser);

  writeUsersToFile(users);
  res.json({ message: "User registered!" });
};

exports.login = async (req, res) => {
  const { username, password } = req.body;
  const users = readUsersFromFile();

  const user = users.find((u) => u.username === username);

  if (user && (await bcrypt.compare(password, user.password))) {
    /* const token = jwt.sign({ username: user.username }, JWT_SECRET, {
      expiresIn: "1h",
    }); */

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    const csrfToken = generateCsrfToken();

    res.cookie("accessToken", accessToken, {
      httpOnly: HTTP_ONLY,
      secure: SECURE,
      maxAge: 15 * 60 * 1000,
      sameSite: SAME_SITE,
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: HTTP_ONLY,
      secure: SECURE,
      maxAge: 15 * 60 * 1000,
      sameSite: SAME_SITE,
    });

    res.json({ csrfToken });
  } else {
    res.status(401).json({ message: "Invalid credentials " });
  }
};

exports.logout = (req, res) => {
  res.clearCookie("accessToken", {
    httpOnly: true,
    sameSite: "Strict",
    secure: true,
  });
  res.clearCookie("refreshToken", {
    httpOnly: true,
    sameSite: "Strict",
    secure: true,
  });
  return res.status(200).json({ message: "Logout successful" });
};

/* exports.logout = (req, res) => {
  res.status(200).send("Logout successful");
}; */

exports.basicLogin = (req, res) => {
  res.status(200).send("Basic login successful");
};

exports.bearerLogin = (req, res) => {
  res.status(200).send("Bearer token provided");
};

exports.refreshToken = (req, res) => {
  res.status(200).send("Bearer token refreshed");
};

exports.digestLogin = (req, res) => {
  res.status(200).send("Digest login successful");
};

exports.customLogin = (req, res) => {
  res.status(200).send("Custom login successful");
};
