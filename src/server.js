const authRoutes = require("./routes/authRoutes");
const {
  PORT,
  AUTH,
  AUTH_TYPES,
  HTTP_ONLY,
  SECURE,
  SAME_SITE,
} = require("./config.js");

const app = require("./app.js");

app.listen(PORT, (err) => {
  if (err) {
    console.log(`Failed to start the server ${err}`);
  }
  console.log(`server running on port ${PORT}`);
  console.log(`Using ${AUTH} authentication`);
  console.log(`HTTPOnly is ${HTTP_ONLY}`);
  console.log(`Secure is ${SECURE}!`);
  console.log(`Same site is ${SAME_SITE}`);
});

/////
