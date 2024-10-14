const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../config/keys');


exports.authenticateJWT = (req, res, next) => {
const token = req.headers.authorization?.split(' ')[1];
	if (token) {
jwt.verify(token, JWT_SECRET, (err, user) => {
if (err) return res.status(403).json({ message: 'Forbidden' });
	req.user = user;
	next();
});
	} else {
res.status(401).json({ message: 'Unauthorized'});
	}
};
