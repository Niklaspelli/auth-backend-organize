const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../config/keys');

const users = require('../models/userModel');

const usersFilePath = './data/users.json';

const readUsersFromFile = () => {
const fileData = fs.readFileSync(usersFilePath);
	return JSON.parse(fileData);
};

const writeUsersToFile = (users) => {
	fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
};

exports.register = async (req, res) => {
const { username, password } = req.body;
const users = readUsersFromFile();

	if (users.find(user => user.username === username)) {
return res.status(400).json({ message: 'Username already exist'});
	}

	const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = { username, password: hashedPassword  };

	users.push(newUser);

	writeUsersToFile(users);
	res.json({ message: 'User registered!'});
};


exports.login = async (req, res) => {
        const { username, password } = req.body;
        const users = readUsersFromFile();

	const user = users.find(u => u.username === username);


	if (user && (await bcrypt.compare(password, user.password))) {
           const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h'});
	   res.json({ token });	
	} else {
          res.status(401).json({ message: 'Invalid credentials '});
	}
};
