const express = require('express');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const session = require('express-session');
const KnexSessionStore = require('connect-session-knex');

const db = require('./dbConfig.js');
const Users = require('./users/users-module.js');

const server = express();
const sessionOptions = {
  name: 'Lambdaschool',
  secret: 'Enjoing lifes little secrets',
  cookie: {
    maxAge: 1000 * 60 * 60, //1000 = 1 second * 60 = 1 minute * 60 = 1 hour * 2 = 2 hour
    secure: false, //false by default
  },
  httpOnly: true,
  resave: false,
  saveUninitialized: false,
  
  store: new KnexSessionStore({
    knex: require('./dbConfig.js'),
    tablename: 'sessions',
    sidfieldname: 'sid',
    createtable: true,
    clearInterval: 1000 * 60 * 60
  }),
}

server.use(session(sessionOptions));
server.use(helmet());
server.use(express.json());

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
  let user = req.body;

// 1. Hash the pwd using bcrypt
  const hash = bcrypt.hashSync(user.password, 10); //2^n

// 2. replace the real pwd with the hash
  user.password = hash;

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
    // check that pwds match
      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.user = user;
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'You shall not pass!' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

function restricted(req, res, next) {
  const { username, password } = req.body;

  if(username && password) {
    Users.findBy({ username })
    .first()
    .then(user => {
    // check that pwds match
      if (user && bcrypt.compareSync(password, user.password)) {
        next();
      } else {
        res.status(401).json({ message: 'You shall not pass!' });
      }
    })
    .catch(error => {
      res.status(500).json({message: "Ran into an unexpected error"});
    });
  }
  else {
    res.status(400).json({ message: 'No credentials provided' });
  }
}

// protect this route, only authenticated users should see it
server.post('/api/users', restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

// Logout to end session
router.get('/logout', (req, res) => {
  if(req.session) {
    req.session.destroy( err => {
      if(err) {
        res.send('A problem occured while trying to logout');
      }
      else{
        res.send('You have successfully logged out!');
      }
    });
  }
  else {
    res.end();
  }
})

const port = process.env.PORT || 9090;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));