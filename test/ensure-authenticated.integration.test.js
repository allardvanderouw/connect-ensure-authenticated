const assert = require('assert');
const request = require('supertest');

const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bodyParser = require('body-parser');
const session = require('express-session');
const cookieParser = require('cookie-parser');

const { ensureAuthenticated } = require('../lib');

const testUser = {
  username: 'bob',
  password: '12345',
  firstName: 'Bob',
  favoriteNumber: 42,
};

describe('ensureAuthenticated integration test', () => {
  let app;
  let server;

  before(async () => {
    app = express();

    // Resolve with test user without checks for test
    passport.use(new LocalStrategy(async (username, password, done) => {
      done(null, testUser);
    }));

    passport.serializeUser((user, done) => {
      done(null, user.username);
    });

    // Resolve with test user without checks for test
    passport.deserializeUser(async (username, done) => {
      done(null, testUser);
    });

    app.use(cookieParser()); // Add cookieParser for user serialization from cookie
    app.use(bodyParser.json()); // The json bodyParser is added the set JSON data in req.body
    app.use(session({ secret: 'mandatory', resave: false, saveUninitialized: false })); // Add sessions

    app.use(passport.initialize()); // Initialize passport
    app.use(passport.session()); // Add session to passport

    // Create session
    app.post('/api/login', (req, res, next) => {
      passport.authenticate('local', (authenticationError, user, info) => {
        if (authenticationError) {
          res.status(500);
          res.json({ error: authenticationError });
        } else if (info) {
          res.status(400);
          res.json({ error: info });
        } else {
          req.logIn(user, (loginError) => {
            if (loginError) {
              res.status(401);
              res.json({ error: loginError });
            } else {
              res.status(200);
              res.json(user);
            }
          });
        }
      })(req, res, next);
    });

    // Dummy route which can only be accessed when authenticated
    app.get('/api/authenticated', ensureAuthenticated(), (req, res) => {
      res.status(200);
      res.json({ authenticated: true });
    });

    // End session
    app.post('/api/logout', ensureAuthenticated(), (req, res) => {
      req.logout();
      res.json({ logout: true });
    });

    // Add unless router for testing
    const unlessRouter = express.Router();
    unlessRouter.use(ensureAuthenticated().unless({ path: ['/api/unless/not-authenticated'] }));

    unlessRouter.get('/authenticated', (req, res) => {
      res.status(200);
      res.json({ authenticated: true });
    });

    unlessRouter.get('/not-authenticated', (req, res) => {
      res.status(200);
      res.json({ notAuthenticated: true });
    });

    app.use('/api/unless/', unlessRouter);

    // Add custom options router for testing
    const customOptionsRouter = express.Router();
    customOptionsRouter.use(ensureAuthenticated({
      statusCode: 418,
      message: 'I\'m a teapot!',
    }));

    customOptionsRouter.get('/authenticated', (req, res) => {
      res.status(200);
      res.json({ authenticated: true });
    });

    app.use('/api/custom-options/', customOptionsRouter);

    // Start sserver
    server = await app.listen(3000);
  });

  after(async () => {
    await server.close();
  });

  describe('without unless', () => {
    it('should successfully login and access a protected route', async () => {
      const loginResponse = await request('http://localhost:3000')
        .post('/api/login')
        .send({
          username: testUser.username,
          password: testUser.password,
        });

      assert.equal(loginResponse.status, 200);
      assert.deepStrictEqual(loginResponse.body, testUser);

      const cookie = loginResponse.headers['set-cookie'];
      assert.notEqual(cookie, undefined);

      const response = await request('http://localhost:3000')
        .get('/api/authenticated')
        .set('cookie', cookie);

      assert.equal(response.status, 200);
      assert.deepStrictEqual(response.body, { authenticated: true });

      const logoutResponse = await request('http://localhost:3000')
        .post('/api/logout')
        .set('cookie', cookie);

      assert.equal(logoutResponse.status, 200);
      assert.deepStrictEqual(logoutResponse.body, { logout: true });
    });

    it('should throw an error if the user is not authenticated', async () => {
      const response = await request('http://localhost:3000')
        .get('/api/authenticated');

      assert.equal(response.status, 401);
      assert.deepStrictEqual(response.body, { message: 'Authentication required' });
    });
  });

  describe('with unless', () => {
    it('should successfully login and access a protected route guarded by unless', async () => {
      const loginResponse = await request('http://localhost:3000')
        .post('/api/login')
        .send({
          username: testUser.username,
          password: testUser.password,
        });

      assert.equal(loginResponse.status, 200);
      assert.deepStrictEqual(loginResponse.body, testUser);

      const cookie = loginResponse.headers['set-cookie'];
      assert.notEqual(cookie, undefined);

      const response = await request('http://localhost:3000')
        .get('/api/unless/authenticated')
        .set('cookie', cookie);

      assert.equal(response.status, 200);
      assert.deepStrictEqual(response.body, { authenticated: true });

      const logoutResponse = await request('http://localhost:3000')
        .post('/api/logout')
        .set('cookie', cookie);

      assert.equal(logoutResponse.status, 200);
      assert.deepStrictEqual(logoutResponse.body, { logout: true });
    });

    it('should throw an error if the user is not authenticated', async () => {
      const response = await request('http://localhost:3000')
        .get('/api/unless/authenticated');

      assert.equal(response.status, 401);
      assert.deepStrictEqual(response.body, { message: 'Authentication required' });
    });

    it('should successfully return because the route is not authenticated due to unless', async () => {
      const response = await request('http://localhost:3000')
        .get('/api/unless/not-authenticated');

      assert.equal(response.status, 200);
      assert.deepStrictEqual(response.body, { notAuthenticated: true });
    });
  });

  describe('custom options', () => {
    it('should throw a custom error message/status if the user is not authenticated', async () => {
      const response = await request('http://localhost:3000')
        .get('/api/custom-options/authenticated');

      assert.equal(response.status, 418);
      assert.deepStrictEqual(response.body, { message: 'I\'m a teapot!' });
    });
  });
});
