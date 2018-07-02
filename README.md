# connect-ensure-authenticated

[![NPM version](https://img.shields.io/npm/v/connect-ensure-authenticated.svg)](https://www.npmjs.com/package/connect-ensure-authenticated)
[![Build Status](https://travis-ci.com/allardvanderouw/connect-ensure-authenticated.svg?branch=master)](https://travis-ci.com/allardvanderouw/connect-ensure-authenticated)
[![codecov](https://codecov.io/gh/allardvanderouw/connect-ensure-authenticated/branch/master/graph/badge.svg)](https://codecov.io/gh/allardvanderouw/connect-ensure-authenticated)

This simple middleware ensures that a user is logged in with Passport (https://github.com/jaredhanson/passport). If a request is received that is unauthenticated, the request returns a JSON error.

## Install

Yarn
```
$ yarn add connect-ensure-authenticated
```

NPM
```
$ npm install connect-ensure-authenticated
```

## Usage

#### Ensure Authentication

In this example, an application has a whoami API endpoint. A user must be logged in before accessing this endpoint.

```javascript
const { ensureAuthenticated } = require('connect-ensure-authenticated');
const app = express()

app.get('/api/whoami', ensureAuthenticated(), (req, res) => {
  res.json({ user: req.user });
});
```
      
If a user is not logged in when attempting to access this page, the request will return a 401 status code with 

#### With unless

This middleware supports express-unless (https://github.com/jfromaniello/express-unless).

```javascript
const { ensureAuthenticated } = require('connect-ensure-authenticated');
const app = express()

app.use(ensureAuthenticated().unless({ path: ['/api/not-authenticated'] }));

app.get('/api/authenticated', (req, res) => {
  res.status(200);
  res.json({ authenticated: true });
});

app.get('/api/not-authenticated', (req, res) => {
  res.status(200);
  res.json({ notAuthenticated: true });
});

app.use('/api/unless/', unlessRouter);
```

The `/api/authenticated` endpoint returns an authentication error while `/api/not-authenticated` does not because it is exluded with unless.

#### With custom status code and/or message

The ensureAuthenticated middleware can be configured to return another status code and/or message.

```javascript
const { ensureAuthenticated } = require('connect-ensure-authenticated');
const app = express()

app.use(ensureAuthenticated({
  statusCode: 418, // default = 401
  message: 'I\'m a teapot!', // default = Authentication required
}));

app.get('/api/authenticated', (req, res) => {
  res.status(200);
  res.json({ authenticated: true });
});

app.use('/api/unless/', unlessRouter);
```

#### How do I use this with Passport?

Take a look at the integration test for some inspiration. I might create a full-blown example in the near future.

## Prior art

This module was heavily inspired by [Jared Hanson's connect-ensure-login module](https://github.com/jaredhanson/connect-ensure-login).