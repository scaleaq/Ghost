const express = require('../../../shared/express');
const passport = require('passport');
const debug = require('@tryghost/debug')('scaleaq:auth');
const cookieParser = require('cookie-parser');
const expressSession = require('express-session');
const config = require('../../../shared/config');

module.exports = () => {
  debug('AuthApp setup start');

  let identityMetadata = config.get('auth:identityMetadata');
  let clientId = config.get('auth:clientId');
  let redirectUrl = config.get('auth:redirectUrl');
  let cookieEncryptionKeys = config.get('auth:cookieEncryptionKeys');
  let requireHttps = config.get('auth:requireHttps');
  let cookieExpirationInSeconds = config.get('auth:cookieExpirationInSeconds');

  function ensureAuthenticated(req, res, next) {
      debug('Checking if user is logged in...');
      if(req.user) {
          debug('found user!');
      }
      if (req.isAuthenticated()) { return next(); }
      res.redirect('/login');
  }

  passport.serializeUser((user, done) => {
      debug('Serializing user');
      done(null, user.oid);
  });
    
  passport.deserializeUser((oid, done) => {
      debug('Deserializing user');
      findByOid(oid, function (err, user) {
          done(err, user);
      });
  });

  // array to hold logged in users
  var users = [];

  var findByOid = function(oid, fn) {
    for (var i = 0, len = users.length; i < len; i++) {
      var user = users[i];
    debug('we are using user: ', user);
      if (user.oid === oid) {
        return fn(null, user);
      }
    }
    return fn(null, null);
  };

  const OIDCStrategy = require('passport-azure-ad').OIDCStrategy;

  passport.use(new OIDCStrategy({
      identityMetadata: identityMetadata,
      clientID: clientId,
      redirectUrl: redirectUrl,
      allowHttpForRedirectUrl: !requireHttps,
      responseType: 'id_token',
      responseMode: 'form_post',
      nonceLifetime: cookieExpirationInSeconds,
      nonceMaxAmount: 5,
      useCookieInsteadOfSession: true,
      cookieEncryptionKeys: cookieEncryptionKeys, 
    },
    function(iss, sub, profile, accessToken, refreshToken, done) {
      debug('Got profile!');
      if (!profile.oid) {
          return done(new Error("No oid found"), null);
        }
        // asynchronous verification, for effect...
        process.nextTick(function () {
          findByOid(profile.oid, function(err, user) {
            if (err) {
              return done(err);
            }
            if (!user) {
              // "Auto-registration"
              users.push(profile);
              return done(null, profile);
            }
            return done(null, user);
          });
        });
    }
  ));

  const authApp = express('auth');
  authApp.use(cookieParser());
  authApp.use(expressSession({ secret: 'keyboard cat', resave: true, saveUninitialized: false }));

  authApp.use(express.urlencoded({ extended : true }));

  authApp.use(passport.initialize());
  authApp.use(passport.session());

  authApp.get('/login',
    function(req, res, next) {
      passport.authenticate('azuread-openidconnect', 
        { 
          response: res,
          session: false,
          failureRedirect: '/' 
        }
      )(req, res, next);
    },
    function(req, res) {
      res.redirect('/');
  });

  authApp.post('/redirect',
    function(req, res, next) {
      passport.authenticate('azuread-openidconnect', { response: res })(req, res, next);
    },
    function(req, res) {
      res.redirect('/');
    });

  authApp.use(ensureAuthenticated, (req, res, next) => {
      next();
  });

  return authApp;
}