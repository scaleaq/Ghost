const express = require('../../../shared/express');
const passport = require('passport');
const debug = require('@tryghost/debug')('scaleaq:auth');
const cookieParser = require('cookie-parser');
const expressSession = require('express-session');
const config = require('../../../shared/config');
const crypto = require('crypto');

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

      //Store return to url
      req.session.returnTo = req.originalUrl;
      res.redirect('/login');
  }

  passport.serializeUser((user, done) => {
      debug('Serializing user');
      done(null, user);
  });
    
  passport.deserializeUser((user, done) => {
      debug('Deserializing user');
      done(null, user);
  });

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
        return done(null, profile);
    }
  ));

  const authApp = express('auth');
  authApp.use(cookieParser());
  let sess = {
    secret: 'keyboard cat', 
    resave: true, 
    saveUninitialized: false
  };
  
  if (authApp.get('env') === 'production') {
    sess.cookie.secure = true // serve secure cookies
  }
  authApp.use(expressSession(sess));

  authApp.use(express.urlencoded({ extended : true }));

  authApp.use(passport.initialize());
  authApp.use(passport.session());

  authApp.get('/login',
    function(req, res, next) {
      passport.authenticate('azuread-openidconnect', 
        { 
          session: false,
        }
      )(req, res, next);
    },
    function(req, res) {
      res.redirect('/');
  });

  authApp.post('/redirect',
    function(req, res, next) {
      passport.authenticate('azuread-openidconnect', { request: req, successReturnToOrRedirect: req.session.returnTo })(req, res, next);
    });
    // function(req, res) {
    //   res.redirect('/');
    // });

  authApp.get('/commento-sso', ensureAuthenticated, (req, res, next) => {
    let key = process.env.COMMENTO_KEY;
    let token = req.query.token;
    let hmac = req.query.hmac;

    let bufferedToken = Buffer.from(token, 'hex');
    let bufferedKey = Buffer.from(key, 'hex');

    let expectedHmac = crypto.createHmac('sha256', bufferedKey).update(bufferedToken).digest('hex');
    
    if(hmac != expectedHmac) {
      return res.sendStatus(401);
    }

    let payload = {
      "token": token,
      "email": req.user.upn,
      "name":  req.user.displayName,
      "link":  "",
      "photo": "",
    };

    let payloadStr = JSON.stringify(payload);
    let payloadHex = Buffer.from(payloadStr, 'utf8').toString('hex');
    let hmacRes = crypto.createHmac('sha256', bufferedKey).update(payloadStr).digest('hex');
    res.redirect(`https://commento.scaleaq.com/api/oauth/sso/callback?payload=${payloadHex}&hmac=${hmacRes}`);
  });

  authApp.use(ensureAuthenticated, (req, res, next) => {
      next();
  });

  return authApp;
}