var express = require("express");
var session = require('express-session');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var passport = require('passport');
var saml = require('passport-saml');
var fs = require('fs');

var app = express();
app.use(cookieParser());

app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())

app.use(session({
    secret: 'secret', 
    resave: false, 
    saveUninitialized: true
}));

passport.serializeUser(function(user, done) {
    console.log('-----------------------------');
    console.log('serialize user');
    console.log(user);
    console.log('-----------------------------');
    done(null, user);
});
passport.deserializeUser(function(user, done) {
    console.log('-----------------------------');
    console.log('deserialize user');
    console.log(user);
    console.log('-----------------------------');
    done(null, user);
});

var samlStrategy = new saml.Strategy({
    // config options here
    callbackUrl: 'http://localhost:4300/login/callback',
    entryPoint: 'http://localhost:8080/simplesaml/saml2/idp/SSOService.php',
    logoutUrl: 'http://localhost:8080/simplesaml/saml2/idp/SingleLogoutService.php?ReturnTo=http://localhost:4300/auth/saml/logout/callback',
    issuer: 'saml-poc',
    identifierFormat: null,
    decryptionPvk: fs.readFileSync(__dirname + '/certs/key.pem', 'utf8'),
    privateCert: fs.readFileSync(__dirname + '/certs/key.pem', 'utf8'),
    cert: fs.readFileSync(__dirname + "/certs/idp_key.pem", "utf8"),
    validateInResponseTo: false,
    disableRequestedAuthnContext: true
  }, function(profile, done) {
      console.log('I am logged in =====');
      console.log(profile);
      console.log('==========');
      console.log(done);
      return done(null, profile);
  });

passport.use('samlStrategy', samlStrategy);
app.use(passport.initialize({}));
app.use(passport.session({}));

passport.logoutSamlCallback = function(req, res){
    console.log('I am logout called...');
    req.logout();
    res.redirect('/');
}

app.get('/',
    function(req, res) {
        console.log(req.cookies);
        res.send('Test Home Page');
    }
);

app.get('/login',
    function (req, res, next) {
        console.log('-----------------------------');
        console.log('/Start login handler');
        next();
    },
    passport.authenticate('samlStrategy'),
);

app.post('/login/callback',
    function (req, res, next) {
        console.log('-----------------------------');
        console.log('/Start login callback ');
        next();
    },
    passport.authenticate('samlStrategy'),
    function (req, res) {
        console.log('-----------------------------');
        console.log('login call back dumps');
        console.log(req.user);
        console.log('-----------------------------');
        res.send('Log in Callback Success');
    }
);

app.post('/auth/saml/logout/callback', passport.logoutSamlCallback);

app.get('/logout', (req, res, next) => {
    samlStrategy.logout(req, function() {
        // LOCAL logout
        req.logout();
        // redirect to the IdP with the encrypted SAML logout request
        cookie = req.cookies;
        for (var prop in cookie) {
            if (!cookie.hasOwnProperty(prop)) {
                continue;
            }    
            res.cookie(prop, '', {expires: new Date(0)});
        }
        res.redirect('/');
    });
})

app.get('/metadata',
    function(req, res) {
        res.type('application/xml'); 
        res.status(200).send(
          samlStrategy.generateServiceProviderMetadata(
             fs.readFileSync(__dirname + '/certs/cert.pem', 'utf8'), 
             fs.readFileSync(__dirname + '/certs/cert.pem', 'utf8')
          )
        );
    }
);

var server = app.listen(4300, function () {
    console.log('Listening on port %d', server.address().port)
});