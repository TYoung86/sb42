"use strict";

const fs = require('fs');
const http = require('http');
const https = require('https');
const autoCert = require('autocert');
const peer = require('peer');
const tls = require('tls');
const express = require('express');
const peerServer = peer.ExpressPeerServer;
const compression = require('compression');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const passport = require('passport');
const GooglePassportStrategy = require('passport-google-oauth20').Strategy;
const peerKey = process.env.peerKey;
const sessionKey = process.env.sessionKey;
const ejs = require('ejs');
const aesgcm = require('aes-gcm-stream');

//noinspection JSUnresolvedVariable
const pkgInfo = JSON.parse(fs.readFileSync('package.json'));
const app = express();

// app.set('view engine', 'html');

const localhostSCtx = new tls.createSecureContext({
	pfx: fs.readFileSync('localhost.pfx')
});

var autoCertChallenges = {};
const autoCertTlsOpts = autoCert.tlsOpts({
	email: pkgInfo.author.email,
	autoCertChallenges
});

const localCerts = () => {
	var certsFound = {};
	for ( const fileName of fs.readdirSync('./') ) {
		var name;
		if (fileName.endsWith('.crt') || fileName.endsWith('.cer')) {
			name = fileName.slice(0, -4);
			var keyFileName = name + '.key';
			if (fs.existsSync(keyFileName))
				certsFound[name] = new tls.createSecureContext
				({ cert: fs.readFileSync(fileName), key: fs.readFileSync(keyFileName) });
		}
		else if (fileName.endsWith('.pfx') || fileName.endsWith('.p12')) {
			name = fileName.slice(0, -4);
			certsFound[name] = new tls.createSecureContext
			({ pfx: fs.readFileSync(fileName) });
		}
	}
	return certsFound;
};

const fallbackSCtx = getFirstValue(localCerts);

const tlsOpts = {
	SNICallback: (name, cb) => {
		console.log('SNI request: %s', name);
		// will I need wildcard support?
		return name === null
			? cb(null, localhostSCtx)
			: name === 'localhost'
			? cb(null, fallbackSCtx)
			: localCerts[name]
		|| autoCertTlsOpts.SNICallback(name, cb);
	}
};

const aDayInSeconds = 86400;

app.configure(function() {
	app.engine('html', ejs.renderFile);
	app.set('views', __dirname + '/private');
	app.set('view options', {layout: false});

	app.use(compression);

	app.use(session({
		secret: sessionKey,
		resave: false,
		cookie: {
			secure: true,
			httpOnly: true,
			sameSite: true,
		},
		store: new FileStore({
			ttl: aDayInSeconds,
			reapInterval: aDayInSeconds,
			reapAsync: true,
			reapSyncFallback: true,
			encrypt: true
		}),
		rolling: true,
		saveUninitialized: false,
	}));

	app.use(passport.initialize());
	app.use(passport.session());
});


http.createServer((req, res) => {
	var proof = autoCertChallenges[req.url];
	if (proof) {
		console.log('Challenge request: %s', proof);
		res.end(proof);
	} else {
		console.log('Insecure request: %s %s', req.method, req.url);
		var destination = `https://${req.headers.host}/lost?r=${encodeURIComponent(req.url)}`;
		res.writeHead(307,{
			'Location': destination
		});
		res.end(destination);
	}
}).listen(80);

const server = https.createServer(tlsOpts, (req, res) => {
	console.log('Secure request: %s %s', req.method, req.url);
	return app(req,res);
}).listen(443);

const stupidlyHigh = -1>>>1;

app.use('/peers', peerServer(server, {
	debug: false,
	key: peerKey,
	ip_limit: stupidlyHigh,
	concurrent_limit: stupidlyHigh,
	timeout: 10000
}));

app.all('/lost', (req, res, next) => {
	res.status(403);
	res.sendFile('public/lost.html');
});

passport.use(new GooglePassportStrategy({
		clientID: process.env.GOOGLE_CLIENT_ID,
		clientSecret: process.env.GOOGLE_CLIENT_SECRET,
		callbackURL: "https://sb42.life/auth/google/callback"
	},
	function(accessToken, refreshToken, profile, done) {
		var id = profile.id;
		var data = {
			email:profile.email,
			name: profile.name,
			icon: profile._json['picture'],
			created: Date.UTC
		};
		// TODO: save
	}
));

app.get('/auth/google',
	passport.authenticate('google', {
		scope: [
			'email',
			'profile',
			'https://www.googleapis.com/auth/plus.login'
		]
	}));

app.get('/auth/google/callback',
	passport.authenticate('google', { failureRedirect: '/login' }),
	(req, res)=>{
		res.redirect('/');
	});

app.get('/logout',
	(req, res)=>{
		req.logout();
		res.redirect('/');
	});

app.use('/public', express.static('public'));

