"use strict";

//noinspection JSUnusedLocalSymbols
function getFirstKey(obj) {
	try {
		//noinspection LoopStatementThatDoesntLoopJS,UnnecessaryLocalVariableJS
		for (const k in obj)
			//noinspection JSUnfilteredForInLoop
			return k;
	} catch ( err ) {
		return undefined;
	}
}
function getFirstValue(obj) {
	try {
		//noinspection LoopStatementThatDoesntLoopJS,UnnecessaryLocalVariableJS
		for (const v of obj)
			//noinspection JSUnfilteredForInLoop
			return v;
	} catch ( err ) {
		return undefined;
	}
}

const fs = require('fs');
const promisify = require('promisify-node');
const pfs = promisify('fs');
const http = require('http');
const https = require('https');
const letiny = require('letiny');
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
const usersKey = process.env.usersKey;
const ejs = require('ejs');
const aesGcm = require('aes-gcm-stream');
const cbor = require('cbor');
const hsts = require('strict-transport-security');
const spdy = require('spdy');

//noinspection JSUnresolvedVariable,ES6ModulesDependencies,NodeModulesDependencies
const pkgInfo = JSON.parse(fs.readFileSync('package.json'));
const app = express();

app.set('view engine', 'ejs');

const localCerts = () => {
	var certsFound = {};
	for ( const fileName of fs.readdirSync('./certs/') ) {
		if (fileName.endsWith('.pfx') || fileName.endsWith('.p12')) {
			const name = fileName.slice(0, -4);
			console.log("Found local certificate for %s", name);
			fs.readFile(fileName, (err,data) => {
				if (err) throw err;
				console.log("Created secure context for %s", name);
				certsFound[name] = new tls.createSecureContext({ pfx: data });
			});
		}
	}
	return certsFound;
};
const localhostSCtx = localCerts['localhost'];
const fallbackSCtx = getFirstValue(localCerts);
const acmeChallengePathPrefix = '/.well-known/acme-challenge/';
const domainSuffixWhitelist = [
	'sb42.life'
];

function checkAgainstDomainSuffixWhitelist(host) {
	return domainSuffixWhitelist.some( domainSuffix =>
		host === domainSuffix || host.endsWith('.'+domainSuffix) )
}

function dynamicSniCallback(name, cb) {
// will I need wildcard support?
	switch (name) {
		case null: {
			console.log('Fallback SNI request');
			cb(null, fallbackSCtx || localhostSCtx);
			break;
		}
		case 'localhost': {
			console.log('Localhost SNI request');
			cb(null, localhostSCtx || fallbackSCtx);
			break;
		}
		default: {
			try {
				if (name in localCerts) {
					console.log('Local Cert SNI request: %s', name);
					cb(null, localCerts[name]);
				} else {
					console.log("Let's Encrypt SNI request: %s", name);
					const email = pkgInfo.author.email;
					const privateKey = `${__dirname}/certs/${name}.key`;
					const accountKey = `${__dirname}/certs/${email}.key`;
					const pfxFile = `${__dirname}/certs/${name}.pfx`;
					//noinspection JSUnusedGlobalSymbols
					const letinyOptions = {
						email: pkgInfo.author.email,
						domains: [name],
						privateKey,
						accountKey,
						pfxFile,
						aes: true, fork: false, agreeTerms: true,
						// url: 'https://acme-staging.api.letsencrypt.org',
						challenge: (domain, path, data, done) => {
							console.log("Saving Let's Encrypt challenge...");
							if (path.startsWith(acmeChallengePathPrefix))
								path = path.substr(acmeChallengePathPrefix.length);
							else
								throw new Error(`Path does not begin with expected prefix.\n${path}`);
							if (path.includes('/'))
								throw new Error(`Path includes slashes after removing prefix.\n${path}`);
							fs.writeFile(`./challenges/${path}`, data, err => done());
						}
					};
					if (!checkAgainstDomainSuffixWhitelist(name)) {
						console.log("Well that's embarrassing...");
					}
					letiny.getCert(letinyOptions, err=> {
						if (err) throw err;
						console.log("Accessing saved Let's Encrypt challenge...");
						fs.access(pfxFile, fs.constants.R_OK, err => {
							if (err) throw err;
							console.log("Reading saved Let's Encrypt challenge...");
							fs.readFile(pfxFile, (err, data) => {
								if (err) throw err;
								console.log("Answering Let's Encrypt challenge...");
								localCerts[name] = new tls.createSecureContext({pfx: data});
								cb(null, localCerts[name]);
							});
						});
					});
				}
			} catch (err) {
				console.error(err.stack);
				console.log('Fallback SNI request due to error');
				cb(null, fallbackSCtx || localhostSCtx);
			}
			break;
		}
	}
}

const spdyOptions = {
	spdy: {
		ssl: true, plain: false,
		maxChunk: 64 * 1024,
		maxStreams: require('os').cpus().length * 4
	},
	SNICallback: dynamicSniCallback
};

const aDayInSeconds = 86400;

//noinspection JSUnusedLocalSymbols
function noop() {}

function User(profile, accessToken, refreshToken, done) {
	if ( !done )
		return new Promise( (res,rej) => User( profile,
			(err,obj) => (err?rej:res)({err, obj}) ) );
	var isUpdate = typeof profile === 'object';
	var id = isUpdate ? profile.id : profile;
	isUpdate = isUpdate && Object.keys(profile).length > 0;
	console.log('User profile %s: %s', isUpdate ? 'update' : 'access',  id);
	var now = Date.UTC;
	var updatedUser = profile ? {
		accessToken,
		refreshToken,
		email: profile.email,
		name: profile.name,
		picture: profile._json['picture'],
		modified: now
	} : {};
	var filePath = './users/'+id;
	pfs.access(filePath, fs.constants.R_OK)
		.then(err => err ? Promise.resolve({})
			: new Promise((resolve,reject) => {
			var cborDecoder = new cbor.Decoder();
			cborDecoder.on('complete', obj => resolve(obj) );
			cborDecoder.on('error', obj => reject(obj) );
			try {
				fs.createReadStream(filePath)
					.pipe(aesGcm.decrypt(aesGcmConfig))
					.pipe(cborDecoder);
			} catch ( err ) {
				reject(err);
			}
		}))
		.then(readUser => Object.setPrototypeOf(
			Object.assign(
				{created:now},
				readUser,
				updatedUser),
			{id}))
		.then(user => isUpdate
			? pfs.writeFile(filePath, cbor.encode(Object.setPrototypeOf(user, null)),
			err => done(err, user))
			: done(null, user));
}

const robotsTxt = 'User-agent: *\nDisallow: /\n';

//app.engine('html', ejs.renderFile);
//app.set('views', './views');
//app.set('view options', {layout: false});

//app.use(compression);
/*
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
app.use(hsts.getSTS({"max-age":{days:90}}));
*/

http.createServer((req, res) => {
	switch ( req.url ) {
		case '/robots.txt': {
			console.log('Robots.txt request from %s: %s',
				req.connection.remoteAddress, req.method);
			res.statusCode = 200;
			res.statusMessage = 'Hello Robot';
			res.setHeader('Content-Type', 'text/plain');
			res.end(robotsTxt);
			break;
		}
		case '/favicon.ico': {
			console.log('Favicon request from %s: %s',
				req.connection.remoteAddress, req.method);
			const destination = `https://${req.headers.host}${req.url}`;
			res.writeHead(307, 'Upgrade Your Security', {
				'Location': destination
			});
			res.end(destination);
			break;
		}
		default: {
			const fullPath = req.url;
			if ( !fullPath.startsWith(acmeChallengePathPrefix) ) {
				const host = req.headers.host;
				if ( !checkAgainstDomainSuffixWhitelist(host) ) {
					console.log('Bad host request from %s: %s %s %s',
						req.connection.remoteAddress, req.method, host, req.url);
					res.writeHead(400, 'This Is Not Me');
					res.end(`This is not ${req.headers.host}. This is ${domainSuffixWhitelist[0]}.\n` +
						"Please check your DNS settings, and (if debugging) confirm you did not manually specify your host header or add an entry to your hosts file.");
					break;
				}

				console.log('Lost request from %s: %s %s',
					req.connection.remoteAddress, req.method, req.url);
				const destination = `https://${req.headers.host}/lost/?r=${encodeURIComponent(req.url)}`;
				res.writeHead(307, 'You Seem To Be Lost', {
					'Location': destination
				});
				res.end(destination);
				break;
			}
			console.log('Challenge request from %s: %s %s',
				req.connection.remoteAddress, req.method, req.url);
			const path = fullPath.substr(acmeChallengePathPrefix.length);
			const challengeFile = `./challenges/${path}`;
			fs.access(challengeFile, fs.constants.R_OK, err => {
				if (err) throw err;
				res.statusCode = 200;
				res.statusMessage = 'Challenge Accepted';
				res.setHeader('Content-Type', 'text/plain');
				fs.readFile(challengeFile, (err, data) => {
					console.log('Challenge response: %s', JSON.stringify(data.toString()));
					res.end(data);
					fs.unlink(challengeFile, err => {
						if (err) throw err;
						console.log('Challenge cleaned up.');
					});
				});
			});
			break;
		}
	}
}).listen(80);
/*(req, res) => {
 console.log('Secure request from %s: %s %s',
 req.connection.remoteAddress, req.method, req.url);
 return app(req,res);
 }*/
const server = spdy.createServer(spdyOptions, app).listen(443);

const stupidlyHigh = -1>>>1;
/*
app.use('/peers', peerServer(server, {
	debug: false,
	key: peerKey,
	ip_limit: stupidlyHigh,
	concurrent_limit: stupidlyHigh,
	timeout: 10000
}));
*/
app.all('*', (req,res,next) => {

	if ( !checkAgainstDomainSuffixWhitelist(req.headers.host) ) {
		console.log('Bad host request from %s: %s %s',
			req.connection.remoteAddress, req.method, req.url);
		res.statusCode = 400;
		res.statusMessage = 'This Is Not Me';
		res.setHeader('Content-Type', 'text/plain');
		res.send(`This is not ${req.headers.host}. This is ${domainSuffixWhitelist[0]}.\n` +
			"Please check your DNS configuration. You probably have a bad A record.\n" +
			"We got a security certificate certifying we're this host just to safely tell you we're not this host.\n" +
			"Stay in school. Don't do hard drugs. Fix your stuff, guy.\n");
		//res.end();
	}
	else next();
});

app.all('/lost/*', (req, res, next) => {
	console.log('Lost request from %s: %s %s',
		req.connection.remoteAddress, req.method, req.url);
	res.status(403);
	res.render('lost');
	next();
});

const aesGcmConfig = {
	key: usersKey
};

passport.use(new GooglePassportStrategy({
		clientID: process.env.GOOGLE_CLIENT_ID,
		clientSecret: process.env.GOOGLE_CLIENT_SECRET,
		callbackURL: "https://sb42.life/auth/google/callback"
	}, User ));

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
		console.log('Google authentication callback request from %s',
			req.connection.remoteAddress);
		res.redirect('/');
	});

app.get('/logout',
	(req, res)=>{
		console.log('Logout request from %s',
			req.connection.remoteAddress);
		req.logout();
		res.redirect('/');
	});


app.get('/robots.txt',
	(req, res) => {
		console.log('Secure robots.txt request from %s',
			req.connection.remoteAddress);
		res.setHeader('Content-Type', 'text/plain');
		res.send(new Buffer(robotsTxt));
	});

app.use('/public', express.static('public'));


