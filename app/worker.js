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
//const shrinkRay = require('shrink-ray');
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
const waitOn = promisify(require('wait-on'));
let server;


//noinspection JSUnresolvedVariable,ES6ModulesDependencies,NodeModulesDependencies
const pkgInfo = JSON.parse(fs.readFileSync('package.json'));
const app = express();



//app.engine('html', ejs.renderFile);
//app.set('views', './views');
//app.set('view options', {layout: false});
/*
 app.use(shrinkRay({
 zlib: {
 chunkSize: 64 * 1024
 }
 }));
 */
app.use(compression({
	chunkSize: 64 * 1024
}));

//app.set('view engine', 'ejs');

const localCerts = {};

function updateLocalCerts() {
	const reads = [];
	for (const fileName of fs.readdirSync('./certs/')) {
		if (fileName.endsWith('.pfx') || fileName.endsWith('.p12')) {
			const name = fileName.slice(0, -4);
			//console.log("Do we already have a cert for %s? %s", name, name in localCerts);
			//console.log("We have localCerts for %s", Object.keys(localCerts).join(', '));
			if ( name in localCerts ) {
				console.log("Already have local certificate for %s", name);
				continue;
			}
			const filePath = `./certs/${fileName}`;
			console.log("Found local certificate for %s", name);
			reads.push(waitOn({
					resources: [ filePath ],
					interval: 10,
					timeout: 60000,
					window: 100
				})
				.then(() => pfs.readFile(filePath))
				.then((data) => {
					console.log("Created secure context for %s", name);
					localCerts[name] = new tls.createSecureContext({pfx: data});
				})
				.catch(err => console.error("While retrieving local certificate %s...\n%s", name, err.stack))
			);
		}
	}
	return Promise.all(reads);
}

const localhostSCtx = localCerts['localhost'];
const fallbackSCtx = getFirstValue(localCerts);
const acmeChallengePathPrefix = '/.well-known/acme-challenge/';
const domainSuffixWhitelist = [
	'sb42.life'
];

function checkAgainstDomainSuffixWhitelist(host) {
	if ( typeof host !== 'string' ) return false;
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
					const email = pkgInfo.author.email;
					const privateKey = `${__dirname}/certs/${name}.key`;
					const accountKey = `${__dirname}/certs/${email}.key`;
					const pfxFile = `${__dirname}/certs/${name}.pfx`;
					const lockFile = `${__dirname}/certs/${name}.lock`;
					pfs.access(lockFile, fs.constants.R_OK)
						.then( () => {
							console.log("Waiting on existing Let's Encrypt SNI request: %s", name);
							return updateLocalCerts()
								.then(() => {
									if ( name in localCerts ) {
										console.log("Satisfied Let's Encrypt SNI request from local storage: %s", name);
										cb(null, localCerts[name]);
									} else
										throw new Error('Timed out waiting for certificate to appear.');
								})
								.catch(err => console.error("While updating local certificates to account for %s...\n%s", name, err.stack));
						})
						.catch( () => {
							fs.closeSync(fs.openSync(lockFile, 'a'));
							console.log("Let's Encrypt SNI request: %s", name);
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
									fs.writeFile(`./challenges/${path}`, data, err => {
										if (err) throw err;
										done();
										console.log("Saved Let's Encrypt challenge...");
									});
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
						})
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

//noinspection JSUnusedLocalSymbols
function noop() {}

function User(profile, accessToken, refreshToken, done) {
	if ( !done )
		return new Promise( (res,rej) => User( profile,undefined,undefined,
			(err,obj) => (err?rej:res)({err, obj}) ) );
	console.log('User call profile for:', profile);
	let isUpdate = typeof profile === 'object';
	const id = isUpdate ? profile.id : profile;
	isUpdate = isUpdate && Object.keys(profile).length > 0;
	console.log('User profile %s: %s', isUpdate ? 'update' : 'access',  id);
	const now = new Date();
	const updatedUser = profile ? {
		accessToken,
		refreshToken,
		email: profile.email,
		name: profile.name,
		picture: profile.picture || ( profile._json && profile._json.picture ),
		modified: now
	} : {};
	const filePath = './users/'+id;
	pfs.access(filePath, fs.constants.R_OK)
		.then(() => new Promise((resolve,reject) => {
			const cborDecoder = new cbor.Decoder();
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
		.catch(err => {
			return new Error(`User profile for ${id} does not exist.`);
		})
		.then(user => {
			console.log('Resulting user profile for:', user);
			if (isUpdate) {
				console.log('Updating user profile for %s.', id);
				pfs.writeFile(filePath,
					cbor.encode(Object.setPrototypeOf(user, null)),
					err => done(err, user));
			} else {
				console.log('Accessed user profile for %s.', id);
				var err = user instanceof Error ? user : null;
				done(err, err ? null : user);
				throw err;
			}
		})
		.catch(err => console.error("While retrieving user %s...\n%s", id, err.stack))
}

passport.serializeUser((user, done)=>{
	console.log('Serializing user profile for %s.', user.id);
	done(null, user.id)
});
passport.deserializeUser((id, done)=>{
	console.log('Deserializing user profile for %s.', id);
	User(id).then((err, user) => {
		if (err)
			console.warn('While deserializing user profile for %s...\n%s',id,err.stack);
		console.log('Done deserializing user profile for %s.\n', id, user);
		done(err,user);
	}).catch( err => {
		console.error('While deserializing user profile for %s...\n%s',id,err.stack);
		done(err, undefined);
	})
});

const robotsTxt = 'User-agent: *\nDisallow: /\n';
app.use((req,res,next) => {
	if ( res.flush ) {
		let flushing = true;
		const finishFlushing = () => flushing = false;
		res.on('finish', finishFlushing);
		res.on('close', finishFlushing);
		let interval = setInterval(() => {
			if (flushing)
				try { res.flush(); }
				catch ( err ) { clearInterval(interval); }
			else clearInterval(interval);
		}, 100);
		next();
	}
});


const aDayInSeconds = 86400;
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
		encrypt: true,
		minTimeout: 10,
		maxTimeout: 100,
		factor: 1,
		retries: 10,
	}),
	rolling: true,
	saveUninitialized: false,
}));

const stupidlyHigh = -1>>>1;
app.use((req,res,next) => {
	if ( !checkAgainstDomainSuffixWhitelist(req.headers.host) ) {
		console.log('Bad host request from %s: %s %s',
			req.connection.remoteAddress, req.method, req.url);
		res.statusCode = 410;
		res.statusMessage = 'This Is Not Me';
		res.setHeader('Content-Type', 'text/plain');
		res.send(`This is not ${req.headers.host}. This is ${domainSuffixWhitelist[0]}. You are not being hacked.\n` +
			"Please check your DNS configuration. Someone typed an A record IP wrong.\n" +
			"We got a security certificate certifying we're these guys just to safely tell you we're not.\n" +
			"Stay in school. Don't do hard drugs. Fix your stuff, guy.\n");
		//res.end();
		res.end();
	}
	else {
		console.log("Filling secure request for %s: %s %s",
			req.connection.remoteAddress, req.method, req.url);
		next();
	}
});

app.use(hsts.getSTS({"max-age":{days:90}}));
//app.use(passport.initialize());
//app.use(passport.session());

http.createServer((req, res) => {
	switch ( req.url ) {
		case '/robots.txt': {
			console.log('Robots.txt request from %s: %s',
				req.connection.remoteAddress, req.method);
			res.statusCode = 200;
			res.statusMessage = 'Hello Robot';
			res.setHeader('Content-Type', 'text/plain');
			res.setHeader('Upgrade-Insecure-Requests', 1);
			res.end(robotsTxt);
			break;
		}
		case '/favicon.ico': {
			console.log('Favicon request from %s: %s',
				req.connection.remoteAddress, req.method);
			const destination = `https://${req.headers.host}${req.url}`;
			res.writeHead(307, 'Upgrade Your Security', {
				'Upgrade-Insecure-Requests': 1,
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
					res.writeHead(410,'This Is Not Me', { 'Upgrade-Insecure-Requests': 1 });
					res.end(`This is not ${req.headers.host}. This is ${domainSuffixWhitelist[0]}. You are not being hacked.\n` +
						"Most likely, some network admin somewhere typed an A record IP wrong. If you are that admin, shame on you.\n" +
						"Please check your DNS settings, and (if debugging) confirm you did not manually specify your host header or add an entry to your hosts file.");
					break;
				}

				console.log('Lost request from %s: %s %s',
					req.connection.remoteAddress, req.method, req.url);
				const destination = `https://${req.headers.host}/lost/?r=${encodeURIComponent(req.url)}`;
				res.writeHead(307, 'You Seem To Be Lost', {
					'Upgrade-Insecure-Requests': 1,
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
				res.setHeader('Upgrade-Insecure-Requests', 1);
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

function makeGoogleAuthCallbackUrl(host) {
	return `https://${host}/auth/google/callback`;
}

const googlePassportStrategy = new GooglePassportStrategy({
	clientID: process.env.GOOGLE_CLIENT_ID,
	clientSecret: process.env.GOOGLE_CLIENT_SECRET,
	callbackURL: makeGoogleAuthCallbackUrl('sb42.life')
}, User );

passport.use(googlePassportStrategy);

app.get('/auth/google',
	passport.authenticate('google', {
		scope: [
			'email',
			'profile'
		]
	}));

app.get('/auth/google/callback',
	(req, res, next) => {
		googlePassportStrategy.callbackURL = makeGoogleAuthCallbackUrl(req.headers.host);
		next();
	},
	passport.authenticate('google', { failureRedirect: '/' }),
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

app.get('/favicon.ico',
	(req, res) => {
		console.log('Secure favicon.ico request from %s',
			req.connection.remoteAddress);
		res.setHeader('Content-Type', 'image/x-icon');
		res.sendFile(`${__dirname}/public/favicon.ico`);
	});

app.get('/whoami',
	(req, res) => {
		console.log('Whoami:', req.user);
		res.send(req.user || 'No idea.');
	});

app.use('/public', express.static('public'));


// must be last
app.use(function(req, res){
	res.status(404);


	// default to plain-text. send()
	if (req.accepts('txt')) {
		res.type('txt').send('404 Not Found\nRequest not handled.');
		return;
	}
	// respond with json
	if (req.accepts('json')) {
		res.send({error:{status:{code:404,message:'Not Found'}},reason:'Request not handled.'});
		return;
	}
	// respond with xml
	if (req.accepts('xml')) {
		res.send('<?xml version="1.0"?><error><status code="404"><message>Not Found</message></status><reason>Request not handled.</reason></error>');
		return;
	}

	req.sendStatus(404);
});

updateLocalCerts()
	.then(() => {
		console.log('Setting up the actual server...');
		server = spdy.createServer(spdyOptions, app)
	})
	.then((server) => {
		console.log('Setting up the peer server...');
		app.use('/peers', peerServer(server, {
			debug: false,
			key: peerKey,
			ip_limit: stupidlyHigh,
			concurrent_limit: stupidlyHigh,
			timeout: 10000
		}));
	})
	.then(() => {
		console.log('Waiting a bit for things to settle down...');
		return new Promise((res,rej) =>setTimeout(()=>res(),50))
	})
	.then(() => {
		console.log('Exposing the server...');
		return server.listen(443)
	});
