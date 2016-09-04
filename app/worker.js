"use strict";

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
const usersKey = process.env.usersKey;
const ejs = require('ejs');
const aesGcm = require('aes-gcm-stream');
const cbor = require('cbor');

//noinspection JSUnresolvedVariable,ES6ModulesDependencies,NodeModulesDependencies
const pkgInfo = JSON.parse(fs.readFileSync('package.json'));
const app = express();

// app.set('view engine', 'html');

const localhostSCtx = new tls.createSecureContext({
	pfx: fs.readFileSync('localhost.pfx')
});

var autoCertChallenges = {};
const autoCertTlsOpts = autoCert.tlsOpts({
	email: pkgInfo.author.email,
	challenges: autoCertChallenges
});

const localCerts = () => {
	var certsFound = {};
	for ( const fileName of fs.readdirSync('./') ) {
		var name;
		if (fileName.endsWith('.crt') || fileName.endsWith('.cer')) {
			name = fileName.slice(0, -4);
			var keyFileName = name + '.key';
			if (fs.accessSync(keyFileName, fs.constants.R_OK))
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
			? cb(null, fallbackSCtx || localhostSCtx)
			: name === 'localhost'
			? cb(null, localhostSCtx)
			: localCerts[name]
		|| autoCertTlsOpts.SNICallback(name, cb);
	}
};

const aDayInSeconds = 86400;


function User(profile, accessToken, refreshToken, done) {
	if ( !done )
		return new Promise( (res,rej) => User( profile,
			(err,obj) => (err?rej:res)({err, obj}) ) );
	var isUpdate = typeof profile === 'object';
	var id = isUpdate ? profile.id : profile;
	isUpdate = isUpdate && Object.keys(profile).length > 0;
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
	res.sendFile('./private/lost.html');
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
		res.redirect('/');
	});

app.get('/logout',
	(req, res)=>{
		req.logout();
		res.redirect('/');
	});

app.use('/public', express.static('public'));

