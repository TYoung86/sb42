"use strict";
const pkgInfo = require('./package.json');
const http = require('http');
const https = require('https');
const autocert = require('autocert');
const peer = require('peer');
const fs = require('fs');
const tls = require('tls');
const express = require('express');
const peerServer = peer.ExpressPeerServer;
const threads = require('webworker-threads');
const randomstring = require('randomstring');
const compression = require('compression');

const peerKey = randomstring.generate();

const app = express();

const fallbackSCtx = new tls.createSecureContext({
	pfx: fs.readFileSync('localhost.pfx')
});

app.use(compression);

var autocertChallenges = {};
var autocertTlsOpts = autocert.tlsOpts({
	email: pkgInfo.author.email,
	autocertChallenges
});

http.createServer((req, res) => {
	var proof = autocertChallenges[req.url];
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


const tlsOpts = {
	SNICallback: (name, cb) => {
		console.log('SNI request: %s', name);
		return name === null || name === 'localhost'
			? cb(null, fallbackSCtx)
			: tlsOpts.SNICallback(name, cb);
	}
};

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
	res.status(403)

});

app.use('/public', express.static('public'));


