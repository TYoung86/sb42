"use strict";
var pkgInfo = require('./package.json');
var http = require('http');
var https = require('https');
var autocert = require('autocert');
var peer = require('peer');
var fs = require('fs');
var tls = require('tls');

var challenges = {};
 
http.createServer((req, res) => {
  var proof = challenges[req.url];
  if (proof) {
    console.log("Challenge request: %s", proof);
    res.end(proof);
  } else {
    console.log("Insecure request: %s", req.address);
    res.statusCode = 404;
    res.end(JSON.stringify( { challenges } ,null,"\t"));
  }
}).listen(80);


var autocertTlsOpts = autocert.tlsOpts({
  email: pkgInfo.author.email,
  challenges,
});

var fallbackSCtx = new tls.createSecureContext({
  pfx: fs.readFileSync('localhost.pfx')
});

var tlsOpts = {
  SNICallback: (name, cb) => {
    console.log("SNI request: %s", name);
    return name === null || name === 'localhost' ? cb(null,fallbackSCtx) : tlsOpts.SNICallback(name, cb);
  }
};

https.createServer(tlsOpts, (req, res) => {
  console.log("Secure request: %s", name);
  res.end('is this thing on?');
}).listen(443);

peer.PeerServer({
  port: 9001, ssl: tlsOpts
}).on('connection', id => console.log("Peer request: %s", id));