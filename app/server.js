var package = require('./package.json');
var http = require('http');
var https = require('https');
var autocert = require('autocert');
var peer = require('peer');
 
var challenges = {};
 
http.createServer((req, res) => {
  var proof = challenges[req.url];
  if (proof) {
    res.end(proof);
  } else {
    res.statusCode = 404;
    res.end('not found');
  }
}).listen(80);
 
var tlsOpts = autocert.tlsOpts({
  email: package.author.email,
  challenges,
});

https.createServer(tlsOpts, (req, res) => {
  res.end('secure af');
}).listen(443);

peer.PeerServer({
  port: 9001, ssl: tlsOpts
});