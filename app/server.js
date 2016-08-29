var pkgInfo = require('./package.json');
var http = require('http');
var https = require('https');
var autocert = require('autocert');
var peer = require('peer');
var fs = require('fs');

var challenges = {};
 
http.createServer((req, res) => {
  var proof = challenges[req.url];
  if (proof) {
    res.end(proof);
  } else {
    res.statusCode = 404;
    res.end(JSON.stringify( { challenges, tlsOpts } ,null,"\t"));
  }
}).listen(80);
 
var tlsOpts = autocert.tlsOpts({
  email: pkgInfo.author.email,
  challenges,
});

tlsOpts.pfx = fs.readFileSync('localhost.pfx');

https.createServer(tlsOpts, (req, res) => {
  res.end('is this thing on?');
}).listen(443);

peer.PeerServer({
  port: 9001, ssl: tlsOpts
});