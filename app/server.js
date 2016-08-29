var pkgInfo = require('./package.json');
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
<<<<<<< HEAD
    res.end(JSON.stringify( { challenges, tlsOpts } ,null,"\t"));
=======
    res.end(JSON.stringify(challenges,null,"\t"));
>>>>>>> 2bb1ed7203102a01cf25088a2395fb28fa7e3585
  }
}).listen(80);
 
var tlsOpts = autocert.tlsOpts({
  email: pkgInfo.author.email,
  challenges,
});

https.createServer(tlsOpts, (req, res) => {
  res.end('is this thing on?');
}).listen(443);

peer.PeerServer({
  port: 9001, ssl: tlsOpts
});