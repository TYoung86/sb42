"use strict";

const cluster = require('cluster');


if (cluster.isMaster) (()=> {
	const fs = require('fs');
	const aesGcm = require('aes-gcm-stream');
	const randomString = require('randomstring');
	const cpuCount = require('os').cpus().length;

	function readOrCreateKeyFile(keyFileName, generator) {
		const hasKeyFile = fs.existsSync(keyFileName);
		const keyValue =  hasKeyFile
			? fs.readFileSync(keyFileName, {encoding:'utf-8'})
			: generator ? generator() : randomString.generate();
		if ( !hasKeyFile )
			fs.writeFileSync(keyFileName, keyValue, {encoding:'utf-8'});
		return keyValue;
	}

	const shared = {
		peerKey : readOrCreateKeyFile('peer.key'),
		sessionKey: readOrCreateKeyFile('session.key'),
		userKey: readOrCreateKeyFile('users.key', aesGcm.createEncodedKey),
	};

	function spawnWorker() {
		cluster.fork(shared);
	}

	cluster.on('exit', w => spawnWorker());

	for (var i = 0; i < cpuCount; ++i) spawnWorker();
})();
else require('./worker.js');