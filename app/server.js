"use strict";

const cluster = require('cluster');

function getFirstKey(obj) {
	//noinspection LoopStatementThatDoesntLoopJS
	for (const k in obj) return k;
}
function getFirstValue(obj) {
	//noinspection LoopStatementThatDoesntLoopJS
	for (const v of obj) return v;
}

if (cluster.isMaster) (()=> {
	const fs = require('fs');
	const randomString = require('randomstring');
	const cpuCount = require('os').cpus().length;

	function readOrCreateKeyFile(keyFileName) {
		const hasKeyFile = fs.existsSync(keyFileName);
		const keyValue =  hasKeyFile
			? fs.readFileSync(keyFileName, {encoding:'utf-8'})
			: randomString.generate();
		if ( !hasKeyFile )
			fs.writeFileSync(keyFileName, keyValue, {encoding:'utf-8'});
		return keyValue;
	}

	const shared = {
		peerKey : readOrCreateKeyFile('peer.key'),
		sessionKey: readOrCreateKeyFile('session.key')
	};

	function spawnWorker() {
		cluster.fork(shared);
	}

	cluster.on('exit', w => spawnWorker());

	for (var i = 0; i < cpuCount; ++i) spawnWorker();
})();
else require('worker');