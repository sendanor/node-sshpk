// Copyright 2015 Joyent, Inc.

import nacl from "tweetnacl";
import {
	Writable
} from "stream";
import assert from "assert-plus";
import {Buffer} from "safer-buffer";
import Signature from "./signature";

export class Verifier extends Writable {

	constructor(key, hashAlgo) {

		super({});

		if (hashAlgo.toLowerCase() !== 'sha512')
			throw (new Error('ED25519 only supports the use of ' +
				'SHA-512 hashes'));

		this.key = key;
		this.chunks = [];

	}

	_write(chunk, enc, cb) {
		this.chunks.push(chunk);
		cb();
	}

	update(chunk) {
		if (typeof (chunk) === 'string')
			chunk = Buffer.from(chunk, 'binary');
		this.chunks.push(chunk);
	}

	verify(signature, fmt) {
		var sig;
		if (Signature.isSignature(signature, [2, 0])) {
			if (signature.type !== 'ed25519')
				return (false);
			sig = signature.toBuffer('raw');

		} else if (typeof (signature) === 'string') {
			sig = Buffer.from(signature, 'base64');

		} else if (Signature.isSignature(signature, [1, 0])) {
			throw (new Error('signature was created by too old ' +
				'a version of sshpk and cannot be verified'));
		}

		assert.buffer(sig);
		return (nacl.sign.detached.verify(
			new Uint8Array(Buffer.concat(this.chunks)),
			new Uint8Array(sig),
			new Uint8Array(this.key.part.A.data)));
	}
}

export class Signer extends Writable {

	constructor(key, hashAlgo) {

		super({});

		if (hashAlgo.toLowerCase() !== 'sha512')
			throw (new Error('ED25519 only supports the use of ' +
				'SHA-512 hashes'));

		this.key = key;
		this.chunks = [];

	}

	_write(chunk, enc, cb) {
		this.chunks.push(chunk);
		cb();
	}

	update(chunk) {
		if (typeof (chunk) === 'string')
			chunk = Buffer.from(chunk, 'binary');
		this.chunks.push(chunk);
	}

	sign () {
		var sig = nacl.sign.detached(
			new Uint8Array(Buffer.concat(this.chunks)),
			new Uint8Array(Buffer.concat([
			this.key.part.k.data, this.key.part.A.data])));
		var sigBuf = Buffer.from(sig);
		var sigObj = Signature.parse(sigBuf, 'ed25519', 'raw');
		sigObj.hashAlgorithm = 'sha512';
		return (sigObj);
	}

}

