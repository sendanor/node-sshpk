// Copyright 2017 Joyent, Inc.

import assert from "assert-plus";
import {Buffer} from "safer-buffer";
import algs from "./algs";
import crypto from "crypto";
import Signature from "./signature";
import errs from "./errors";
import utils from "./utils";
import {
	generateECDSA,
	generateED25519
} from "./dhe";
import edCompat from "./ed-compat";
import nacl from "tweetnacl";
import Key from "./key";
import formatsAuto from "./formats/auto";
import formatsPem from "./formats/pem";
import formatsPkcs1 from "./formats/pkcs1";
import formatsPkcs8 from "./formats/pkcs8";
import formatsRfc4253 from "./formats/rfc4253";
import formatsSshPrivate from "./formats/ssh-private";
import formatsDnsSec from "./formats/dnssec";

var KeyParseError = errs.KeyParseError;

var formats = {};
formats['auto'] = formatsAuto;
formats['pem'] = formatsPem;
formats['pkcs1'] = formatsPkcs1;
formats['pkcs8'] = formatsPkcs8;
formats['rfc4253'] = formatsRfc4253;
formats['ssh-private'] = formatsSshPrivate;
formats['openssh'] = formats['ssh-private'];
formats['ssh'] = formats['ssh-private'];
formats['dnssec'] = formatsDnsSec;

export default class PrivateKey extends Key {

	constructor(opts) {

		super();

		this._pubCache = undefined;

		/*
         * API versions for PrivateKey:
         * [1,0] -- initial ver
         * [1,1] -- added auto, pkcs[18], openssh/ssh-private formats
         * [1,2] -- added defaultHashAlgorithm
         * [1,3] -- added derive, ed, createDH
         * [1,4] -- first tagged version
         * [1,5] -- changed ed25519 part names and format
         * [1,6] -- type arguments for hash() and fingerprint()
         */
		this._sshpkApiVersion = [1, 6];

	}

	toBuffer(format, options) {
		if (format === undefined)
			format = 'pkcs1';
		assert.string(format, 'format');
		assert.object(formats[format], 'formats[format]');
		assert.optionalObject(options, 'options');

		return (formats[format].write(this, options));
	}

	hash(algo, type) {
		return (this.toPublic().hash(algo, type));
	}

	fingerprint(algo, type) {
		return (this.toPublic().fingerprint(algo, type));
	}

	toPublic () {
		if (this._pubCache)
			return (this._pubCache);

		var algInfo = algs.info[this.type];
		var pubParts = [];
		for (var i = 0; i < algInfo.parts.length; ++i) {
			var p = algInfo.parts[i];
			pubParts.push(this.part[p]);
		}

		this._pubCache = new Key({
			type: this.type,
			source: this,
			parts: pubParts
		});
		if (this.comment)
			this._pubCache.comment = this.comment;
		return (this._pubCache);
	}

	derive(newType) {
		assert.string(newType, 'type');
		var priv, pub, pair;

		if (this.type === 'ed25519' && newType === 'curve25519') {
			priv = this.part.k.data;
			if (priv[0] === 0x00)
				priv = priv.slice(1);

			pair = nacl.box.keyPair.fromSecretKey(new Uint8Array(priv));
			pub = Buffer.from(pair.publicKey);

			return (new PrivateKey({
				type: 'curve25519',
				parts: [
					{ name: 'A', data: utils.mpNormalize(pub) },
					{ name: 'k', data: utils.mpNormalize(priv) }
				]
			}));
		} else if (this.type === 'curve25519' && newType === 'ed25519') {
			priv = this.part.k.data;
			if (priv[0] === 0x00)
				priv = priv.slice(1);

			pair = nacl.sign.keyPair.fromSeed(new Uint8Array(priv));
			pub = Buffer.from(pair.publicKey);

			return (new PrivateKey({
				type: 'ed25519',
				parts: [
					{ name: 'A', data: utils.mpNormalize(pub) },
					{ name: 'k', data: utils.mpNormalize(priv) }
				]
			}));
		}
		throw (new Error('Key derivation not supported from ' + this.type +
			' to ' + newType));
	}

	createVerify(hashAlgo) {
		return (this.toPublic().createVerify(hashAlgo));
	}

	createSign(hashAlgo) {
		if (hashAlgo === undefined)
			hashAlgo = this.defaultHashAlgorithm();
		assert.string(hashAlgo, 'hash algorithm');

		/* ED25519 is not supported by OpenSSL, use a javascript impl. */
		if (this.type === 'ed25519' && edCompat !== undefined)
			return (new edCompat.Signer(this, hashAlgo));
		if (this.type === 'curve25519')
			throw (new Error('Curve25519 keys are not suitable for ' +
				'signing or verification'));

		var v, nm, err;
		try {
			nm = hashAlgo.toUpperCase();
			v = crypto.createSign(nm);
		} catch (e) {
			err = e;
		}
		if (v === undefined || (err instanceof Error &&
			err.message.match(/Unknown message digest/))) {
			nm = 'RSA-';
			nm += hashAlgo.toUpperCase();
			v = crypto.createSign(nm);
		}
		assert.ok(v, 'failed to create verifier');
		var oldSign = v.sign.bind(v);
		var key = this.toBuffer('pkcs1');
		var type = this.type;
		var curve = this.curve;
		v.sign = function () {
			var sig = oldSign(key);
			if (typeof (sig) === 'string')
				sig = Buffer.from(sig, 'binary');
			sig = Signature.parse(sig, type, 'asn1');
			sig.hashAlgorithm = hashAlgo;
			sig.curve = curve;
			return (sig);
		};
		return (v);
	}

	static parse(data, format, options) {
		if (typeof (data) !== 'string')
			assert.buffer(data, 'data');
		if (format === undefined)
			format = 'auto';
		assert.string(format, 'format');
		if (typeof (options) === 'string')
			options = { filename: options };
		assert.optionalObject(options, 'options');
		if (options === undefined)
			options = {};
		assert.optionalString(options.filename, 'options.filename');
		if (options.filename === undefined)
			options.filename = '(unnamed)';

		assert.object(formats[format], 'formats[format]');

		try {
			var k = formats[format].read(data, options);
			assert.ok(k instanceof PrivateKey, 'key is not a private key');
			if (!k.comment)
				k.comment = options.filename;
			return (k);
		} catch (e) {
			if (e.name === 'KeyEncryptedError')
				throw (e);
			throw (new KeyParseError(options.filename, format, e));
		}
	}

	static isPrivateKey(obj, ver) {
		return (utils.isCompatible(obj, PrivateKey, ver));
	}

	static generate(type, options) {
		if (options === undefined)
			options = {};
		assert.object(options, 'options');

		switch (type) {
		case 'ecdsa':
			if (options.curve === undefined)
				options.curve = 'nistp256';
			assert.string(options.curve, 'options.curve');
			return (generateECDSA(options.curve));
		case 'ed25519':
			return (generateED25519());
		default:
			throw (new Error('Key generation not supported with key ' +
				'type "' + type + '"'));
		}
	}

	static _oldVersionDetect(obj) {
		assert.func(obj.toPublic);
		assert.func(obj.createSign);
		if (obj.derive)
			return ([1, 3]);
		if (obj.defaultHashAlgorithm)
			return ([1, 2]);
		if (obj.formats['auto'])
			return ([1, 1]);
		return ([1, 0]);
	}

}

PrivateKey.formats = formats;

