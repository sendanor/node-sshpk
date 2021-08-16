// Copyright 2017 Joyent, Inc.

import assert from "assert-plus";
import {isCompatible} from "./utils";
import asn1 from "asn1";
import {Buffer} from "safer-buffer";

/*JSSTYLED*/
var DNS_NAME_RE = /^([*]|[a-z0-9][a-z0-9\-]{0,62})(?:\.([*]|[a-z0-9][a-z0-9\-]{0,62}))*$/i;

var oids = {};
oids.cn = '2.5.4.3';
oids.o = '2.5.4.10';
oids.ou = '2.5.4.11';
oids.l = '2.5.4.7';
oids.s = '2.5.4.8';
oids.c = '2.5.4.6';
oids.sn = '2.5.4.4';
oids.postalCode = '2.5.4.17';
oids.serialNumber = '2.5.4.5';
oids.street = '2.5.4.9';
oids.x500UniqueIdentifier = '2.5.4.45';
oids.role = '2.5.4.72';
oids.telephoneNumber = '2.5.4.20';
oids.description = '2.5.4.13';
oids.dc = '0.9.2342.19200300.100.1.25';
oids.uid = '0.9.2342.19200300.100.1.1';
oids.mail = '0.9.2342.19200300.100.1.3';
oids.title = '2.5.4.12';
oids.gn = '2.5.4.42';
oids.initials = '2.5.4.43';
oids.pseudonym = '2.5.4.65';
oids.emailAddress = '1.2.840.113549.1.9.1';

var unoids = {};
Object.keys(oids).forEach(k => {
	unoids[oids[k]] = k;
});

export default class Identity {

	constructor(opts) {
		var self = this;
		assert.object(opts, 'options');
		assert.arrayOfObject(opts.components, 'options.components');
		this.components = opts.components;
		this.componentLookup = {};
		this.components.forEach(function (c) {
			if (c.name && !c.oid)
				c.oid = oids[c.name];
			if (c.oid && !c.name)
				c.name = unoids[c.oid];
			if (self.componentLookup[c.name] === undefined)
				self.componentLookup[c.name] = [];
			self.componentLookup[c.name].push(c);
		});
		if (this.componentLookup.cn && this.componentLookup.cn.length > 0) {
			this.cn = this.componentLookup.cn[0].value;
		}
		assert.optionalString(opts.type, 'options.type');
		if (opts.type === undefined) {
			if (this.components.length === 1 &&
				this.componentLookup.cn &&
				this.componentLookup.cn.length === 1 &&
				this.componentLookup.cn[0].value.match(DNS_NAME_RE)) {
				this.type = 'host';
				this.hostname = this.componentLookup.cn[0].value;

			} else if (this.componentLookup.dc &&
				this.components.length === this.componentLookup.dc.length) {
				this.type = 'host';
				this.hostname = this.componentLookup.dc.map(
					function (c) {
					return (c.value);
				}).join('.');

			} else if (this.componentLookup.uid &&
				this.components.length ===
				this.componentLookup.uid.length) {
				this.type = 'user';
				this.uid = this.componentLookup.uid[0].value;

			} else if (this.componentLookup.cn &&
				this.componentLookup.cn.length === 1 &&
				this.componentLookup.cn[0].value.match(DNS_NAME_RE)) {
				this.type = 'host';
				this.hostname = this.componentLookup.cn[0].value;

			} else if (this.componentLookup.uid &&
				this.componentLookup.uid.length === 1) {
				this.type = 'user';
				this.uid = this.componentLookup.uid[0].value;

			} else if (this.componentLookup.mail &&
				this.componentLookup.mail.length === 1) {
				this.type = 'email';
				this.email = this.componentLookup.mail[0].value;

			} else if (this.componentLookup.cn &&
				this.componentLookup.cn.length === 1) {
				this.type = 'user';
				this.uid = this.componentLookup.cn[0].value;

			} else {
				this.type = 'unknown';
			}
		} else {
			this.type = opts.type;
			if (this.type === 'host')
				this.hostname = opts.hostname;
			else if (this.type === 'user')
				this.uid = opts.uid;
			else if (this.type === 'email')
				this.email = opts.email;
			else
				throw (new Error('Unknown type ' + this.type));
		}
		/*
         * API versions for Identity:
         * [1,0] -- initial ver
         */
		this._sshpkApiVersion = [1, 0];
	}

	toString () {
		return (this.components.map(function (c) {
			var n = c.name.toUpperCase();
			/*JSSTYLED*/
			n = n.replace(/=/g, '\\=');
			var v = c.value;
			/*JSSTYLED*/
			v = v.replace(/,/g, '\\,');
			return (n + '=' + v);
		}).join(', '));
	}

	get(name, asArray) {
		assert.string(name, 'name');
		var arr = this.componentLookup[name];
		if (arr === undefined || arr.length === 0)
			return (undefined);
		if (!asArray && arr.length > 1)
			throw (new Error('Multiple values for attribute ' + name));
		if (!asArray)
			return (arr[0].value);
		return (arr.map(function (c) {
			return (c.value);
		}));
	}

	toArray(idx) {
		return (this.components.map(function (c) {
			return ({
				name: c.name,
				value: c.value
			});
		}));
	}

	toAsn1(der, tag) {
		der.startSequence(tag);
		this.components.forEach(function (c) {
			der.startSequence(asn1.Ber.Constructor | asn1.Ber.Set);
			der.startSequence();
			der.writeOID(c.oid);
			/*
			 * If we fit in a PrintableString, use that. Otherwise use an
			 * IA5String or UTF8String.
			 *
			 * If this identity was parsed from a DN, use the ASN.1 types
			 * from the original representation (otherwise this might not
			 * be a full match for the original in some validators).
			 */
			if (c.asn1type === asn1.Ber.Utf8String ||
				c.value.match(NOT_IA5)) {
				var v = Buffer.from(c.value, 'utf8');
				der.writeBuffer(v, asn1.Ber.Utf8String);

			} else if (c.asn1type === asn1.Ber.IA5String ||
				c.value.match(NOT_PRINTABLE)) {
				der.writeString(c.value, asn1.Ber.IA5String);

			} else {
				var type = asn1.Ber.PrintableString;
				if (c.asn1type !== undefined)
					type = c.asn1type;
				der.writeString(c.value, type);
			}
			der.endSequence();
			der.endSequence();
		});
		der.endSequence();
	}

	equals(other) {
		if (!Identity.isIdentity(other, [1, 0]))
			return (false);
		if (other.components.length !== this.components.length)
			return (false);
		for (var i = 0; i < this.components.length; ++i) {
			if (this.components[i].oid !== other.components[i].oid)
				return (false);
			if (!globMatch(this.components[i].value,
				other.components[i].value)) {
				return (false);
			}
		}
		return (true);
	}

	static forHost(hostname) {
		assert.string(hostname, 'hostname');
		return (new Identity({
			type: 'host',
			hostname: hostname,
			components: [ { name: 'cn', value: hostname } ]
		}));
	}

	static forUser(uid) {
		assert.string(uid, 'uid');
		return (new Identity({
			type: 'user',
			uid: uid,
			components: [ { name: 'uid', value: uid } ]
		}));
	}

	static forEmail(email) {
		assert.string(email, 'email');
		return (new Identity({
			type: 'email',
			email: email,
			components: [ { name: 'mail', value: email } ]
		}));
	}

	static parseDN(dn) {
		assert.string(dn, 'dn');
		var parts = [''];
		var idx = 0;
		var rem = dn;
		while (rem.length > 0) {
			var m;
			/*JSSTYLED*/
			if ((m = /^,/.exec(rem)) !== null) {
				parts[++idx] = '';
				rem = rem.slice(m[0].length);
			/*JSSTYLED*/
			} else if ((m = /^\\,/.exec(rem)) !== null) {
				parts[idx] += ',';
				rem = rem.slice(m[0].length);
			/*JSSTYLED*/
			} else if ((m = /^\\./.exec(rem)) !== null) {
				parts[idx] += m[0];
				rem = rem.slice(m[0].length);
			/*JSSTYLED*/
			} else if ((m = /^[^\\,]+/.exec(rem)) !== null) {
				parts[idx] += m[0];
				rem = rem.slice(m[0].length);
			} else {
				throw (new Error('Failed to parse DN'));
			}
		}
		var cmps = parts.map(function (c) {
			c = c.trim();
			var eqPos = c.indexOf('=');
			while (eqPos > 0 && c.charAt(eqPos - 1) === '\\')
				eqPos = c.indexOf('=', eqPos + 1);
			if (eqPos === -1) {
				throw (new Error('Failed to parse DN'));
			}
			/*JSSTYLED*/
			var name = c.slice(0, eqPos).toLowerCase().replace(/\\=/g, '=');
			var value = c.slice(eqPos + 1);
			return ({ name: name, value: value });
		});
		return (new Identity({ components: cmps }));
	}

	static fromArray(components) {
		assert.arrayOfObject(components, 'components');
		components.forEach(function (cmp) {
			assert.object(cmp, 'component');
			assert.string(cmp.name, 'component.name');
			if (!Buffer.isBuffer(cmp.value) &&
				!(typeof (cmp.value) === 'string')) {
				throw (new Error('Invalid component value'));
			}
		});
		return (new Identity({ components: components }));
	}

	static parseAsn1(der, top) {
		var components = [];
		der.readSequence(top);
		var end = der.offset + der.length;
		while (der.offset < end) {
			der.readSequence(asn1.Ber.Constructor | asn1.Ber.Set);
			var after = der.offset + der.length;
			der.readSequence();
			var oid = der.readOID();
			var type = der.peek();
			var value;
			switch (type) {
			case asn1.Ber.PrintableString:
			case asn1.Ber.IA5String:
			case asn1.Ber.OctetString:
			case asn1.Ber.T61String:
				value = der.readString(type);
				break;
			case asn1.Ber.Utf8String:
				value = der.readString(type, true);
				value = value.toString('utf8');
				break;
			case asn1.Ber.CharacterString:
			case asn1.Ber.BMPString:
				value = der.readString(type, true);
				value = value.toString('utf16le');
				break;
			default:
				throw (new Error('Unknown asn1 type ' + type));
			}
			components.push({ oid: oid, asn1type: type, value: value });
			der._offset = after;
		}
		der._offset = end;
		return (new Identity({
			components: components
		}));
	}

	static isIdentity(obj, ver) {
		return (isCompatible(obj, Identity, ver));
	}

	static _oldVersionDetect(obj) {
		return ([1, 0]);
	}
}

/*
 * These are from X.680 -- PrintableString allowed chars are in section 37.4
 * table 8. Spec for IA5Strings is "1,6 + SPACE + DEL" where 1 refers to
 * ISO IR #001 (standard ASCII control characters) and 6 refers to ISO IR #006
 * (the basic ASCII character set).
 */
/* JSSTYLED */
var NOT_PRINTABLE = /[^a-zA-Z0-9 '(),+.\/:=?-]/;
/* JSSTYLED */
var NOT_IA5 = /[^\x00-\x7f]/;

function globMatch(a, b) {
	if (a === '**' || b === '**')
		return (true);
	var aParts = a.split('.');
	var bParts = b.split('.');
	if (aParts.length !== bParts.length)
		return (false);
	for (var i = 0; i < aParts.length; ++i) {
		if (aParts[i] === '*' || bParts[i] === '*')
			continue;
		if (aParts[i] !== bParts[i])
			return (false);
	}
	return (true);
}

