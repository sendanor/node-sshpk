// Copyright 2015 Joyent, Inc.

export class FingerprintFormatError extends Error {
	constructor(fp, format) {
		super();
		if (Error.captureStackTrace)
			Error.captureStackTrace(this, FingerprintFormatError);
		this.name = 'FingerprintFormatError';
		this.fingerprint = fp;
		this.format = format;
		this.message = 'Fingerprint format is not supported, or is invalid: ';
		if (fp !== undefined)
			this.message += ' fingerprint = ' + fp;
		if (format !== undefined)
			this.message += ' format = ' + format;
	}
}

export class InvalidAlgorithmError extends Error {
	constructor(alg) {
		super();
		if (Error.captureStackTrace)
			Error.captureStackTrace(this, InvalidAlgorithmError);
		this.name = 'InvalidAlgorithmError';
		this.algorithm = alg;
		this.message = 'Algorithm "' + alg + '" is not supported';
	}
}

export class KeyParseError extends Error {
	constructor(name, format, innerErr) {
		super();
		if (Error.captureStackTrace)
			Error.captureStackTrace(this, KeyParseError);
		this.name = 'KeyParseError';
		this.format = format;
		this.keyName = name;
		this.innerErr = innerErr;
		this.message = 'Failed to parse ' + name + ' as a valid ' + format +
			' format key: ' + innerErr.message;
	}
}

export class SignatureParseError extends Error {
	constructor(type, format, innerErr) {
		super();
		if (Error.captureStackTrace)
			Error.captureStackTrace(this, SignatureParseError);
		this.name = 'SignatureParseError';
		this.type = type;
		this.format = format;
		this.innerErr = innerErr;
		this.message = 'Failed to parse the given data as a ' + type +
			' signature in ' + format + ' format: ' + innerErr.message;
	}
}

export class CertificateParseError extends Error {
	constructor(name, format, innerErr) {
		super();
		if (Error.captureStackTrace)
			Error.captureStackTrace(this, CertificateParseError);
		this.name = 'CertificateParseError';
		this.format = format;
		this.certName = name;
		this.innerErr = innerErr;
		this.message = 'Failed to parse ' + name + ' as a valid ' + format +
			' format certificate: ' + innerErr.message;
	}
}

export class KeyEncryptedError extends Error {
	constructor(name, format) {
		super();
		if (Error.captureStackTrace)
			Error.captureStackTrace(this, KeyEncryptedError);
		this.name = 'KeyEncryptedError';
		this.format = format;
		this.keyName = name;
		this.message = 'The ' + format + ' format key ' + name + ' is ' +
			'encrypted (password-protected), and no passphrase was ' +
			'provided in `options`';
	}
}
