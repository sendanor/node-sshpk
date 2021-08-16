// Copyright 2015 Joyent, Inc.

import assert from "assert-plus";
import {Buffer} from "safer-buffer";

export default class SSHBuffer {

	constructor(opts) {
		assert.object(opts, 'options');
		if (opts.buffer !== undefined)
			assert.buffer(opts.buffer, 'options.buffer');

		this._size = opts.buffer ? opts.buffer.length : 1024;
		this._buffer = opts.buffer || Buffer.alloc(this._size);
		this._offset = 0;
	}

	toBuffer () {
		return (this._buffer.slice(0, this._offset));
	}

	atEnd () {
		return (this._offset >= this._buffer.length);
	}

	remainder () {
		return (this._buffer.slice(this._offset));
	}

	skip(n) {
		this._offset += n;
	}

	expand () {
		this._size *= 2;
		var buf = Buffer.alloc(this._size);
		this._buffer.copy(buf, 0);
		this._buffer = buf;
	}

	readPart () {
		return ({data: this.readBuffer()});
	}

	readBuffer () {
		var len = this._buffer.readUInt32BE(this._offset);
		this._offset += 4;
		assert.ok(this._offset + len <= this._buffer.length,
			'length out of bounds at +0x' + this._offset.toString(16) +
			' (data truncated?)');
		var buf = this._buffer.slice(this._offset, this._offset + len);
		this._offset += len;
		return (buf);
	}

	readString () {
		return (this.readBuffer().toString());
	}

	readCString () {
		var offset = this._offset;
		while (offset < this._buffer.length &&
			this._buffer[offset] !== 0x00)
			offset++;
		assert.ok(offset < this._buffer.length, 'c string does not terminate');
		var str = this._buffer.slice(this._offset, offset).toString();
		this._offset = offset + 1;
		return (str);
	}

	readInt () {
		var v = this._buffer.readUInt32BE(this._offset);
		this._offset += 4;
		return (v);
	}

	readInt64 () {
		assert.ok(this._offset + 8 < this._buffer.length,
			'buffer not long enough to read Int64');
		var v = this._buffer.slice(this._offset, this._offset + 8);
		this._offset += 8;
		return (v);
	}

	readChar () {
		var v = this._buffer[this._offset++];
		return (v);
	}

	writeBuffer(buf) {
		while (this._offset + 4 + buf.length > this._size)
			this.expand();
		this._buffer.writeUInt32BE(buf.length, this._offset);
		this._offset += 4;
		buf.copy(this._buffer, this._offset);
		this._offset += buf.length;
	}

	writeString(str) {
		this.writeBuffer(Buffer.from(str, 'utf8'));
	}

	writeCString(str) {
		while (this._offset + 1 + str.length > this._size)
			this.expand();
		this._buffer.write(str, this._offset);
		this._offset += str.length;
		this._buffer[this._offset++] = 0;
	}

	writeInt(v) {
		while (this._offset + 4 > this._size)
			this.expand();
		this._buffer.writeUInt32BE(v, this._offset);
		this._offset += 4;
	}

	writeInt64(v) {
		assert.buffer(v, 'value');
		if (v.length > 8) {
			var lead = v.slice(0, v.length - 8);
			for (var i = 0; i < lead.length; ++i) {
				assert.strictEqual(lead[i], 0,
					'must fit in 64 bits of precision');
			}
			v = v.slice(v.length - 8, v.length);
		}
		while (this._offset + 8 > this._size)
			this.expand();
		v.copy(this._buffer, this._offset);
		this._offset += 8;
	}

	writeChar(v) {
		while (this._offset + 1 > this._size)
			this.expand();
		this._buffer[this._offset++] = v;
	}

	writePart(p) {
		this.writeBuffer(p.data);
	}

	write(buf) {
		while (this._offset + buf.length > this._size)
			this.expand();
		buf.copy(this._buffer, this._offset);
		this._offset += buf.length;
	}
}

