var assert = require("assert");
var util = require("util");
var crypto = require("crypto");
var bignum = require("bignum");

var config = require("./config");

// test that a public ID looks like a public ID 
function check_public_id_regexp(public_id) {
    var result = config.public_id_regexp.exec(public_id);
    return !!result;
}

// constant time string comparison (no short circuit)
function sec_str_eq(provided, expected) {
    var num_equal = 0, expected_length = expected.length;
    for (var i=0; i < expected_length; i++) {
        num_equal += ( provided[i] === expected[i] ? 1 : 0 );
    }
    if (provided.length !== expected_length) {
        return false;
    }
    return num_equal === expected_length;
}

// translate 64 bit integer into a 8 byte binary string (requires bignum)
function int8_to_bin(int8) {
    var bin = int8.toBuffer({
        endian: "big",
        size: 8
    });
    assert.equal(bin.length, 8);
    return bin;
}

// translate 8 byte binary string to 64 bit integer (returns bignum)
function bin_to_int8(buf) {
    assert.equal(buf.length, 8);
    var num = bignum.fromBuffer(buf, {
        endian: "big",
        size: 8
    });
    return num;
}

// check that input is within the range of unsigned 8 byte integer
function check_range(internal_id) {
    if (!internal_id instanceof bignum) {
        throw new TypeError("check_range needs a BigNum");
    }
    var acceptable = (internal_id.ge(config.min_id) && internal_id.le(config.max_id));
    return acceptable;
}


// make an AES IV based on our HMAC of plaintext using IV key.
function make_iv(iv_key, bin_str) {
    // we're making the IV from the IV key, by taking a HMAC of the binary
    // representation of this internal ID.  Sha256 normally would have zero
    // known risk of collisions, but because AES IV's are only 16 bytes, we're
    // truncating the output here.  
    //
    // If we were well and truly paranoid, we could test our key by generating
    // the first several billion IVs, sorting them, looking for collisions.
    // Repeat until you find a key w/o collisions to some sufficient range.
    var hmac = crypto.createHmac('sha256', iv_key);
    hmac.update(bin_str);
    var digest = hmac.digest();
    if (typeof digest === "string") {
        digest = new Buffer(digest, 'binary');
    }
    digest = digest.slice(0, config.iv_size);
    return digest;
}

// make a signature over data using a keyed hmac. truncate to a desired size.
function make_hmac_sig(hmac_key, hmac_size, signtext) {
    var hmac = crypto.createHmac('sha256', hmac_key);
    hmac.update(signtext);
    var digest = hmac.digest();
    if (typeof digest === "string") {
        digest = new Buffer(digest, 'binary');
    }
    digest = digest.slice(0, hmac_size);
    return digest;
}

// give us ciphertext for this plaintext.
// note that this way of using the block cipher is only intended for the
// specific purpose outlined in this module.
function encrypt(key, iv, plaintext) {
    var cipher = crypto.createCipheriv('aes-256-cfb8', key, iv);
    var ciphertext = cipher.update(plaintext);
    var finaltext = cipher.final();
    assert.equal(finaltext.length, 0);
    if (typeof ciphertext === "string") {
        ciphertext = new Buffer(ciphertext, 'binary');
    }
    return ciphertext; 
}

// give us plaintext for this ciphertext.
function decrypt(key, iv, ciphertext) {
    var cipher = crypto.createDecipheriv('aes-256-cfb8', key, iv);
    var plaintext = cipher.update(ciphertext);
    var finaltext = cipher.final();
    assert.equal(finaltext.length, 0);
    if (typeof plaintext === "string") {
        plaintext = new Buffer(plaintext, 'binary');
    }
    return plaintext;
}

// make b64 string be URL safe
function b64_to_urlsafe(b64) {
    var safe = b64.replace(/\//g, ".") 
                  .replace(/\+/g, "-");
    return safe;
}

// convert URL safe b64 string back to regular b64
function b64_from_urlsafe(safe) {
    var unsafe = safe.replace(/-/g,  "+")
                     .replace(/\./g, "/");
    return unsafe;
}

// translate buffer to a URL safe base64 string
function encode(unencoded) {
    var buf = new Buffer(unencoded.toString('base64'), 'binary');
    // trim off base64's padding with excessive ==='s
    while (buf[buf.length - 1] === '='.charCodeAt(0)) {
        buf = buf.slice(0, buf.length - 1);
    }
    return b64_to_urlsafe(buf.toString('binary'));
}

// translate URL safe base64 to buffer
function decode(encoded) {
    encoded = b64_from_urlsafe(encoded);
    var buf = new Buffer(encoded, 'base64');
    return buf;
}

exports.check_public_id_regexp = check_public_id_regexp;
exports.check_public_id_regexp = check_public_id_regexp;
exports.sec_str_eq = sec_str_eq;
exports.int8_to_bin = int8_to_bin;
exports.bin_to_int8 = bin_to_int8;
exports.check_range = check_range;
exports.make_iv = make_iv;
exports.make_hmac_sig = make_hmac_sig;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
exports.b64_to_urlsafe = b64_to_urlsafe;
exports.b64_from_urlsafe = b64_from_urlsafe;
exports.encode = encode;
exports.decode = decode;
