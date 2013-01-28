// port of ID translators from Nimbus.io. Comments repeated here:
// 
// We use a variety of ID numbers for a variety of purposes -- most notably
// version IDs.  It is convenient to provide those same identifiers to users to
// allow them to specify particular objects to perform operations on.  
// 
// However, exposing internal IDs directly also leaks some information.  For
// example, if the ID numbers were simply sequentially generated, it becomes
// trivial for end users to determine the rate at which objects are being added
// to the system.  Comparisons can be made among IDs to determine operation
// ordering.  It also facilitates a variety of forms of abuse that involve
// specifying made up IDs.
// 
// The scheme here provides some rudimentary protection against the above.  
// 
// Internal IDs maybe translated to an encrypted form and freely shared with
// the public.  The public form does not reveal the internal ID, public IDs are
// not comparable to determine operation order, and the use of HMAC offers some
// limited protection for erroneous public IDs being made up.
// 
// Note of course that that none of these protections imply that a user who
// knows a particular public ID has rights to any object.  The only (limited)
// protection implied is that a verified public ID is likely to have originated
// within our system.

var crypto = require("crypto");
var assert = require("assert");
var util = require("util");
var bignum = require("bignum");

var public_id_regexp = /^([a-zA-Z0-9.-]{50,75})$/;
var _key_size = 32;
var _iv_size = 16;
var _ciphertext_size = 8;
var _default_hmac_size = 16;
var _min_id = bignum(1);
var _max_id = bignum(2).pow(64).sub(1);

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
    // TODO require a bignum
    var acceptable = (internal_id.ge(_min_id) && internal_id.le(_max_id));
    return acceptable;
}

// test that a public ID looks like a public ID 
function check_public_id_regexp(public_id) {
    var result = public_id_regexp.exec(public_id);
    return !!result;
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
    digest = digest.slice(0, _iv_size);
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

// create and return return a new ID translator object with just 'public_id'
// and 'internal_id' methods.  it does not expose the keys to inspection.
function create_id_translator(key, iv_key, hmac_key, hmac_size) {

    if (typeof hmac_size === 'undefined' ) {
        hmac_size = _default_hmac_size;
    }

    var translator = {
        // return a string that is a public representation of an internal ID
        public_id: function (internal_id) {
            // TODO throw bad ID exception 
            assert(check_range(internal_id));
            var plaintext = int8_to_bin(internal_id);
            var aes_iv = make_iv(iv_key, plaintext);
            var ciphertext = encrypt(key, aes_iv, plaintext);
            var sig_input = Buffer.concat([aes_iv, ciphertext]);
            var sig_output = make_hmac_sig(hmac_key, hmac_size, 
                                               sig_input);
            var encoded = encode(Buffer.concat([sig_input, 
                                                sig_output]));
            return encoded;
        },
        // translate a public_id string into a bignum internal_id
        internal_id: function (public_id) {
            // TODO throw bad ID exception 
            assert(check_public_id_regexp(public_id));
            var unencoded = decode(public_id);
            var aes_iv = unencoded.slice(0, _iv_size);
            var ciphertext = unencoded.slice(_iv_size, 
                                             _iv_size + _ciphertext_size);
            var provided_sig = unencoded.slice(_iv_size + _ciphertext_size);
            var plaintext = decrypt(key, aes_iv, ciphertext);
            var sig_input = unencoded.slice(0, _iv_size + _ciphertext_size);
            var sig_output = make_hmac_sig(hmac_key, hmac_size, 
                                               sig_input);
            var verified = sec_str_eq(provided_sig, sig_output);
            // TODO throw bad ID exception
            assert.equal(verified, true);

            var internal_id = bin_to_int8(plaintext);
            // TODO throw bad ID exception 
            assert(check_range(internal_id));
            return internal_id;
        }
    };

    return translator;

}

// create and return a new ID translator using keys loaded from a file.
// file should 96 bytes of random data.
function load_id_translator(filepath, hmac_size) {
    // sync functions should be OK since we would only do this once at startup
    var descriptor, rnd_data, bytes_read, key, iv_key, hmac_key;

    descriptor = fs.openSync(filepath, "r");

    rnd_data = new Buffer(_key_size * 3);
    rnd_data.fill(0);
    bytes_read = fs.readSync(descriptor, rnd_data, 0, buffer.length);
    assert(bytes_read == buffer.length);

    fs.closeSync(descriptor);

    key = rnd_data.slice(0, 32);
    iv_key = rnd_data.slice(32, 64);
    hmac_key = rnd_data.slice(64);

    return create_id_translator(key, iv_key, hmac_key, hmac_size);
}

// called back by test function below when we have random data
function test_cb(ex, rnd_data) {
    if (ex) throw ex;
    util.log("got random data");

    var key = rnd_data.slice(0, 32);
    var iv_key = rnd_data.slice(32, 64);
    var hmac_key = rnd_data.slice(64);
    assert.equal(key.length, 32);
    assert.equal(iv_key.length, 32);
    assert.equal(hmac_key.length, 32);
    util.log("got keys");

    assert.equal(sec_str_eq("correct", "expected"), false);
    assert.equal(sec_str_eq("expected", "expected"), true);
    assert.equal(sec_str_eq("abc", "expected"), false);
    assert.equal(sec_str_eq("", "expected"), false);
    util.log("sec_str_eq passes");

    // call a test function with a variety of test IDs
    function many_test_ids(id_test_func) {
        for (var i = 1; i <= 63; i++) {
            var test_id = bignum(2).pow(i);
            id_test_func(test_id);
            for (var j = 1; j <= 100; j++) {
                id_test_func(test_id.add(j));
            }
        }
    }

    function test_check_range(test_id) {
        assert.equal(check_range(test_id), true);
        assert.equal(check_range(test_id.neg()), false);
    }
    many_test_ids(test_check_range);
    // also test a few edge cases
    assert.equal(check_range(bignum(0)), false);
    assert.equal(check_range(bignum(1)), true);
    assert.equal(check_range(bignum(2)), true);
    assert.equal(check_range(bignum(2).pow(65)), false);
    assert.equal(check_range(bignum(2).pow(64)), false);
    assert.equal(check_range(bignum(2).pow(64).add(1)), false);
    assert.equal(check_range(bignum(2).pow(64).sub(1)), true);
    util.log("check_range passes");
    

    function test_bin_to_int8_and_back(test_id) {
        var result = bin_to_int8(int8_to_bin(test_id));
        assert(test_id.eq(result), 
            result.toString() + ", " + test_id.toString());
    }
    many_test_ids(test_bin_to_int8_and_back);
    util.log("int8_to_bin and back via bin_to_int8 passes");

    function test_make_iv(test_id) {
        var plaintext = int8_to_bin(test_id);
        var aes_iv = make_iv(iv_key, plaintext);
        assert.equal(aes_iv.length, _iv_size);
    }
    many_test_ids(test_make_iv);

    function test_encrypt_decrypt_encode_decode(test_id) {
        var plaintext = int8_to_bin(test_id);
        var aes_iv = make_iv(iv_key, plaintext);
        var ciphertext = encrypt(key, aes_iv, plaintext);
        var returned_plaintext = decrypt(key, aes_iv, ciphertext);
        assert.equal(
            plaintext.toString('binary'), 
            returned_plaintext.toString('binary'));
        assert.equal(sec_str_eq(plaintext, returned_plaintext), true);
        var encoded_and_decoded = decrypt(key, 
                                          aes_iv, 
                                          decode(encode(ciphertext)));
        assert.equal(sec_str_eq(plaintext, encoded_and_decoded), true);
    }
    many_test_ids(test_encrypt_decrypt_encode_decode);

    function test_make_hmac_sig(test_id) {
        var plaintext = int8_to_bin(test_id);
        var aes_iv = make_iv(iv_key, plaintext);
        var ciphertext = encrypt(key, aes_iv, plaintext);
        var sig_input = Buffer.concat([aes_iv, ciphertext]);
        var sig_output = make_hmac_sig(hmac_key, _default_hmac_size,
                                           sig_input);
        assert.equal(sig_output.length, _default_hmac_size);
    }
    many_test_ids(test_make_hmac_sig);

    function test_translator(test_id) {
        var translator = create_id_translator(key, iv_key, hmac_key, 
                                          _default_hmac_size);
        var public_id = translator.public_id(test_id);
        // util.log(test_id.toString() + ', ' 
        //         + public_id.length + ', '
        //         + public_id.toString('utf8'));
        var returned_id = translator.internal_id(public_id);
        assert.equal(test_id.eq(returned_id), true);
    }
    many_test_ids(test_translator);
    util.log("test_translator passes");

}

function test() {
    util.log("Starting test");
    crypto.randomBytes(32 * 3, test_cb);
}

exports.test = test;
exports.create_id_translator = create_id_translator;
exports.load_id_translator = load_id_translator;
exports.public_id_regexp = public_id_regexp;

test();
