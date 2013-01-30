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
var fs = require("fs");

var config = require("./config");
var lib = require("./lib");
var test = require("./test");

// create and return return a new ID translator object with just 'public_id'
// and 'internal_id' methods.  it does not expose the keys to inspection.
function create_id_translator(key, iv_key, hmac_key, hmac_size) {

    if (typeof hmac_size === 'undefined' ) {
        hmac_size = config.default_hmac_size;
    }

    var translator = {
        // return a string that is a public representation of an internal ID
        public_id: function (internal_id) {
            if (!lib.check_range(internal_id)) {
                throw new TypeError("internal_id out of range");
            }
            var plaintext = lib.int8_to_bin(internal_id);
            var aes_iv = lib.make_iv(iv_key, plaintext);
            var ciphertext = lib.encrypt(key, aes_iv, plaintext);
            var sig_input = Buffer.concat([aes_iv, ciphertext]);
            var sig_output = lib.make_hmac_sig(hmac_key, hmac_size, 
                                               sig_input);
            var encoded = lib.encode(Buffer.concat([sig_input, 
                                                    sig_output]));
            return encoded;
        },
        // translate a public_id string into a bignum internal_id
        internal_id: function (public_id) {
            if (!lib.check_public_id_regexp(public_id)) {
                throw new TypeError("Funny looking ID");
            }
            var unencoded = lib.decode(public_id);
            var aes_iv = unencoded.slice(0, config.iv_size);
            var ciphertext = unencoded.slice(
                config.iv_size, config.iv_size + config.ciphertext_size);
            var provided_sig = unencoded.slice(
                config.iv_size + config.ciphertext_size);
            var plaintext = lib.decrypt(key, aes_iv, ciphertext);
            var sig_input = unencoded.slice(
                0, config.iv_size + config.ciphertext_size);
            var sig_output = lib.make_hmac_sig(hmac_key, hmac_size, sig_input);
            var verified = lib.sec_str_eq(provided_sig, sig_output);
            if (!verified) {
                throw new TypeError("Bad ID");
            }

            var internal_id = lib.bin_to_int8(plaintext);
            if (!lib.check_range(internal_id)) {
                throw new TypeError("internal_id out of range");
            }
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

    rnd_data = new Buffer(config.key_size * 3);
    rnd_data.fill(0);
    bytes_read = fs.readSync(descriptor, rnd_data, 0, rnd_data.length);
    assert(bytes_read == rnd_data.length);

    fs.closeSync(descriptor);

    key = rnd_data.slice(0, 32);
    iv_key = rnd_data.slice(32, 64);
    hmac_key = rnd_data.slice(64);

    return create_id_translator(key, iv_key, hmac_key, hmac_size);
}

exports.create_id_translator = create_id_translator;
exports.load_id_translator = load_id_translator;
exports.public_id_regexp = config.public_id_regexp;
exports.test = test.test;
