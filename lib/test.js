var crypto = require("crypto");
var util = require("util");
var assert = require("assert");
var bignum = require("bignum");

var id_translator = require("./main.js");
var config = require("./config");
var lib = require("./lib");
var main = require("./main");

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

    assert.equal(lib.sec_str_eq("correct", "expected"), false);
    assert.equal(lib.sec_str_eq("expected", "expected"), true);
    assert.equal(lib.sec_str_eq("abc", "expected"), false);
    assert.equal(lib.sec_str_eq("", "expected"), false);
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
        assert.equal(lib.check_range(test_id), true);
        assert.equal(lib.check_range(test_id.neg()), false);
    }
    many_test_ids(test_check_range);
    // also test a few edge cases
    assert.equal(lib.check_range(bignum(0)), false);
    assert.equal(lib.check_range(bignum(1)), true);
    assert.equal(lib.check_range(bignum(2)), true);
    assert.equal(lib.check_range(bignum(2).pow(65)), false);
    assert.equal(lib.check_range(bignum(2).pow(64)), false);
    assert.equal(lib.check_range(bignum(2).pow(64).add(1)), false);
    assert.equal(lib.check_range(bignum(2).pow(64).sub(1)), true);
    util.log("check_range passes");
    

    function test_bin_to_int8_and_back(test_id) {
        var result = lib.bin_to_int8(lib.int8_to_bin(test_id));
        assert(test_id.eq(result), 
            result.toString() + ", " + test_id.toString());
    }
    many_test_ids(test_bin_to_int8_and_back);
    util.log("int8_to_bin and back via bin_to_int8 passes");

    function test_make_iv(test_id) {
        var plaintext = lib.int8_to_bin(test_id);
        var aes_iv = lib.make_iv(iv_key, plaintext);
        assert.equal(aes_iv.length, config.iv_size);
    }
    many_test_ids(test_make_iv);

    function test_encrypt_decrypt_encode_decode(test_id) {
        var plaintext = lib.int8_to_bin(test_id);
        var aes_iv = lib.make_iv(iv_key, plaintext);
        var ciphertext = lib.encrypt(key, aes_iv, plaintext);
        var returned_plaintext = lib.decrypt(key, aes_iv, ciphertext);
        assert.equal(
            plaintext.toString('binary'), 
            returned_plaintext.toString('binary'));
        assert.equal(lib.sec_str_eq(plaintext, returned_plaintext), true);
        var encoded_and_decoded = lib.decrypt(
            key, aes_iv, lib.decode(lib.encode(ciphertext)));
        assert.equal(lib.sec_str_eq(plaintext, encoded_and_decoded), true);
    }
    many_test_ids(test_encrypt_decrypt_encode_decode);

    function test_make_hmac_sig(test_id) {
        var plaintext = lib.int8_to_bin(test_id);
        var aes_iv = lib.make_iv(iv_key, plaintext);
        var ciphertext = lib.encrypt(key, aes_iv, plaintext);
        var sig_input = Buffer.concat([aes_iv, ciphertext]);
        var sig_output = lib.make_hmac_sig(hmac_key, config.default_hmac_size,
                                           sig_input);
        assert.equal(sig_output.length, config.default_hmac_size);
    }
    many_test_ids(test_make_hmac_sig);

    function test_translator(test_id) {
        var translator = main.create_id_translator(key, iv_key, hmac_key, 
                                          config.default_hmac_size);
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

if (require.main === module) {
    test();
}
