// constants 

var bignum = require("bignum");

var config = {
    public_id_regexp: /^([a-zA-Z0-9.-]{50,75})$/,
    key_size: 32,
    iv_size: 16,
    ciphertext_size: 8,
    default_hmac_size: 16,
    min_id: bignum(1),
    max_id: bignum(2).pow(64).sub(1)
};

module.exports = config;
