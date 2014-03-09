<?php
/**
 * Created by PhpStorm.
 * User: Daniel
 * Date: 21/02/14
 * Time: 01:19
 */

namespace Gisleburt\OpenSsl;


class Config
{

    /**
     * Not supported by PHP
     */
    const OPENSSL_KEYTYPE_DSA = OPENSSL_KEYTYPE_DSA;

    /**
     * Not supported by PHP
     */
    const OPENSSL_KEYTYPE_DH = OPENSSL_KEYTYPE_DH;

    /**
     * RSA Encryption
     */
    const OPENSSL_KEYTYPE_RSA = OPENSSL_KEYTYPE_RSA;

    /**
     * default_md Selects which digest method to use
     * @param $digest_alg string
     */
    public $digest_alg;

    /**
     * x509_extensions Selects which extensions should be used when creating an x509 certificate
     * @param $x509_extensions string
     */
    public $x509_extensions;

    /**
     * req_extensions Selects which extensions should be used when creating a CSR
     * @param $req_extensions string
     */
    public $req_extensions;

    /**
     * default_bits Specifies how many bits should be used to generate a private key
     * @param $private_key_bits integer
     */
    public $private_key_bits;

    /**
     * none Specifies the type of private key to create. This can be one of OPENSSL_KEYTYPE_DSA, OPENSSL_KEYTYPE_DH or OPENSSL_KEYTYPE_RSA. The default value is OPENSSL_KEYTYPE_RSA which is currently the only supported key type.
     * @param $private_key_type integer
     */
    public $private_key_type;

    /**
     * encrypt_key Should an exported key (with passphrase) be encrypted?
     * @param $encrypt_key boolean
     */
    public $encrypt_key;

    /**
     * none One of cipher constants.
     * @param $encrypt_key_cipher integer
     */
    public $encrypt_key_cipher;

    /**
     * Return the config as an array
     * @return array
     */
    public function toArray() {
        return (array)$this;
    }

} 