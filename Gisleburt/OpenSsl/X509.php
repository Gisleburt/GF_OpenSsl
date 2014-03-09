<?php
/**
 * Created by PhpStorm.
 * User: Daniel
 * Date: 21/02/14
 * Time: 02:38
 */

namespace Gisleburt\OpenSsl;


class X509 extends OpenSsl {

    /**
     * Can the certificate be used for the client side of an SSL connection?
     * @var  int
     */
    const PURPOSE_SSL_CLIENT = X509_PURPOSE_SSL_CLIENT;

    /**
     * Can the certificate be used for the server side of an SSL connection?
     * @var  int
     */
	const PURPOSE_SSL_SERVER = X509_PURPOSE_SSL_SERVER;

    /**
     * Can the cert be used for Netscape SSL server?
     * @var  int
     */
	const PURPOSE_NS_SSL_SERVER = X509_PURPOSE_NS_SSL_SERVER;

    /**
     * Can the cert be used to sign S/MIME email?
     * @var  int
     */
	const PURPOSE_SMIME_SIGN = X509_PURPOSE_SMIME_SIGN;

    /**
     * Can the cert be used to encrypt S/MIME email?
     * @var  int
     */
	const PURPOSE_SMIME_ENCRYPT = X509_PURPOSE_SMIME_ENCRYPT;

    /**
     * Can the cert be used to sign a certificate revocation list (CRL)?
     * @var  int
     */
	const PURPOSE_CRL_SIGN = X509_PURPOSE_CRL_SIGN;

    /**
     * Can the cert be used for Any/All purposes?
     * @var  int
     */
	const PURPOSE_ANY = X509_PURPOSE_ANY;

    /**
     * @var resource
     */
    protected $resource;

    /**
     * Create the certificate object from an X.509 certificate string
     * Todo: Use a more appropriate Exception
     * @param $x509Certificate
     * @throws Exception
     */
    public function __construct($x509Certificate) {
        $this->resource = openssl_x509_read($x509Certificate);
        if(!$this->resource)
            throw new Exception('Invalid X.509 certificate');
    }

    public function __destruct() {
        openssl_x509_free($this->resource);
    }

    public function __toString() {
        return $this->export();
    }

    /**
     * Checks if a private key corresponds to this certificate
     * @param PrivateKey $key
     * @return bool
     */
    public function checkPrivateKey(PrivateKey $key) {
        return openssl_x509_check_private_key($this->resource, $key->getResource());
    }

    /**
     * Verifies if this certificate can be used for a particular purpose
     * @param array $purpose You
     * @param null $caInfo An array of trusted CA files/dirs
     * @param null $untrustedFile
     * @return int
     */
    public function checkPurpose($purpose = null, $caInfo = null, $untrustedFile = null) {
        return openssl_x509_checkpurpose($this->resource, $purpose, $caInfo, $untrustedFile);
    }

    /**
     * Exports the certificate to file
     * @param $outFilename
     * @param bool $noText
     * @return bool
     */
    public function exportToFile($outFilename, $noText = true) {
        return openssl_x509_export_to_file($this->resource, $outFilename, $noText);
    }

    /**
     * Exports the certificate as a string
     * @param bool $noText
     * @return bool|string
     */
    public function export($noText = true) {
        $output = '';
        if(openssl_x509_export($this->resource, $output, $noText))
            return $output;
        return false;
    }

    /**
     * Return information about the certificate as an array
     * @param bool $shortNames
     * @return array
     */
    public function info($shortNames = true) {
        return openssl_x509_parse($this->resource, $shortNames);
    }

    /**
     * Return information about the certificate as an array
     * @param bool $shortNames
     * @return array
     */
    public function parse($shortNames = true) {
        return $this->info($shortNames);
    }

    /**
     * Creates the certificate from a string
     * @param $x509Certificate
     * @return bool
     */
    public static function read($x509Certificate) {
        return new static($x509Certificate);
    }

} 