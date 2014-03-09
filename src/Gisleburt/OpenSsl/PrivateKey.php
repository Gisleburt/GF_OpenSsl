<?php
/**
 * Created by PhpStorm.
 * User: Daniel
 * Date: 21/02/14
 * Time: 01:31
 */

namespace Gisleburt\OpenSsl;


class PrivateKey extends OpenSsl
{

    /**
     * The resource containing the private key
     * @var resource
     */
    protected $resource;

    /**
     * Attempts to create or import a key
     * @param null $configOrKey Config|string|null string representing the key,
     * or string containing key location in the form file:///path/to/file
     * or config or null to create new key
     * @param null $passPhrase string|null Pass phrase if importing a key and it needs unlocking
     * @throws \Exception
     */
    public function __construct($configOrKey = null, $passPhrase = null)
    {
        if (is_string($configOrKey)) {
            $this->resource = openssl_pkey_get_private($configOrKey, $passPhrase);
        } else {
            $this->resource = openssl_pkey_new($this->objectToArray($configOrKey));
        }

        if (!$this->resource) {
            throw new \Exception('Could not open/create private key');
        }
    }

    /**
     * When destroying the object, make sure to free the resource
     */
    public function __destruct()
    {
        openssl_pkey_free($this->resource);
    }

    /**
     * Generate a private new key
     * @param Config|null $config
     * @return static
     */
    public static function generate($config = null)
    {
        return new static($config);
    }

    /**
     * Load a key from a location
     * @param $fileName string /path/to/file
     * @param $passPhrase string|null
     * @return $this
     */
    public static function loadFromFile($fileName, $passPhrase = null)
    {
        return new static("file://$fileName", $passPhrase);
    }

    /**
     * Load a key from a PEM key string
     * @param $pemKey
     * @param null $passPhrase
     * @return $this
     * @throws \Exception
     */
    public static function loadFromString($pemKey, $passPhrase = null)
    {
        if (is_string($pemKey) && strlen($pemKey)) {
            return new static($pemKey, $passPhrase);
        }
        throw new \Exception('$pemKey did not appear to be a valid PEM key string');
    }

    public function __toString()
    {
        return $this->export();
    }

    /**
     * Attempt to export the private key as a string
     * @param string|null $passPhrase
     * @param Config|null $config
     * @return string
     * @throws \Exception
     */
    public function export($passPhrase = null, $config = null)
    {
        $success = openssl_pkey_export(
            $this->resource,
            $string,
            $passPhrase,
            $this->objectToArray($config)
        );
        if (!$success) {
            throw new \Exception('Private key could not be exported');
        }
        return $string;
    }

    /**
     * Write the private key to a file
     * @param $filename
     * @param null $passPhrase
     * @param null $config
     * @return $this
     * @throws \Exception
     */
    public function exportToFile($filename, $passPhrase = null, $config = null)
    {
        $success = openssl_pkey_export_to_file(
            $this->resource,
            $filename,
            $passPhrase,
            $this->objectToArray($config)
        );
        if (!$success) {
            throw new \Exception('Private key could not be exported to file');
        }
        return $this;
    }

    /**
     * Get the details of the key
     * @return \stdClass
     */
    public function getDetails()
    {
        return $this->arrayToObject(
            openssl_pkey_get_details($this->resource)
        );
    }

    /**
     * Encrypt data with the key
     * @param $data
     * @param null|int $padding
     * @return string
     * @throws \Exception
     */
    public function encrypt($data, $padding = null)
    {
        $success = openssl_private_encrypt($data, $encryptedData, $this->resource, $padding);
        if (!$success) {
            throw new \Exception('Data could not be encrypted with private key');
        }
        return $encryptedData;
    }

    /**
     * Decrypt data with the key
     * @param $encryptedData
     * @param null $padding
     * @return string
     * @throws \Exception
     */
    public function decrypt($encryptedData, $padding = null)
    {
        $success = openssl_private_decrypt($encryptedData, $data, $this->resource, $padding);
        if (!$success) {
            throw new \Exception('Data could not be decrypted');
        }
        return $data;
    }

    public function getResource() {
        return $this->resource;
    }

} 