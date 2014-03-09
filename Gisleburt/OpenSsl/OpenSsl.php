<?php
/**
 * Created by PhpStorm.
 * User: Daniel
 * Date: 21/02/14
 * Time: 01:40
 */

namespace Gisleburt\OpenSsl;


abstract class OpenSsl {

    const PKCS1_PADDING = OPENSSL_PKCS1_PADDING;
    const SSLV23_PADDING = OPENSSL_SSLV23_PADDING;
    const PKCS1_OAEP_PADDING = OPENSSL_PKCS1_OAEP_PADDING;
    const NO_PADDING = OPENSSL_NO_PADDING;

    protected function objectToArray($object) {
        return is_object($object) ? (array)$object : array();
    }

    protected function arrayToObject($array) {
        $object = new \stdClass();
        if(is_array($array)) {
            foreach($array as $key => $value) {
                $object->$key = $value;
            }
        }
        return $object;
    }

    public function __sleep() {
        throw new \Exception('This object can not be serialised');
    }

} 