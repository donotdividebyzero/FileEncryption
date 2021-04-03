<?php
declare(strict_types=1);

namespace DoNotDivideByZero\Encryption\EncryptionAdapter\SodiumChaChaIeft;

use DoNotDivideByZero\Encryption\Exception\NotValidKeyException;

class PrivateKey  extends \DoNotDivideByZero\Encryption\PrivateKey
{
    private string $key;

    /**
     * PrivateKey constructor.
     * @param string $key
     */
    public function __construct(string $key)
    {
        if (!$this->validateKey($key)) {
            throw new NotValidKeyException(
                'Encryption key must be 32 character string without any white space.'
            );
        }

        parent::__construct($key);
    }

    /**
     * @param string $key
     * @return bool
     */
    private function validateKey(string $key): bool
    {
        return strlen($key) === SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES
            && preg_match('/^\S+$/', $key);
    }
}