<?php
declare(strict_types=1);

namespace DoNotDivideByZero\Encryption\EncryptionAdapter;

use DoNotDivideByZero\Encryption\EncryptionAdapterInterface;
use DoNotDivideByZero\Encryption\Exception\CouldNotDecryptException;
use DoNotDivideByZero\Encryption\Exception\CouldNotEncryptException;
use DoNotDivideByZero\Encryption\KeyInterface;

class SodiumChaChaIeft implements EncryptionAdapterInterface
{
    private const ENCODING = '8bit';
    private KeyInterface $key;

    /**
     * @param KeyInterface $key
     */
    public function __construct(KeyInterface $key)
    {
        $this->key = $key;
    }

    /**
     * @param string $content
     * @return string
     * @throws CouldNotEncryptException
     */
    public function encrypt(string $content): string
    {
        try {
            $nonce = random_bytes(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES);
            $cipheredText = sodium_crypto_aead_chacha20poly1305_ietf_encrypt(
                $content,
                $nonce,
                $nonce,
                (string)$this->key
            );

            return $nonce . $cipheredText;
        } catch (\SodiumException $e) {
            throw new CouldNotEncryptException($e->getMessage());
        }
    }

    /**
     * @param string $encrypted
     * @return string
     */
    public function decrypt(string $encrypted): string
    {
        $nonce = mb_substr(
            $encrypted,
            0,
            SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES,
            self::ENCODING
        );
        $payload = mb_substr(
            $encrypted,
            SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES,
            null,
            self::ENCODING
        );

        $plainText = false;
        try {
            $plainText = sodium_crypto_aead_chacha20poly1305_ietf_decrypt(
                $payload,
                $nonce,
                $nonce,
                (string)$this->key
            );

        } catch (\SodiumException $e) {
            $plainText = false;
        }

        /**
         * For some reason $plainText can be false...
         */
        return $plainText !== false ? $plainText : '';
    }
}