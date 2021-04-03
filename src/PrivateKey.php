<?php
declare(strict_types=1);

namespace DoNotDivideByZero\Encryption;


class PrivateKey implements KeyInterface
{
    private string $key;

    /**
     * PrivateKey constructor.
     * @param string $key
     */
    public function __construct(string $key)
    {
        $this->key = $key;
    }

    /**
     * @param \Stringable $pemOrCertificateFile
     * @return static
     */
    public static function fromFile(\Stringable $pemOrCertificateFile): self
    {
        if (!is_readable($pemOrCertificateFile)) {
            throw new \InvalidArgumentException(
                "File '{$pemOrCertificateFile}' is not readable"
            );
        }

        return new static(file_get_contents($pemOrCertificateFile));
    }

    public function __toString(): string
    {
        return $this->key;
    }
}