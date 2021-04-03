<?php
declare(strict_types=1);

namespace DoNotDivideByZero\Encryption;

interface EncryptionAdapterInterface
{
    public function encrypt(string $content): string;

    public function decrypt(string $encrypted): string;
}