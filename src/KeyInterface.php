<?php
declare(strict_types=1);

namespace DoNotDivideByZero\Encryption;

interface KeyInterface extends \Stringable
{
    /**
     * @param \Stringable $filePath
     * @return static
     */
    public static function fromFile(\Stringable $filePath): self;
}