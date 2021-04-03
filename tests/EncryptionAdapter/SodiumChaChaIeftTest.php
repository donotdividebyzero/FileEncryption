<?php


class SodiumChaChaIeftTest extends \PHPUnit\Framework\TestCase
{
    public function testThrowWhenKeyIsInvalid(): void
    {
        $this->expectException(\DoNotDivideByZero\Encryption\Exception\NotValidKeyException::class);

        $adapter = $this->createAdapterByKey('6wRADHBGghovGB0upmg0mbsN');
    }

    /**
     * @dataProvider getCryptData
     * @param string $key
     * @param string $encrypted
     * @param string $decrypted
     * @throws \DoNotDivideByZero\Encryption\Exception\CouldNotEncryptException
     */
    public function testCanEncrypt(string $key, string $encrypted, string $decrypted): void
    {
        $encryptionAdapter = $encryptionAdapter = $this->createAdapterByKey($key);

        self::assertNotEquals(
            $encrypted,
            $encryptionAdapter->encrypt($decrypted)
        );
    }

    /**
     * @dataProvider getCryptData
     *
     * @param string $key
     * @param string $encrypted
     * @param string $decrypted
     */
    public function testCanDecrypt(string $key, string $encrypted, string $decrypted): void
    {
        $encryptionAdapter = $this->createAdapterByKey($key);

        $result = $encryptionAdapter->decrypt($encrypted);

        self::assertEquals($decrypted, $result);
    }

    private function createAdapterByKey(string $key)
    {
        return new \DoNotDivideByZero\Encryption\EncryptionAdapter\SodiumChaChaIeft(
          new \DoNotDivideByZero\Encryption\EncryptionAdapter\SodiumChaChaIeft\PrivateKey($key)
        );
    }

    /**
     * @return array
     */
    public function getCryptData(): array
    {
        $result = $this->dataProvider();
        /* Restore encoded string back to binary */
        foreach ($result as &$cryptParams) {
            $cryptParams['encrypted'] = base64_decode($cryptParams['encrypted']);
        }
        unset($cryptParams);

        return $result;
    }

    private function dataProvider(): array
    {
        return [
            0 => [
                'key' => '6wRADHwwCBGgdxbcHhovGB0upmg0mbsN',
                'encrypted' => '146BhsQ3grT0VgkYuY3ii3gpClXHkFqlIcNpAD4+bAMBP+ToCHZHiJID',
                'decrypted' => 'Hello World!!!',
            ],
            1 => [
                'key' => 'uPuzBU067DXTM4PqEi14Sv5tbWjVcRZI',
                'encrypted' => '6SQaVrCnY10n8tOxYyvWuVGKddjR12ZbGylM9K+bRHqsqltRwuLs15vV',
                'decrypted' => 'Hello World!!!',
            ],
            2 => [
                'key' => 'zsmVdKkwVgylxMM8ZzQ3GTv7SxvusKnJ',
                'encrypted' => 'eQcREUJDV8EEB9WA1pBd5LbVQrs4Kyv6iWnkhOnjeitySuPQAcpIVoCM',
                'decrypted' => 'Hello World!!!',
            ],
            3 => [
                'key' => 'aggaHLvRCxRRyebpsrGAdLAIfSrufYrN',
                'encrypted' => 'PSOa8KCpTsxnTgq4IKbpneF38FIp0JeAeiXQIf30vS5X+riylx05pz9b',
                'decrypted' => 'Hello World!!!',
            ],
            4 => [
                'key' => '6tEWnKY6AcdjS2XfPe1DjTbkvu2cFFZo',
                'encrypted' => 'UglO9dEgslFpwPwejJmrK89PmBicv+I1pfdaXaEI69IrETD8LpdzOLF7',
                'decrypted' => 'Hello World!!!',
            ],
            5 => [
                'key' => '6wRADHwwCBGgdxbcHhovGB0upmg0mbsN',
                'encrypted' => '',
                'decrypted' => '',
            ],
            6 => [
                'key' => '6wRADHwwCBGgdxbcHhovGB0upmg0mbsN',
                'encrypted' => 'bWFsZm9ybWVkLWlucHV0',
                'decrypted' => '',
            ]
        ];
    }
}