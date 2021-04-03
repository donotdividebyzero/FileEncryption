Simple layer of encryption for files or block of memory kind of encrypted swap files.

## Usage
```
$encryptionAdapter = new \DoNotDivideByZero\Encryption\EncryptionAdapter\SodiumChaChaIeft(
    new \DoNotDivideByZero\Encryption\EncryptionAdapter\SodiumChaChaIeft\PrivateKey($key)
);

$encryptionAdapter->encrypt('some text');
```