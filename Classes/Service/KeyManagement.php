<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server\Service;

/*
 *  (c) 2018 punkt.de GmbH - Karlsruhe, Germany - http://punkt.de
 *  All rights reserved.
 */

use Neos\Flow\Annotations as Flow;
use Neos\Utility\Files;
use PunktDe\OAuth2\Server\Domain\Model\ServerConfiguration;
use PunktDe\OAuth2\Server\Domain\Repository\ServerConfigurationRepository;
use PunktDe\OAuth2\Server\Exceptions\OAuthServerException;

/**
 * @Flow\Scope("singleton")
 */
class KeyManagement
{
    /**
     * @Flow\Inject(lazy=false)
     * @var ServerConfigurationRepository
     */
    protected $serverConfigurationRepository;

    /**
     * @return string
     * @throws OAuthServerException
     */
    public function getPublicKey(): string
    {
        $publicKey = $this->serverConfigurationRepository->findOneByConfigurationKey('publicKey');
        if (!$publicKey instanceof ServerConfiguration) {
            throw new OAuthServerException('Public key not found in OAuth server configuration.', 1563515138);
        }

        return $publicKey->getConfigurationValue();
    }

    /**
     * @return string
     * @throws OAuthServerException
     */
    public function getPrivateKey(): string
    {
        $privateKey = $this->serverConfigurationRepository->findOneByConfigurationKey('privateKey');
        if (!$privateKey instanceof ServerConfiguration) {
            throw new OAuthServerException('Private key not found in OAuth server configuration.', 1563515139);
        }

        return $privateKey->getConfigurationValue();
    }

    /**
     * @return string
     * @throws OAuthServerException
     */
    public function getEncryptionKey(): string
    {
        $encryptionKey = $this->serverConfigurationRepository->findOneByConfigurationKey('encryptionKey');
        if (!$encryptionKey instanceof ServerConfiguration) {
            throw new OAuthServerException('Encryption key not found in OAuth server configuration.', 1563515140);
        }
        return $encryptionKey->getConfigurationValue();
    }

    /**
     * @param string $key
     * @return string
     */
    public static function saveKeyToFile(string $key): string
    {
        $tmpDir = sys_get_temp_dir();
        $keyPath = $tmpDir . '/' . sha1($key) . '.key';

        if (!file_exists($keyPath) && !touch($keyPath)) {
            throw new \RuntimeException(sprintf('"%s" key file could not be created', $keyPath));
        }

        if (file_put_contents($keyPath, $key) === false) {
            throw new \RuntimeException(sprintf('Unable to write key file to temporary directory "%s"', $tmpDir));
        }

        if (chmod($keyPath, 0600) === false) {
            throw new \RuntimeException(sprintf('The key file "%s" file mode could not be changed with chmod to 600', $keyPath));
        }

        return 'file://' . $keyPath;
    }

    /**
     * Generates a key pair for the OAuth server
     *
     * @return mixed[]
     */
    public static function generateKeyPair(): array
    {
        $filePath = Files::concatenatePaths([sys_get_temp_dir(), 'oauth_server_rsa']);

        if (file_exists($filePath . '.pub')) {
            unlink($filePath . '.pub');
        }
        if (file_exists($filePath)) {
            unlink($filePath);
        }

        $command = 'openssl genrsa -out ' . $filePath . ' 4096 2>/dev/null';
        exec($command, $output, $exitCode);
        if ($exitCode !== 0) {
            $consoleOutput = trim(implode("\n", $output), "\n");
            return [false, false, $consoleOutput];
        }

        $command = 'openssl rsa -in ' . $filePath . ' -pubout -out ' . $filePath . '.pub 2>/dev/null';
        exec($command, $output, $exitCode);
        if ($exitCode !== 0) {
            $consoleOutput = trim(implode("\n", $output), "\n");
            return [false, false, $consoleOutput];
        }

        $privateKey = file_get_contents($filePath);
        $publicKey = file_get_contents($filePath . '.pub');
        unlink($filePath);
        unlink($filePath . '.pub');

        return [trim($privateKey), trim($publicKey), ''];
    }
}
