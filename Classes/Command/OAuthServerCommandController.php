<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server\Command;

/*
 *  (c) 2018 punkt.de GmbH - Karlsruhe, Germany - http://punkt.de
 *  All rights reserved.
 */

use Neos\Flow\Mvc\Exception\StopActionException;
use Neos\Flow\Persistence\Exception\IllegalObjectTypeException;
use PunktDe\OAuth2\Server\Domain\Model\Client;
use PunktDe\OAuth2\Server\Domain\Model\HashedSecret;
use PunktDe\OAuth2\Server\Domain\Model\ServerConfiguration;
use PunktDe\OAuth2\Server\Domain\Repository\AccessTokenRepository;
use PunktDe\OAuth2\Server\Domain\Repository\ClientRepository;
use PunktDe\OAuth2\Server\Domain\Repository\ScopeRepository;
use PunktDe\OAuth2\Server\Domain\Repository\ServerConfigurationRepository;
use Neos\Flow\Annotations\Inject;
use Neos\Flow\Cli\CommandController;
use PunktDe\OAuth2\Server\Service\KeyManagement;

final class OAuthServerCommandController extends CommandController
{
    /**
     * @Inject()
     * @var ClientRepository
     */
    protected $clientRepository;

    /**
     * @Inject()
     * @var AccessTokenRepository
     */
    protected $accessTokenRepository;

    /**
     * @Inject()
     * @var ScopeRepository
     */
    protected $scopeRepository;

    /**
     * @Inject()
     * @var ServerConfigurationRepository
     */
    protected $serverConfigurationRepository;

    /**
     * Generate server keys
     *
     * This command generates the OAuth server private / public key pair and an encryption key and stores them in the
     * database.
     *
     * @throws \Exception
     */
    public function generateServerKeysCommand(): void
    {
        list($privateKey, $publicKey, $consoleOutput) = KeyManagement::generateKeyPair();
        $this->output($consoleOutput);

        $keys = [
            'encryptionKey' => base64_encode(random_bytes(32)),
            'privateKey' => $privateKey,
            'publicKey' => $publicKey
        ];

        foreach ($keys as $keyName => $keyValue) {
            $serverConfiguration = $this->serverConfigurationRepository->findOneByConfigurationKey($keyName);
            if ($serverConfiguration === null) {
                $this->serverConfigurationRepository->add(new ServerConfiguration($keyName, $keyValue));
                $this->outputLine(sprintf('<success>Generated a new %s and stored it in the database.</success>', $keyName));
            } else {
                $serverConfiguration->setConfigurationValue($keyName);
                $this->serverConfigurationRepository->update($serverConfiguration);
                $this->outputLine(sprintf('<success>Updated %s and stored it in the database.</success>', $keyName));
            }
        }
    }

    /**
     * Creates client credentials
     *
     * @param string $identifier The client identifier
     * @param string $name Name of the machine / system / person owning the new client credentials
     * @param string $grantType Grant type, one of "client_credentials", "authorization_code"
     * @param string $secret The clients secret. If it is not set, it gets created.
     * @param string $redirectUri A single URI, or several URIs comma separated
     *
     * @throws IllegalObjectTypeException
     * @throws StopActionException
     * @throws \Exception
     */
    public function createClientCredentialsCommand(string $identifier, string $name, string $grantType = 'client_credentials', string $secret = '', string $redirectUri = ''): void
    {
        if ($this->clientRepository->findOneByIdentifier($identifier) !== null) {
            $this->outputLine('<error>A client with this identifier already exists.</error>');
            $this->quit(1);
        }

        if ($secret === null) {
            $secret = base64_encode(random_bytes(30));
        }

        $hashedSecret = HashedSecret::fromClearTextSecret($secret);

        $client = new Client($identifier, $name, $grantType, $hashedSecret, $redirectUri);
        $this->clientRepository->add($client);

        $this->outputLine('Client credentials created. Secret: <b>%s</b>', [$secret]);
    }

    /**
     * List clients
     *
     * Lists existing clients
     */
    public function listClientsCommand(): void
    {
        $rows = [];

        /** @var Client $client */
        foreach ($this->clientRepository->findAll() as $client) {
            /** @var Client $client */
            $rows[] = [
                $client->getIdentifier(),
                $client->getName(),
                $client->getGrantType(),
                implode(',', $client->getRedirectUri())
            ];
        }

        $this->output->outputTable(
            $rows,
            ['Identifier', 'Name', 'Grant Type', 'Redirect URIs']
        );
    }

    /**
     * Remove client
     *
     * Removes an existing client
     *
     * @param string $identifier The client identifier
     * @throws IllegalObjectTypeException
     * @throws StopActionException
     */
    public function removeClientCommand(string $identifier): void
    {
        $client = $this->clientRepository->findOneByIdentifier($identifier);
        if ($client === null) {
            $this->outputLine('<error>Client not found.</error>');
            $this->quit(1);
        }

        $this->clientRepository->remove($client);

        $this->outputLine('Client %s removed.', [$identifier]);
    }
}
