<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server;

/*
 *  (c) 2019 punkt.de GmbH - Karlsruhe, Germany - http://punkt.de
 *  All rights reserved.
 */

use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use League\OAuth2\Server\Grant\ImplicitGrant;
use League\OAuth2\Server\Grant\PasswordGrant;
use Neos\Flow\Annotations as Flow;
use League\OAuth2\Server\AuthorizationServer;
use Neos\Flow\Log\PsrSystemLoggerInterface;
use PunktDe\OAuth2\Server\Domain\Repository\AccessTokenRepository;
use PunktDe\OAuth2\Server\Domain\Repository\AuthCodeRepository;
use PunktDe\OAuth2\Server\Domain\Repository\ClientRepository;
use PunktDe\OAuth2\Server\Domain\Repository\RefreshTokenRepository;
use PunktDe\OAuth2\Server\Domain\Repository\ScopeRepository;
use PunktDe\OAuth2\Server\Domain\Repository\UserRepository;
use PunktDe\OAuth2\Server\Service\KeyManagement;
use PunktDe\OAuth2\Server\Utility\LogEnvironment;

class AuthorizationServerFactory
{

    const GRANT_TYPE_CLIENT_CREDENTIALS = 'client_credentials';
    const GRANT_TYPE_AUTH_CODE = 'authorization_code';
    const GRANT_TYPE_IMPLICIT = 'implicit';
    const GRANT_TYPE_PASSWORD = 'password';

    /**
     * @Flow\Inject(lazy=false)
     * @var KeyManagement
     */
    protected $keyManagement;

    /**
     * @Flow\Inject(lazy=false)
     * @var ClientRepository
     */
    protected $clientRepository;

    /**
     * @Flow\Inject(lazy=false)
     * @var AccessTokenRepository
     */
    protected $accessTokenRepository;

    /**
     * @Flow\Inject(lazy=false)
     * @var ScopeRepository
     */
    protected $scopeRepository;

    /**
     * @Flow\Inject(lazy=false)
     * @var AuthCodeRepository
     */
    protected $authCodeRepository;

    /**
     * @Flow\Inject(lazy=false)
     * @var RefreshTokenRepository
     */
    protected $refreshTokenRepository;

    /**
     * @Flow\Inject(lazy=false)
     * @var UserRepository
     */
    protected $userRepository;

    /**
     * @Flow\Inject(lazy=false)
     * @var PsrSystemLoggerInterface
     */
    protected $logger;

    /**
     * @Flow\InjectConfiguration(path="grantTypes")
     * @var mixed[]
     */
    protected $grantTypeConfiguration;

    /**
     * @var AuthorizationServer
     */
    protected $authorizationServer;

    /**
     * @return AuthorizationServer
     * @throws OAuthServerException
     * @throws \Exception
     */
    public function getInstance(): AuthorizationServer
    {
        $privateKeyPathAndFilename = KeyManagement::saveKeyToFile($this->keyManagement->getPrivateKey());

        if (!$this->authorizationServer instanceof AuthorizationServer) {
            $this->authorizationServer = new AuthorizationServer(
                $this->clientRepository,
                $this->accessTokenRepository,
                $this->scopeRepository,
                $privateKeyPathAndFilename,
                $this->keyManagement->getEncryptionKey()
            );

            if ($this->isGrantTypeEnabled(self::GRANT_TYPE_CLIENT_CREDENTIALS)) {
                $this->initializeClientCredentialsGrant();
            }

            if ($this->isGrantTypeEnabled(self::GRANT_TYPE_AUTH_CODE)) {
                $this->initializeAuthCodeGrant();
            }

            if ($this->isGrantTypeEnabled(self::GRANT_TYPE_IMPLICIT)) {
                $this->initializeImplicitGrant();
            }

            if ($this->isGrantTypeEnabled(self::GRANT_TYPE_PASSWORD)) {
                $this->initializePasswordGrant();
            }
        }

        return $this->authorizationServer;
    }

    /**
     * @throws \Exception
     */
    private function initializeClientCredentialsGrant(): void
    {
        $this->authorizationServer->enableGrantType(
            new ClientCredentialsGrant(),
            new \DateInterval('PT1H')
        );
    }

    /**
     * @throws \Exception
     */
    private function initializeAuthCodeGrant(): void
    {
        $authCodeGrant = new AuthCodeGrant(
            $this->authCodeRepository,
            $this->refreshTokenRepository,
            new \DateInterval('PT10M')
        );

        $authCodeGrant->setRefreshTokenTTL(new \DateInterval('P1M')); // refresh tokens will expire after 1 month

        $this->authorizationServer->enableGrantType(
            $authCodeGrant,
            new \DateInterval('PT1H')
        );

        $this->logger->debug('AuthCodeGrant initialized', LogEnvironment::fromMethodName(__METHOD__));
    }

    /**
     * @throws \Exception
     */
    private function initializeImplicitGrant(): void
    {
        $this->authorizationServer->enableGrantType(
            new ImplicitGrant(new \DateInterval('PT1H')),
            new \DateInterval('PT1H') // access tokens will expire after 1 hour
        );
    }

    /**
     * @throws \Exception
     */
    private function initializePasswordGrant(): void
    {
        $grant = new PasswordGrant(
            $this->userRepository,
            $this->refreshTokenRepository
        );

        $grant->setRefreshTokenTTL(new \DateInterval('P1M')); // refresh tokens will expire after 1 month

        $this->authorizationServer->enableGrantType(
            $grant,
            new \DateInterval('PT1H') // access tokens will expire after 1 hour
        );
    }

    /**
     * @param string $grantType
     * @return bool
     */
    private function isGrantTypeEnabled(string $grantType): bool
    {
        return isset($this->grantTypeConfiguration[$grantType]['enabled']) ? $this->grantTypeConfiguration[$grantType]['enabled'] : false;
    }
}
