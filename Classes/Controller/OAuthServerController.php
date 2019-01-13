<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server\Controller;

/*
 *  (c) 2018 punkt.de GmbH - Karlsruhe, Germany - http://punkt.de
 *  All rights reserved.
 */

use League\OAuth2\Server\Grant\PasswordGrant;
use Neos\Flow\Annotations as Flow;
use League\OAuth2\Server\Grant\ImplicitGrant;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use PunktDe\OAuth2\Server\Domain\Model\UserEntity;
use PunktDe\OAuth2\Server\Domain\Repository\AccessTokenRepository;
use PunktDe\OAuth2\Server\Domain\Repository\AuthCodeRepository;
use PunktDe\OAuth2\Server\Domain\Repository\ClientRepository;
use PunktDe\OAuth2\Server\Domain\Repository\RefreshTokenRepository;
use PunktDe\OAuth2\Server\Domain\Repository\ScopeRepository;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use Neos\Flow\Mvc\Controller\ActionController;
use PunktDe\OAuth2\Server\Domain\Repository\UserRepository;
use PunktDe\OAuth2\Server\Service\KeyManagement;
use PunktDe\OAuth2\Server\Service\PsrRequestResponseService;
use PunktDe\OAuth2\Server\Utility\LogEnvironment;

final class OAuthServerController extends ActionController
{
    const GRANT_TYPE_CLIENT_CREDENTIALS = 'clientCredentials';
    const GRANT_TYPE_AUTH_CODE = 'authCode';
    const GRANT_TYPE_IMPLICIT = 'implicit';
    const GRANT_TYPE_PASSWORD = 'password';

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
     * @var KeyManagement
     */
    protected $keyManagement;

    /**
     * @var AuthorizationServer
     */
    protected $authorizationServer;

    /**
     * @var string[]
     */
    protected $supportedMediaTypes = ['application/json'];

    /**
     * @Flow\InjectConfiguration(path="grantTypes")
     * @var mixed[]
     */
    protected $grantTypeConfiguration;

    /**
     * @return void
     * @throws \Exception
     */
    public function initializeObject(): void
    {
        if($this->isGrantTypeEnabled(self::GRANT_TYPE_CLIENT_CREDENTIALS)) {
            $this->initializeClientCredentialsGrant();
        }

        if($this->isGrantTypeEnabled(self::GRANT_TYPE_AUTH_CODE)) {
            $this->initializeAuthCodeGrant();
        }

        if($this->isGrantTypeEnabled(self::GRANT_TYPE_IMPLICIT)) {
            $this->initializeImplicitGrant();
        }

        if($this->isGrantTypeEnabled(self::GRANT_TYPE_PASSWORD)) {
            $this->initializePasswordGrant();
        }
    }

    /**
     * uriPattern: 'oauth/authorize'
     *
     * @return string
     */
    public function authorizeAction(): string
    {
        $response = new Response();

        $this->logger->info('Requested authorization', LogEnvironment::fromMethodName(__METHOD__));
        $this->debugRequest();

        try {
            $authRequest = $this->authorizationServer->validateAuthorizationRequest($this->request->getHttpRequest());
            $authRequest->setUser(new UserEntity());
            $authRequest->setAuthorizationApproved(true);
            $response = $this->authorizationServer->completeAuthorizationRequest($authRequest, $response);

        } catch (OAuthServerException $exception) {
            // All instances of OAuthServerException can be formatted into a HTTP response
            $this->logger->error(sprintf('OAuthServerException: %s', $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
            $response = $exception->generateHttpResponse($response);

        } catch (\Exception $exception) {
            $this->logger->error(sprintf('Unknown exception: %s', $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
            PsrRequestResponseService::psr7ErrorResponseFromMessage($response, $exception->getMessage());
        }

        return PsrRequestResponseService::transferPsr7ResponseToFlowResponse($response, $this->response);
    }

    /**
     * uriPattern: 'oauth/token'
     *
     * @return string
     */
    public function accessTokenAction(): string
    {
        $response = new Response();

        $this->logger->info('OAuth access token requested', LogEnvironment::fromMethodName(__METHOD__));
        $this->debugRequest();

        try {
            $authRequest = $this->authorizationServer->validateAuthorizationRequest($this->request->getHttpRequest());
            $authRequest->setUser(new UserEntity());

            // At this point we could redirect the user to an authorization page.

            $authRequest->setAuthorizationApproved(true);
            $response = $this->authorizationServer->completeAuthorizationRequest($authRequest, $response);

        } catch (OAuthServerException $exception) {
            $this->logger->error(sprintf('OAuthServerException: %s', $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
            $response = $exception->generateHttpResponse($response);
        } catch (\Exception $exception) {
            $this->logger->error(sprintf('%s', $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
            PsrRequestResponseService::psr7ErrorResponseFromMessage($response, $exception->getMessage());
        }

        return PsrRequestResponseService::transferPsr7ResponseToFlowResponse($response, $this->response);
    }

    /**
     * @throws \PunktDe\OAuth2\Server\OAuthServerException
     * @throws \Exception
     */
    private function initializeClientCredentialsGrant(): void
    {
        $privateKeyPathAndFilename = KeyManagement::saveKeyToFile($this->keyManagement->getPrivateKey());
        $this->authorizationServer = new AuthorizationServer(
            $this->clientRepository,
            $this->accessTokenRepository,
            $this->scopeRepository,
            $privateKeyPathAndFilename,
            $this->keyManagement->getEncryptionKey()
        );

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

    /**
     * Debug the current request to the log
     */
    private function debugRequest(): void
    {
        $requestArguments = $this->request->getHttpRequest()->getArguments();
        if (isset($requestArguments['client_secret'])) {
            $requestArguments['client_secret'] = str_repeat('*', strlen($requestArguments['client_secret']));
        }

        $this->logger->debug('Request arguments', $requestArguments + LogEnvironment::fromMethodName(__METHOD__));
    }
}
