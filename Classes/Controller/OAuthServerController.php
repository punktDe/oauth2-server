<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server\Controller;

/*
 *  (c) 2018 punkt.de GmbH - Karlsruhe, Germany - http://punkt.de
 *  All rights reserved.
 */

use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Context;
use Psr\Http\Message\ResponseInterface;
use PunktDe\OAuth2\Server\AuthorizationServerFactory;
use PunktDe\OAuth2\Server\Domain\Model\UserEntity;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use Neos\Flow\Mvc\Controller\ActionController;
use PunktDe\OAuth2\Server\Service\PsrRequestResponseService;
use PunktDe\OAuth2\Server\Session\AuthorizationSession;
use PunktDe\OAuth2\Server\Utility\LogEnvironment;

final class OAuthServerController extends ActionController
{
    /**
     * @Flow\Inject
     * @var Context
     */
    protected $securityContext;

    /**
     * @Flow\Inject
     * @var AuthorizationSession
     */
    protected $authorizationSession;

    /**
     * @Flow\Inject
     * @var AuthorizationServerFactory
     */
    protected $authorizationServerFactory;

    /**
     * @var AuthorizationServer
     */
    protected $authorizationServer;

    /**
     * @var string[]
     */
    protected $supportedMediaTypes = ['application/json'];

    /**
     * @Flow\InjectConfiguration(path="authenticationPageUri")
     * @var string
     */
    protected $authenticationPageUri;

    /**
     * @return void
     * @throws \Exception
     */
    public function initializeAction(): void
    {
        $this->authorizationServer = $this->authorizationServerFactory->getInstance();
    }

    /**
     * uriPattern: 'oauth/authorize'
     *
     * @return string
     */
    public function authorizeAction(): string
    {
        $response = new Response();

        $this->logger->info('Requested authorization for client ' . $this->getRequestingClientFromCurrentRequest(), LogEnvironment::fromMethodName(__METHOD__));
        $this->debugRequest();

        try {
            $authorizationRequest = $this->authorizationServer->validateAuthorizationRequest($this->request->getHttpRequest());

            if ($this->securityContext->isInitialized() && $this->securityContext->getAccount() instanceof Account) {
                $response = $this->approveAuthenticationRequest($authorizationRequest, $response);
            } else {
                $this->authorizationSession->setAuthorizationRequest($authorizationRequest);
                $this->redirectToUri($this->authenticationPageUri);
            }

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

        $this->logger->info('OAuth access token requested for client ' . $this->getRequestingClientFromCurrentRequest(), LogEnvironment::fromMethodName(__METHOD__));
        $this->debugRequest();

        try {
            $response = $this->authorizationServer->respondToAccessTokenRequest(
                $this->request->getHttpRequest(),
                $response
            );
        } catch (OAuthServerException $exception) {
            $this->logger->error(sprintf('OAuthServerException: %s', $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
            $response = $exception->generateHttpResponse($response);
        } catch (\Exception $exception) {
            PsrRequestResponseService::psr7ErrorResponseFromMessage($response, $exception->getMessage());
        }

        return PsrRequestResponseService::transferPsr7ResponseToFlowResponse($response, $this->response);
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

        $this->logger->debug('Request arguments for ' . $this->request->getHttpRequest()->getRelativePath(), $requestArguments + LogEnvironment::fromMethodName(__METHOD__));
    }

    /**
     * @return string
     */
    private function getRequestingClientFromCurrentRequest(): string
    {
        return $this->request->getHttpRequest()->hasArgument('client_id') ? $this->request->getHttpRequest()->getArgument('client_id') : '';
    }

    /**
     * @param AuthorizationRequest $authRequest
     * @param Response $response
     * @return Response
     */
    private function approveAuthenticationRequest(AuthorizationRequest $authRequest, Response $response): ResponseInterface
    {
        $authRequest->setUser(new UserEntity());
        $authRequest->setAuthorizationApproved(true);
        $response = $this->authorizationServer->completeAuthorizationRequest($authRequest, $response);
        return $response;
    }
}
