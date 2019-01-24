<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server\Controller;

/*
 *  (c) 2018 punkt.de GmbH - Karlsruhe, Germany - http://punkt.de
 *  All rights reserved.
 */

use Neos\Flow\Annotations as Flow;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Psr\Http\Message\ResponseInterface;
use PunktDe\OAuth2\Server\Authorization\AuthorizationApprovalService;
use PunktDe\OAuth2\Server\AuthorizationServerFactory;
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
     * @var AuthorizationSession
     */
    protected $authorizationSession;

    /**
     * @Flow\Inject
     * @var AuthorizationApprovalService
     */
    protected $authorizationApprovalService;

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
    public function authorizationAction(): string
    {
        $this->logger->info(sprintf('Requested authorization for client %s with scopes "%s"', $this->getRequestingClientFromCurrentRequest(), $this->getRequestedScopesFromCurrentRequest()), LogEnvironment::fromMethodName(__METHOD__));
        $this->debugRequest();

        $response = $this->withErrorHandling(function () {
            $authorizationRequest = $this->authorizationServer->validateAuthorizationRequest($this->request->getHttpRequest());

            $response = $this->approveAuthorizationRequest($authorizationRequest, new Response());
            if ($authorizationRequest->isAuthorizationApproved()) {
                return $response;
            } else {
                $this->authorizationSession->setAuthorizationRequest($authorizationRequest);
                $this->redirectToUri($this->authenticationPageUri);
            }
        });

        return PsrRequestResponseService::transferPsr7ResponseToFlowResponse($response, $this->response);
    }

    /**
     * Is called after authorizationAction was called without valid user session.
     *
     * uriPattern: 'oauth/approveauthorization'
     *
     * @return string
     */
    public function approveAuthorizationAction(): string
    {
        $this->logger->info('Approve client form session stored authorization request', LogEnvironment::fromMethodName(__METHOD__));

        $response = $this->withErrorHandling(function () {
            $authorizationRequest = $this->authorizationSession->getAndRemoveAuthorizationRequest();
            if (!$authorizationRequest instanceof AuthorizationRequest) {
                throw new OAuthServerException('Requested to authorize a session stored request, but session request was empty', 1548142529, 'session_request_missing');
            }

            $response = $this->approveAuthorizationRequest($authorizationRequest, new Response());
            if ($authorizationRequest->isAuthorizationApproved()) {
                return $response;
            } else {
                throw new OAuthServerException('Requesteded to authorize a session stored request, but user was not authenticated', 1548142529, 'user_not_authenticated');
            }
        });

        return PsrRequestResponseService::transferPsr7ResponseToFlowResponse($response, $this->response);
    }

    /**
     * uriPattern: 'oauth/token'
     *
     * @return string
     */
    public function accessTokenAction(): string
    {
        $this->logger->info('OAuth access token requested for client ' . $this->getRequestingClientFromCurrentRequest(), LogEnvironment::fromMethodName(__METHOD__));
        $this->debugRequest();

        $response = $this->withErrorHandling(function () {
            return $this->authorizationServer->respondToAccessTokenRequest($this->request->getHttpRequest(), new Response());
        });

        return PsrRequestResponseService::transferPsr7ResponseToFlowResponse($response, $this->response);
    }

    /**
     * @param callable $callback
     * @return Response
     */
    private function withErrorHandling(callable $callback): Response
    {
        try {
            return $callback();
        } catch (OAuthServerException $exception) {
            // All instances of OAuthServerException can be formatted into a HTTP response
            $this->logger->error(sprintf('OAuthServerException: %s', $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
            return $exception->generateHttpResponse(new Response());
        } catch (\Exception $exception) {
            $this->logger->error(sprintf('Unknown exception: %s', $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
            return PsrRequestResponseService::psr7ErrorResponseFromMessage(new Response(), $exception->getMessage());
        }
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
     * @return string
     */
    private function getRequestedScopesFromCurrentRequest(): string
    {
        return $this->request->getHttpRequest()->hasArgument('scope') ? $this->request->getHttpRequest()->getArgument('scope') : '';
    }

    /**
     * @param AuthorizationRequest $authorizationRequest
     * @param Response $response
     * @return Response
     */
    private function approveAuthorizationRequest(AuthorizationRequest $authorizationRequest, Response $response): ResponseInterface
    {
        $this->authorizationApprovalService->approveAuthorizationRequest($authorizationRequest);
        if ($authorizationRequest->isAuthorizationApproved()) {
            $response = $this->authorizationServer->completeAuthorizationRequest($authorizationRequest, $response);
        }

        return $response;
    }
}
