<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server\Controller;

/*
 *  (c) 2018 punkt.de GmbH - Karlsruhe, Germany - http://punkt.de
 *  All rights reserved.
 */

use Exception;
use Neos\Flow\Annotations as Flow;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Neos\Flow\Log\ThrowableStorageInterface;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Flow\Mvc\Exception\NoSuchArgumentException;
use Neos\Flow\Mvc\Exception\StopActionException;
use Psr\Http\Message\ResponseInterface;
use PunktDe\OAuth2\Server\Authorization\AuthorizationApprovalService;
use PunktDe\OAuth2\Server\AuthorizationServerFactory;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use Neos\Flow\Mvc\Controller\ActionController;
use PunktDe\OAuth2\Server\Service\PsrRequestResponseService;
use PunktDe\OAuth2\Server\Session\AuthorizationSession;

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
     * @Flow\Inject
     * @var ThrowableStorageInterface
     */
    protected $throwableStorage;

    /**
     * @return void
     * @throws Exception
     */
    public function initializeAction(): void
    {
        $this->authorizationServer = $this->authorizationServerFactory->getInstance();
    }

    /**
     * uriPattern: 'oauth/authorize'
     *
     * @return string
     * @throws NoSuchArgumentException
     * @throws StopActionException
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
                $this->logger->debug('User is not authorized, redirecting to ' . $this->authenticationPageUri, LogEnvironment::fromMethodName(__METHOD__));
                $this->redirectToUri($this->authenticationPageUri);
            }
        });

        return PsrRequestResponseService::replaceResponse($response, $this->response);
    }

    /**
     * Is called after authorizationAction was called without valid user session.
     *
     * uriPattern: 'oauth/approveauthorization'
     *
     * @return string
     * @throws StopActionException
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
                throw new OAuthServerException('Requested to authorize a session stored request, but user was not authenticated', 1548142529, 'user_not_authenticated');
            }
        });

        return PsrRequestResponseService::replaceResponse($response, $this->response);
    }

    /**
     * uriPattern: 'oauth/token'
     *
     * @return string
     * @throws NoSuchArgumentException
     * @throws StopActionException
     */
    public function accessTokenAction(): string
    {
        $this->logger->info('OAuth access token requested for client ' . $this->getRequestingClientFromCurrentRequest(), LogEnvironment::fromMethodName(__METHOD__));
        $this->debugRequest();

        $response = $this->withErrorHandling(function () {
            return $this->authorizationServer->respondToAccessTokenRequest($this->request->getHttpRequest(), new Response());
        });

        return PsrRequestResponseService::replaceResponse($response, $this->response);
    }

    /**
     * @param callable $callback
     * @return Response
     * @throws StopActionException
     */
    private function withErrorHandling(callable $callback): Response
    {
        try {
            return $callback();
        } catch (OAuthServerException $exception) {
            // All instances of OAuthServerException can be formatted into a HTTP response
            $this->logger->error(sprintf('OAuthServerException: %s', $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
            return $exception->generateHttpResponse(new Response());
        } catch (StopActionException $exception) {
            // In case of a redirect to the login page, a StopActionException needs to be thrown.
            throw $exception;
        } catch (Exception $exception) {
            $message = $this->throwableStorage->logThrowable($exception);
            $this->logger->error($message, LogEnvironment::fromMethodName(__METHOD__));
            return PsrRequestResponseService::psr7ErrorResponseFromMessage(new Response(), $exception->getMessage());
        }
    }

    /**
     * Debug the current request to the log
     */
    private function debugRequest(): void
    {
        $requestArguments = $this->request->getArguments();
        if (isset($requestArguments['client_secret'])) {
            $requestArguments['client_secret'] = str_repeat('*', strlen($requestArguments['client_secret']));
        }

        $this->logger->debug('Request arguments for ' . $this->request->getHttpRequest()->getUri(), $requestArguments + LogEnvironment::fromMethodName(__METHOD__));
    }

    /**
     * @return string
     * @throws NoSuchArgumentException
     */
    private function getRequestingClientFromCurrentRequest(): string
    {
        return $this->request->hasArgument('client_id') ? $this->request->getArgument('client_id') : '';
    }

    /**
     * @return string
     * @throws NoSuchArgumentException
     */
    private function getRequestedScopesFromCurrentRequest(): string
    {
        return $this->request->hasArgument('scope') ? $this->request->getArgument('scope') : '';
    }

    /**
     * @param AuthorizationRequest $authorizationRequest
     * @param Response $response
     * @return ResponseInterface
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
