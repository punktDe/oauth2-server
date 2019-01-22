<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server\Session;

/*
 *  (c) 2019 punkt.de GmbH - Karlsruhe, Germany - http://punkt.de
 *  All rights reserved.
 */

use Neos\Flow\Annotations as Flow;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;

/**
 * @Flow\Scope("session")
 */
class AuthorizationSession
{
    /**
     * @var AuthorizationRequest
     */
    protected $authorizationRequest;

    /**
     * @return AuthorizationRequest
     */
    public function getAuthorizationRequest(): AuthorizationRequest
    {
        return $this->authorizationRequest;
    }

    /**
     * @Flow\Session(autoStart = TRUE)
     * @param AuthorizationRequest $authorizationRequest
     */
    public function setAuthorizationRequest(AuthorizationRequest $authorizationRequest): void
    {
        $this->authorizationRequest = $authorizationRequest;
    }
}
