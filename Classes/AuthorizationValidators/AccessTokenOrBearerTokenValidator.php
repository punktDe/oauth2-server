<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server\AuthorizationValidators;

/*
 *  (c) 2019 punkt.de GmbH - Karlsruhe, Germany - http://punkt.de
 *  All rights reserved.
 */

use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidator;
use Psr\Http\Message\ServerRequestInterface;

/**
 * This validator accepts either an authorization header with a Bearer prefixed access token
 * or as access_token GET parameter
 */
class AccessTokenOrBearerTokenValidator extends BearerTokenValidator
{
    public function validateAuthorization(ServerRequestInterface $request)
    {
        if ($request->hasHeader('authorization') === true) {
            return parent::validateAuthorization($request);
        }

        if ($request->getAttribute('access_token', null) !== null) {
            return parent::validateAuthorization($request->withHeader('authorization', 'Bearer ' . $request->getAttribute('access_token')));
        }
    }
}
