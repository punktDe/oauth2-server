<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server\Authorization\Validators;

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
    /**
     * phpcs:disable
     * @param ServerRequestInterface $request
     * @return BearerTokenValidator|ServerRequestInterface
     */
    public function validateAuthorization(ServerRequestInterface $request)
    {
        if ($request->hasHeader('authorization') === true && substr(trim(current($request->getHeader('authorization'))), 0, 6) === 'Bearer') {
            return parent::validateAuthorization($request);
        }

        if ($request->getAttribute('access_token', null) !== null) {
            return parent::validateAuthorization($request->withHeader('authorization', 'Bearer ' . $request->getAttribute('access_token')));
        }
    }
}
