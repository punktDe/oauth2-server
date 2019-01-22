<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server\Authorization\ApprovalStrategies;

/*
 *  (c) 2019 punkt.de GmbH - Karlsruhe, Germany - http://punkt.de
 *  All rights reserved.
 */

use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Neos\Flow\Security\Account;

interface ApprovalStrategyInterface
{

    /**
     * @param AuthorizationRequest $authorizationRequest
     * @param Account $account
     * @return bool
     */
    public function isApproved(AuthorizationRequest $authorizationRequest, Account $account): bool;
}
