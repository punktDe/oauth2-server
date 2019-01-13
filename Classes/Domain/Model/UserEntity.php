<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server\Domain\Model;

/*
 *  (c) 2018 punkt.de GmbH - Karlsruhe, Germany - http://punkt.de
 *  All rights reserved.
 */

use League\OAuth2\Server\Entities\UserEntityInterface;
use Neos\Flow\Persistence\Doctrine\PersistenceManager;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Context;
use Neos\Flow\Annotations as Flow;

final class UserEntity implements UserEntityInterface
{

    /**
     * @Flow\Inject
     * @var Context
     */
    protected $securityContext;

    /**
     * @Flow\Inject
     * @var PersistenceManager
     */
    protected $persistenceManager;

    /**
     * Return the user's identifier.
     *
     * @return mixed
     */
    public function getIdentifier()
    {
        if ($this->securityContext->isInitialized() && $this->securityContext->getAccount() instanceof Account) {
            return $this->persistenceManager->getIdentifierByObject($this->securityContext->getAccount());
        }

        return null;
    }
}
