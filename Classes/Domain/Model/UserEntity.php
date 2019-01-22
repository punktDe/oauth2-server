<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server\Domain\Model;

/*
 *  (c) 2018 punkt.de GmbH - Karlsruhe, Germany - http://punkt.de
 *  All rights reserved.
 */

use Neos\Flow\Annotations as Flow;
use League\OAuth2\Server\Entities\UserEntityInterface;
use Neos\Flow\Persistence\Doctrine\PersistenceManager;
use Neos\Flow\Security\Account;

final class UserEntity implements UserEntityInterface
{
    /**
     * @var Account
     */
    protected $account;

    /**
     * @Flow\Inject
     * @var PersistenceManager
     */
    protected $persistenceManager;


    public function __construct(Account $account)
    {
        $this->account = $account;
    }

    /**
     * Return the user's identifier.
     *
     * @return mixed
     */
    public function getIdentifier()
    {
        return $this->persistenceManager->getIdentifierByObject($this->account);
    }
}
