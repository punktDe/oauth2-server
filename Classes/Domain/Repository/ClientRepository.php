<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server\Domain\Repository;

/*
 *  (c) 2018 punkt.de GmbH - Karlsruhe, Germany - http://punkt.de
 *  All rights reserved.
 */

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Flow\Persistence\Repository;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use Psr\Log\LoggerInterface;
use PunktDe\OAuth2\Server\Domain\Model\Client;

/**
 * @Flow\Scope("singleton")
 */
class ClientRepository extends Repository implements ClientRepositoryInterface
{
    /**
     * @Flow\Inject
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @param string $identifier
     * @return Client|null
     */
    public function findOneByIdentifier(string $identifier): ?Client
    {
        return $this->__call('findOneByIdentifier', [$identifier]);
    }

    /**
     * @param string $clientIdentifier
     * @return ClientEntityInterface|null
     * phpcs:disable
     */
    public function getClientEntity($clientIdentifier): ?ClientEntityInterface
    {
        return $this->findOneByIdentifier($clientIdentifier);
    }

    /**
     * @param string $clientIdentifier
     * @param string|null $clientSecret
     * @param string|null $grantType
     * @return bool
     */
    public function validateClient($clientIdentifier, $clientSecret, $grantType)
    {
        $client = $this->getClientEntity($clientIdentifier);
        if(!$client instanceof ClientEntityInterface) {
            return false;
        }

        if ($client->getGrantType() !== $grantType) {
            $this->logger->warning(sprintf('Requested grant %s type does not equal the client grant type %s', $grantType, $client->getGrantType()), LogEnvironment::fromMethodName(__METHOD__));
            return false;
        }
        if (!$client->validateSecret((string) $clientSecret)) {
            $this->logger->warning(sprintf('Incorrect secret provided for client %s (grant type %s).', $clientIdentifier, $grantType), LogEnvironment::fromMethodName(__METHOD__));
            return false;
        }
        return true;
    }
}
