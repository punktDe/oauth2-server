<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server\Domain\Repository;

/*
 *  (c) 2018 punkt.de GmbH - Karlsruhe, Germany - http://punkt.de
 *  All rights reserved.
 */

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Persistence\Repository;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use Psr\Log\LoggerInterface;
use PunktDe\OAuth2\Server\Domain\Model\Client;
use PunktDe\OAuth2\Server\Utility\LogEnvironment;

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
     * @param string $grantType
     * @param null $clientSecret
     * @param bool $mustValidateSecret
     * @return ClientEntityInterface|null
     * phpcs:disable
     */
    public function getClientEntity($clientIdentifier, $grantType, $clientSecret = null, $mustValidateSecret = true): ?ClientEntityInterface
    {
        $client = $this->findOneByIdentifier($clientIdentifier);
        if ($client === null) {
            return null;
        }
        if ($client->getGrantType() !== $grantType) {
            $this->logger->warning(sprintf('Requested grant %s type does not equal the client grant type %s', $grantType, $client->getGrantType()), LogEnvironment::fromMethodName(__METHOD__));
            return null;
        }
        if ($mustValidateSecret && !$client->validateSecret((string) $clientSecret)) {
            $this->logger->warning(sprintf('Incorrect secret provided for client %s (grant type %s).', $clientIdentifier, $grantType), LogEnvironment::fromMethodName(__METHOD__));
            return null;
        }
        return $client;
    }
}
