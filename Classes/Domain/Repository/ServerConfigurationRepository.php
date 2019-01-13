<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server\Domain\Repository;

/*
 *  (c) 2018 punkt.de GmbH - Karlsruhe, Germany - http://punkt.de
 *  All rights reserved.
 */

use PunktDe\OAuth2\Server\Domain\Model\ServerConfiguration;
use Neos\Flow\Annotations\Scope;
use Neos\Flow\Persistence\Repository;

/**
 * @Scope("singleton")
 */
class ServerConfigurationRepository extends Repository
{
    /**
     * @param string $key
     * @return ServerConfiguration|null
     */
    public function findOneByConfigurationKey(string $key): ?ServerConfiguration
    {
        return $this->__call('findOneByConfigurationKey', [$key]);
    }
}
