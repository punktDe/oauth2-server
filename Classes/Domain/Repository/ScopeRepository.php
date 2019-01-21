<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server\Domain\Repository;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use Neos\Flow\Annotations as Flow;
use PunktDe\OAuth2\Server\Domain\Model\Scope;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use Neos\Flow\Persistence\Repository;

/**
 * @Flow\Scope("singleton")
 */
final class ScopeRepository extends Repository implements ScopeRepositoryInterface
{
    // phpcs:disable

    /**
     * @Flow\InjectConfiguration(path="scopes")
     * @var string[]
     */
    protected $scopeIdentifiers;

    /**
     * @var Scope[]
     */
    protected $scopes;

    /**
     * @param string $identifier
     * @return Scope|null
     */
    public function getScopeEntityByIdentifier($identifier)
    {
        if (!key_exists($identifier, $this->scopeIdentifiers)) {
            return null;
        }

        if (!isset($this->scopes[$identifier])) {
            $this->scopes[$identifier] = new Scope($identifier);
        }

        return $this->scopes[$identifier];
    }

    /**
     * @param array $scopes
     * @param string $grantType
     * @param ClientEntityInterface $clientEntity
     * @param null $userIdentifier
     * @return ScopeEntityInterface[]
     */
    public function finalizeScopes(array $scopes, $grantType, ClientEntityInterface $clientEntity, $userIdentifier = null)
    {
        return $scopes;
    }
}
