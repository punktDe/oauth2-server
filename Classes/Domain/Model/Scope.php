<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server\Domain\Model;

/*
 *  (c) 2018 punkt.de GmbH - Karlsruhe, Germany - http://punkt.de
 *  All rights reserved.
 */

use Doctrine\ORM\Mapping as ORM;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use Neos\Flow\Annotations\Identity;

final class Scope implements ScopeEntityInterface
{
    /**
     * @Identity
     * @ORM\Id
     * @var string
     */
    protected $identifier;

    /**
     * Scope constructor.
     *
     * @param string $identifier
     */
    public function __construct(string $identifier)
    {
        $this->identifier = $identifier;
    }

    /**
     * @return string
     */
    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    /**
     * @return string
     * phpcs:disable
     */
    public function __toString()
    {
        return $this->identifier;
    }

    /**
     * @return string
     */
    public function jsonSerialize()
    {
        return $this->identifier;
    }
}
