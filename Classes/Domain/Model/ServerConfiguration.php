<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server\Domain\Model;

/*
 *  (c) 2018 punkt.de GmbH - Karlsruhe, Germany - http://punkt.de
 *  All rights reserved.
 */

use Doctrine\ORM\Mapping as ORM;
use Neos\Flow\Annotations\Entity;
use Neos\Flow\Annotations\Identity;

/**
 * @Entity()
 */
class ServerConfiguration implements \JsonSerializable
{
    /**
     * @Identity()
     * @ORM\Id()
     * @var string
     */
    protected $configurationKey;

    /**
     * @ORM\Column(type="text")
     * @var string
     */
    protected $configurationValue;

    /**
     * ServerConfiguration constructor.
     *
     * @param string $configurationKey
     * @param string $configurationValue
     */
    public function __construct(string $configurationKey, string $configurationValue)
    {
        $this->configurationKey = $configurationKey;
        $this->configurationValue = $configurationValue;
    }

    /**
     * @return string
     */
    public function getConfigurationKey(): string
    {
        return $this->configurationKey;
    }

    /**
     * @return string
     */
    public function getConfigurationValue(): string
    {
        return $this->configurationValue;
    }

    /**
     * @param string $configurationValue
     */
    public function setConfigurationValue(string $configurationValue): void
    {
        $this->configurationValue = $configurationValue;
    }

    /**
     * @return string
     */
    public function __toString(): string
    {
        return $this->configurationValue;
    }

    /**
     * @return string
     * phpcs:disable
     */
    public function jsonSerialize()
    {
        return $this->__toString();
    }
}
