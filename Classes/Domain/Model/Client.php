<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server\Domain\Model;

/*
 *  (c) 2018 punkt.de GmbH - Karlsruhe, Germany - http://punkt.de
 *  All rights reserved.
 */

use League\OAuth2\Server\Entities\ClientEntityInterface;
use Neos\Flow\Annotations\Identity;
use Neos\Flow\Annotations\Entity;
use Doctrine\ORM\Mapping as ORM;
use Neos\Flow\Annotations\Inject;
use Neos\Utility\Arrays;
use Psr\Log\LoggerInterface;

/**
 * @Entity
 */
class Client implements ClientEntityInterface
{
    /**
     * @Identity
     * @ORM\Id
     * @var string
     */
    protected $identifier;

    /**
     * @var string
     */
    protected $name;

    /**
     * One of "client_credentials", "authorization_code"
     *
     * @var string
     */
    protected $grantType;

    /**
     * @var string
     */
    protected $hashedSecret = null;

    /**
     * @ORM\Column(nullable=true, type="text", length=2000)
     * @var string
     */
    protected $redirectUri = null;

    /**
     * @Inject()
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @param string $identifier
     * @param string $name
     * @param string $grantType
     * @param HashedSecret|null $hashedSecret
     * @param string|null $redirectUri
     */
    public function __construct(string $identifier, string $name, string $grantType, ?HashedSecret $hashedSecret = null, ?string $redirectUri = null)
    {
        $this->identifier = $identifier;
        $this->name = $name;
        $this->grantType = $grantType;
        $this->hashedSecret = $hashedSecret;
        $this->redirectUri = $redirectUri;
    }

    /**
     * @param string $secret
     * @return bool
     */
    public function validateSecret(string $secret): bool
    {
        if (is_string($this->hashedSecret)) {
            $this->hashedSecret = HashedSecret::fromHashedSecret($this->hashedSecret);
        }
        return $this->hashedSecret->validateClearTextSecret($secret);
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
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * @param string $name
     */
    public function setName(string $name): void
    {
        $this->name = $name;
    }

    /**
     * @return string
     */
    public function getGrantType(): string
    {
        return $this->grantType;
    }

    /**
     * @param string $grantType
     */
    public function setGrantType(string $grantType): void
    {
        $this->grantType = $grantType;
    }

    /**
     * @return string|string[]
     */
    public function getRedirectUri()
    {
        return Arrays::trimExplode(',', $this->redirectUri);
    }

    /**
     * @param string $redirectUri
     */
    public function setRedirectUri(string $redirectUri): void
    {
        $this->redirectUri = $redirectUri;
    }

    /**
     * @return bool
     */
    public function isConfidential()
    {
        return true;
    }
}
