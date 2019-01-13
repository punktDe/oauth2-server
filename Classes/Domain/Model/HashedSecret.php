<?php
namespace PunktDe\OAuth2\Server\Domain\Model;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Cryptography\HashService;

/**
 * A hashed secret
 */
final class HashedSecret implements \JsonSerializable
{
    const MINIMUM_LENGTH = 8;
    const MAXIMUM_LENGTH = 100;

    /**
     * @var string
     */
    private $clearTextSecret;

    /**
     * @var string
     */
    private $hashedSecret;

    /**
     * @Flow\Inject
     * @var HashService
     */
    protected $hashService;

    /**
     * @param string $clearTextSecret
     * @return static
     */
    public static function fromClearTextSecret(string $clearTextSecret)
    {
        if (strlen($clearTextSecret) < self::MINIMUM_LENGTH) {
            throw new \InvalidArgumentException('The secret is too short.', 1510137987314);
        }
        if (strlen($clearTextSecret) > self::MAXIMUM_LENGTH) {
            throw new \InvalidArgumentException('The secret is too long.', 1510138008439);
        }
        $secret = new static();
        $secret->clearTextSecret = $clearTextSecret;
        return $secret;
    }

    /**
     * @param string $hashedSecret
     * @return static
     */
    public static function fromHashedSecret(string $hashedSecret): HashedSecret
    {
        $secret = new static();
        $secret->hashedSecret = $hashedSecret;
        return $secret;
    }

    /**
     * @return string
     */
    public function getHashedSecret(): string
    {
        if ($this->hashedSecret === null) {
            $this->hashedSecret = $this->hashService->hashPassword($this->clearTextSecret);
            unset($this->clearTextSecret);
        }
        return $this->hashedSecret;
    }

    /**
     * @param string $clearTextSecret
     * @return bool
     */
    public function validateClearTextSecret(string $clearTextSecret): bool
    {
        return $this->hashService->validatePassword($clearTextSecret, $this->hashedSecret);
    }

    /**
     * @return string
     */
    public function __toString(): string
    {
        return $this->getHashedSecret();
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
