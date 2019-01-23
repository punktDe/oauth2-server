<?php
declare(strict_types=1);

namespace PunktDe\Oauth2\Server\Tests\Functional;

/*
 *  (c) 2019 punkt.de GmbH - Karlsruhe, Germany - http://punkt.de
 *  All rights reserved.
 */

use League\OAuth2\Server\AuthorizationServer;
use Neos\Flow\Tests\FunctionalTestCase;
use PunktDe\OAuth2\Server\AuthorizationServerFactory;
use PunktDe\OAuth2\Server\Command\OAuthServerCommandController;

class AuthorizationServerFactoryTest extends FunctionalTestCase
{

    /**
     * @var AuthorizationServerFactory
     */
    protected $authorizationServerFactory;

    protected static $testablePersistenceEnabled = true;

    public function setUp()
    {
        parent::setUp();
        $this->authorizationServerFactory = $this->objectManager->get(AuthorizationServerFactory::class);

        $this->objectManager->get(OAuthServerCommandController::class)->generateServerKeysCommand();
        $this->persistenceManager->persistAll();
    }

    /**
     * @test
     */
    public function getInstance()
    {
        $authorizationServer = $this->authorizationServerFactory->getInstance();
        $this->assertInstanceOf(AuthorizationServer::class, $authorizationServer);
    }
}
