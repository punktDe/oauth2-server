<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server\Authorization;

/*
 *  (c) 2019 punkt.de GmbH - Karlsruhe, Germany - http://punkt.de
 *  All rights reserved.
 */

use Neos\Flow\Annotations as Flow;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Neos\Flow\Log\PsrSystemLoggerInterface;
use Neos\Flow\Reflection\ReflectionService;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Context;
use PunktDe\OAuth2\Server\Authorization\ApprovalStrategies\ApprovalStrategyInterface;
use PunktDe\OAuth2\Server\Domain\Model\UserEntity;
use PunktDe\OAuth2\Server\Utility\LogEnvironment;

class AuthorizationApprovalService
{
    /**
     * @Flow\Inject
     * @var ReflectionService
     */
    protected $reflectionService;

    /**
     * @Flow\Inject
     * @var Context
     */
    protected $securityContext;

    /**
     * @Flow\Inject
     * @var PsrSystemLoggerInterface
     */
    protected $logger;

    /**
     * @param AuthorizationRequest $authorizationRequest
     * @return void
     */
    public function approveAuthorizationRequest(AuthorizationRequest $authorizationRequest): void
    {
        if (!$this->securityContext->isInitialized() || !$this->securityContext->getAccount() instanceof Account) {
            return;
        }

        $account = $this->securityContext->getAccount();
        $approvalStrategyClassNames = $this->reflectionService->getAllImplementationClassNamesForInterface(ApprovalStrategyInterface::class);

        /** @var ApprovalStrategyInterface $approvalStrategyClassName */
        foreach ($approvalStrategyClassNames as $approvalStrategyClassName) {
            if((new $approvalStrategyClassName)->isApproved($authorizationRequest, $account) !== true) {
                $this->logger->info(sprintf('Approval strategy %s did not approve the given account and authorization request', get_class($approvalStrategyClassName)), LogEnvironment::fromMethodName(__METHOD__));
                return;
            }
        }

        $authorizationRequest->setUser(new UserEntity($account));
        $authorizationRequest->setAuthorizationApproved(true);
    }
}
