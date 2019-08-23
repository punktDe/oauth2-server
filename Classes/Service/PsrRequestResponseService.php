<?php
declare(strict_types=1);

namespace PunktDe\OAuth2\Server\Service;

/*
 *  (c) 2018 punkt.de GmbH - Karlsruhe, Germany - http://punkt.de
 *  All rights reserved.
 */

use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Stream;
use Neos\Flow\Http\Component\ReplaceHttpResponseComponent;
use Neos\Flow\Http\Request;
use Neos\Flow\Mvc\ActionResponse;
use Psr\Http\Message\ServerRequestInterface;

class PsrRequestResponseService
{
    /**
     * Transfer the truly PSR-7 compatible response to the Flow HTTP response
     *
     * @param Response $psr7Response
     * @param ActionResponse $actionResponse
     * @return string
     */
    public static function replaceResponse(Response $psr7Response, ActionResponse $actionResponse): string
    {
        $actionResponse->setComponentParameter(ReplaceHttpResponseComponent::class, ReplaceHttpResponseComponent::PARAMETER_RESPONSE, $psr7Response);
        return $psr7Response->getBody()->getContents();
    }

    /**
     * @param Response $psr7Response
     * @param string $message
     * @param int $status
     * @return Response
     */
    public static function psr7ErrorResponseFromMessage(Response $psr7Response, string $message, int $status = 500): Response
    {
        $body = new Stream(fopen('php://temp', 'r+'));
        $body->write($message);
        return $psr7Response->withStatus($status)->withBody($body);
    }
}
