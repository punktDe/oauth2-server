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
use Neos\Flow\Http\Request;
use Psr\Http\Message\ServerRequestInterface;

class PsrRequestResponseService
{
    /**
     * @param Request $flowRequest
     * @return ServerRequestInterface
     */
    public static function transferFlowRequestToPsr7Request(Request $flowRequest): ServerRequestInterface
    {
        return new ServerRequest(
            $flowRequest->getMethod(),
            $flowRequest->getUri(),
            $flowRequest->getHeaders()->getAll(),
            $flowRequest->getVersion()
        );
    }

    /**
     * Transfer the truly PSR-7 compatible response to the Flow HTTP response
     *
     * @param Response $psr7Response
     * @param \Neos\Flow\Http\Response $flowResponse
     * @return string
     */
    public static function transferPsr7ResponseToFlowResponse(Response $psr7Response, \Neos\Flow\Http\Response $flowResponse): string
    {
        $flowResponse->setStatus($psr7Response->getStatusCode());
        foreach ($psr7Response->getHeaders() as $headerName => $headerValues) {
            foreach ($headerValues as $headerValue) {
                $flowResponse->setHeader($headerName, $headerValue);
            }
        }

        $psr7Response->getBody()->rewind();

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
        $body = new Stream('php://temp', 'r+');
        $body->write($message);
        return $psr7Response->withStatus($status)->withBody($body);
    }
}
