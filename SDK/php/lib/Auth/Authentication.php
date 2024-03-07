<?php

namespace Baiducloud\SDK\Auth;

use Baiducloud\SDK\ApiException;

interface Authentication
{
    public function getAuthName();
    /**
     * Apply authentication settings to header and query params.
     *
     * @param array $queryParams Array of query parameters
     * @param array $headerParams Array of header parameters
     * @param string $payload HTTP request body
     * @param string $method HTTP method
     * @param string $uri URI
     * @return bool
     * @throws ApiException if failed to update the parameters
     */
    public function applyToParams($httpClient, array &$queryParams, array &$headerParams, $payload, $method, $uri);
}
