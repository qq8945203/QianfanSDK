<?php

namespace Baiducloud\SDK\Auth;

use DateTime;
use DateTimeZone;

class IamAuth implements Authentication
{
    private const HEADER_HOST = 'host';
    private const HEADER_CONTENT_MD5 = 'content-md5';
    private const HEADER_CONTENT_LENGTH = 'content-length';
    private const HEADER_CONTENT_TYPE = 'content-type';

    private const BCE_HEADER_TO_SIGN = [self::HEADER_HOST, self::HEADER_CONTENT_MD5, self::HEADER_CONTENT_LENGTH, self::HEADER_CONTENT_TYPE];
    private const BCE_PREFIX = 'x-bce-';
    private $iamAk;
    private $iamSk;
    private $signExpireInSeconds = 1800;

    /**
     * @param $iamAk
     * @param $iamSk
     * @param int $signExpireInSeconds
     */
    public function __construct($iamAk, $iamSk, int $signExpireInSeconds = 1800)
    {
        $this->iamAk = $iamAk;
        $this->iamSk = $iamSk;
        $this->signExpireInSeconds = $signExpireInSeconds;
    }

    public function getIamAk()
    {
        return $this->iamAk;
    }

    public function getIamSk()
    {
        return $this->iamSk;
    }

    public function getSignExpireInSeconds()
    {
        return $this->signExpireInSeconds;
    }

    private static function md5($data)
    {
        return md5($data);
    }

    private static function encodeHex($data)
    {
        return bin2hex($data);
    }

    private static function hmacSha256($key, $data)
    {
        return hash_hmac('sha256', $data, $key);
    }

    private static function getCanonicalUri($path)
    {
        if (substr($path, 0, 1) !== "/") {
            $path = sprintf("/%s", $path);
        }
        return str_replace("%2F", "/", rawurlencode($path));
    }

    private static function getCanonicalQuery($params)
    {
        if (empty($params)) {
            return "";
        }
        $querySet = [];
        foreach ($params as $key => $value) {
            if (strtolower($key) !== "authorization") {
                $querySet[] = sprintf("%s=%s",
                    rawurlencode($key),
                    rawurlencode($value));
            }
        }
        asort($querySet);
        return join("&", $querySet);
    }

    private static function getCanonicalHeaders($headers)
    {
        if (empty($headers)) {
            return ["", ""];
        }
        $headerSet = [];
        $canonicalSet = [];
        foreach ($headers as $key => $value) {
            $key = trim(strtolower($key));
            if (strpos($key, self::BCE_PREFIX) === 0 || in_array($key, self::BCE_HEADER_TO_SIGN)) {
                $headerSet[] = sprintf("%s:%s", rawurlencode($key), rawurlencode(trim($value)));
                $canonicalSet[] = rawurlencode($key);
            }
        }
        asort($canonicalSet);
        asort($headerSet);
        return [join(";", $canonicalSet), join("\n", $headerSet)];
    }

    private function sign($queryParams, $headerParams, $timestamp, $method, $uri)
    {
        $path = $uri->getPath();
        // 1. Generate signingKey
        $authStringPrefix = sprintf("bce-auth-v1/%s/%s/%d",
            $this->iamAk, $timestamp, $this->signExpireInSeconds);

        try {
            // 1.2. Use authStringPrefix with SK to generate sign key using SHA-256
            $signingKey = self::hmacSha256($this->iamSk, $authStringPrefix);

            // 2. Generate Canonical URI
            $canonicalUri = self::getCanonicalUri($path);

            // 3. Generate Canonical Query String
            $canonicalQuery = self::getCanonicalQuery($queryParams);

            // 4. Generate Canonical Headers
            $canonicalHeaders = self::getCanonicalHeaders($headerParams);

            $canonicalRequest = [
                $method,
                $canonicalUri,
                $canonicalQuery,
                $canonicalHeaders[1]
            ];

            $signature = self::hmacSha256($signingKey, join("\n", $canonicalRequest));

            return sprintf("%s/%s/%s", $authStringPrefix, $canonicalHeaders[0], $signature);
        } catch (Exception $e) {
            error_log($e->getMessage());
            return null;
        }
    }

    private static function getCanonicalTime()
    {
        $utcDayFormat = 'Y-m-d';
        $utcHourFormat = 'H:i:s';
        $now = new DateTime("now", new DateTimeZone("UTC"));
        return sprintf("%sT%sZ", $now->format($utcDayFormat), $now->format($utcHourFormat));
    }

    public function getAuthName()
    {
        return "IamAuth";
    }

    public function applyToParams($httpClient, array &$queryParams, array &$headerParams, $payload, $method, $uri)
    {
        if ($this->iamAk === null || $this->iamSk === null) {
            return false;
        }
        $timestamp = self::getCanonicalTime();
        $headerParams[self::HEADER_HOST] = $uri->getHost();
        $headerParams[self::HEADER_CONTENT_MD5] = self::md5($payload);
        $sign = $this->sign($queryParams, $headerParams, $timestamp, $method, $uri);
        $headerParams['Authorization'] = $sign;
        return true;
    }
}
