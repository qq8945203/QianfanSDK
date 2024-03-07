<?php
namespace Baiducloud\SDK\Auth;
use Baiducloud\SDK\ApiException;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Request;

class OAuth implements Authentication
{
    private $ak;
    private $sk;
    private $client;
    private $accessToken;
    private $basePath;

    public function __construct($ak, $sk, $basePath='https://aip.baidubce.com')
    {
        $this->ak = $ak;
        $this->sk = $sk;
        $this->basePath = $basePath;
        $this->accessToken = new AccessToken();
    }

    public function getAccessToken()
    {
        return $this->accessToken->getValue();
    }

    public function getAk()
    {
        return $this->ak;
    }

    public function getSk()
    {
        return $this->sk;
    }

    public function getAuthName()
    {
        return "OAuth";
    }

    public function applyToParams($httpClient ,&$queryParams, &$headerParams, $payload, $method, $uri)
    {
        if ($this->accessToken->isExpire()) {
            if ($this->ak === null || $this->sk === null) {
                return false;
            }

            try {
                $response = $httpClient->request('POST', $this->basePath.'/oauth/2.0/token', [
                    'headers' => ['Content-Type' => 'application/x-www-form-urlencoded'],
                    'form_params' => [
                        'grant_type' => 'client_credentials',
                        'client_id' => $this->ak,
                        'client_secret' => $this->sk,
                    ],
                ]);

                if ($response->getStatusCode() == 200) {
                    $respBody = $response->getBody()->getContents();
                    $accessToken = json_decode($respBody);
                    if ($accessToken === null || empty($accessToken->access_token)) {
                        throw new ApiException("Invalid access token received.");
                    }
                    $this->accessToken->setValue($accessToken->access_token);
                    $this->accessToken->init();
                } else {
                    throw new ApiException("API request failed with status code " . $response->getStatusCode());
                }
            } catch (GuzzleException $e) {
                throw new ApiException("An error occurred while requesting the access token.", 0, $e);
            }
        }

        $queryParams['access_token'] = $this->accessToken->getValue();
        return true;
    }
}

class AccessToken
{
    private $value;
    private $expiryTime = 0;

    public function getValue()
    {
        return $this->value;
    }

    public function setValue($accessToken)
    {
        $this->value = $accessToken;
    }

    public function init()
    {
        if ($this->value !== null && $this->value !== "") {
            $timestampStr = explode('.', $this->value)[3];
            $timestamp = intval($timestampStr);
            $this->expiryTime = ($timestamp - 300) * 1000;
        } else {
            throw new Exception("accessToken value is null");
        }
    }

    public function isExpire()
    {
        if ($this->expiryTime === 0) {
            return true;
        }
        $currentTimeInMillis = round(microtime(true) * 1000);
        return $currentTimeInMillis > $this->expiryTime;
    }
}