<?php

namespace OAuth\OAuth2\Service;

use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\Common\Http\Client\CurlClient as CurlClient;

class Stripe extends AbstractService
{
    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = array(),
        UriInterface $baseApiUri = null
    ) {
        
        $this->httpClient = $httpClient = new CurlClient();

        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri);

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://connect.stripe.com/oauth/token');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://connect.stripe.com/oauth/authorize');
    }

    /**
     * {@inheritdoc}
     */
    public function getDeauthorizationEndpoint()
    {
        return new Uri('https://connect.stripe.com/oauth/deauthorize');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://connect.stripe.com/oauth/token');
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_QUERY_STRING;
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        $data = json_decode($responseBody, true);
        
        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['error'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }

        $token = new StdOAuth2Token();
        $token->setAccessToken($data['access_token']);
        // I'm invincible!!!
        $token->setEndOfLife(StdOAuth2Token::EOL_NEVER_EXPIRES);
        unset($data['access_token']);

        $token->setExtraParams($data);

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    public function requestAccessToken($code, $state = null)
    {
        if (null !== $state) {
            $this->validateAuthorizationState($state);
        }

        $bodyParams = array(
            'code'          => $code,
            'client_id'     => $this->credentials->getConsumerId(),
            'client_secret' => $this->credentials->getConsumerSecret(),
            'redirect_uri'  => $this->credentials->getCallbackUrl(),
            'grant_type'    => 'authorization_code',
        );

        $responseBody = $this->httpClient->retrieveResponse(
            $this->getAccessTokenEndpoint(),
            $bodyParams,
            $this->getExtraOAuthHeaders()
        );

        $parsedResult = $responseBody;
        
        $token = $this->parseAccessTokenResponse($parsedResult);
        $this->storage->storeAccessToken($this->service(), $token);

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    public function requestDeauthorization($user_id, $state = null)
    {
        if (null !== $state) {
            $this->validateAuthorizationState($state);
        }

        $bodyParams = array(
            'client_id'      => $this->credentials->getConsumerId(),
            'client_secret'  => $this->credentials->getConsumerSecret(),
            'stripe_user_id' => $user_id
        );

        //pr($bodyParams);

        $responseBody = $this->httpClient->retrieveResponse(
            $this->getDeauthorizationEndpoint(),
            $bodyParams,
            $this->getExtraOAuthHeaders()
        );

        $parsedResult = $responseBody;
        
        //pr($parsedResult);

        return true;
    }
}
