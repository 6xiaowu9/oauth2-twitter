<?php

declare(strict_types=1);

/**
 * This file is part of the smolblog/oauth2-twitter library
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @copyright Copyright (c) Evan Hildreth <me@eph.me> (on behalf of the Smolblog project)
 * @license http://opensource.org/licenses/BSD BSD
 * @link https://packagist.org/packages/smolblog/oauth2-twitter Packagist
 * @link https://github.com/smolblog/oauth2-twitter GitHub
 */

namespace Smolblog\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Represents a Twitter OAuth2 service provider (authorization server).
 *
 * @link http://tools.ietf.org/html/rfc6749#section-1.1 Roles (RFC 6749, §1.1)
 */
class Twitter extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /**
     * Returns the base URL for authorizing a client.
     *
     * Eg. https://oauth.service.com/authorize
     *
     * @return string
     */
    public function getBaseAuthorizationUrl(): string
    {
        return 'https://twitter.com/i/oauth2/authorize';
    }

    protected function getPkceMethod(): string
    {
        return AbstractProvider::PKCE_METHOD_S256;
    }

    protected function getAuthorizationParameters(array $options): array
    {
        if (!isset($options['code_challenge'])) {
            $options['code_challenge'] = $this->getRandomPkceCode();
            $options['code_challenge_method'] = 'S256';
        }

        return parent::getAuthorizationParameters($options);
    }

    /**
     * Returns a prepared request for requesting an access token. Overridden
     * to add the required headers for Twitter
     *
     * @param array $params Query string parameters
     * @return RequestInterface
     */
    protected function getAccessTokenRequest(array $params): RequestInterface
    {
        $request = parent::getAccessTokenRequest($params);

        $token_string = base64_encode($this->clientId . ':' . $this->clientSecret);

        return $request->withHeader('Authorization', "Basic $token_string");
    }

    /**
     * Returns the base URL for requesting an access token.
     *
     * Eg. https://oauth.service.com/token
     *
     * @param array $params
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params): string
    {
        return 'https://api.twitter.com/2/oauth2/token';
    }

    /**
     * Returns the URL for requesting the resource owner's details.
     *
     * @param AccessToken $token
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        return 'https://api.twitter.com/2/users/me?user.fields=id,name,username,profile_image_url';
    }

    /**
     * Returns the default scopes used by this provider.
     *
     * This should only be the scopes that are required to request the details
     * of the resource owner, rather than all the available scopes.
     *
     * @return array
     */
    protected function getDefaultScopes(): array
    {
        return [
            'tweet.read',
            'users.read',
            'offline.access',
        ];
    }

    /**
     * Returns the string that should be used to separate scopes when building
     * the URL for requesting an access token.
     *
     * @return string Contains one space (` `)
     */
    protected function getScopeSeparator(): string
    {
        return ' ';
    }

    /**
     * Checks a provider response for errors.
     *
     * @throws IdentityProviderException
     * @param  ResponseInterface $response
     * @param  array|string $data Parsed response data
     * @return void
     */
    protected function checkResponse(ResponseInterface $response, $data): void
    {
        if ($response->getStatusCode() == 200) {
            return;
        }

        $error = $data['error_description'] ?? '';
        $code = $data['code'] ?? $response->getStatusCode();

        throw new IdentityProviderException($error, $code, $data);
    }

    /**
     * Generates a resource owner object from a successful resource owner
     * details request.
     *
     * @param  array $response
     * @param  AccessToken $token
     * @return TwitterUser
     */
    protected function createResourceOwner(array $response, AccessToken $token): TwitterUser
    {
        return new TwitterUser($response);
    }
}
