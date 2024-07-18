<?php

declare(strict_types = 1);

namespace RestOauth\Lib;

use Cake\Http\Exception\BadRequestException;
use Cake\Http\Exception\UnauthorizedException;
use Cake\Http\Response;
use Cake\Http\ServerRequest;
use OAuth2\ResponseType\AuthorizationCode;
use RestApi\Lib\Exception\DetailedException;
use RestApi\Lib\Helpers\CookieHelper;
use RestApi\Model\Table\OauthAccessTokensTable;

class AuthorizationCodeGrantPkceFlow
{
    public static function codeChallengeMethod(): string
    {
        return 'S256';
    }

    public function buildUrl(string $domain, string $path, array $queryParams): string
    {
        $sep = str_contains($path, '?') ? '&' : '?';
        return $domain . $path . $sep . http_build_query($queryParams);
    }

    public function getLoginChallenge(ServerRequest $request): string
    {
        $responseType = $request->getQuery('response_type');
        $clientId = $request->getQuery('client_id');
        $state = $request->getQuery('state');// recommended
        /** @var string $redirectUri Optional. The URL to redirect after authorization has been granted */
        $redirectUri = $request->getQuery('redirect_uri');
        $codeChallengeMethod = $request->getQuery('code_challenge_method');
        $codeChallenge = $request->getQuery('code_challenge');
        if (!$responseType || strtolower($responseType) !== 'code') {
            throw new BadRequestException('Only Authorization Code Grant (PKCE) Flow is allowed');
        }
        if ($codeChallengeMethod !== $this->codeChallengeMethod()) {
            throw new BadRequestException('Only S256 challenge method is allowed');
        }
        $this->_validateClientId($clientId);
        if (!$codeChallenge) {
            throw new BadRequestException('Required parameter missing code_challenge');
        }
        return $this->computeLoginChallenge($codeChallenge, $redirectUri, $state);
    }

    protected function computeLoginChallenge(string $codeChallenge, string $redirectUri, string $state = null): string
    {
        $Cookie = new CookieHelper();
        $storedValue = [
            'challenge' => $codeChallenge,
            'redirect' => $redirectUri,
            'state' => $state,
        ];
        $cookie = $Cookie->writeLoginChallenge($storedValue, 5);
        return $cookie->read();
    }

    public function loginWithPasswordToRedirect(
        array $data,
        CookieHelper $CookieHelper,
        Response $response,
        OauthAccessTokensTable $OauthTable
    ): array {
        if (!($data['login_challenge'] ?? null)) {
            throw new DetailedException('Missing required parameter "login_challenge"');
        }
        try {
            /** @var Response $response */
            list($response, $return) = $this->loginWithPasswordToArray($data, $CookieHelper, $response, $OauthTable);
            $params = [
                'state' => $return['state'],
                'code' => $return['code'],
            ];
            return [$response, $this->buildUrl($this->_getRedirectUri($return['redirect_uri']), '', $params)];
        } catch (UnauthorizedException $e) {
            $params = [
                'error_status' => $e->getCode(),
                'error' => 'invalid_grant',
                'error_description' => 'Invalid username and password'
            ];
        } catch (DetailedException $e) {
            $params = [
                'error_status' => $e->getCode(),
                'error' => 'invalid_request',
                'error_description' => $e->getMessage()
            ];
            throw $e;
        }
        $challenge = $CookieHelper->decryptLoginChallenge(urldecode($data['login_challenge']));
        return [$response, $this->buildUrl($this->_getRedirectUri($challenge['redirect']), '', $params)];
    }

    public function loginWithPasswordToArray(
        array $data,
        CookieHelper $CookieHelper,
        Response $response,
        OauthAccessTokensTable $OauthTable
    ): array {
        $clientId = $data['client_id'] ?? false;
        $this->_validateClientId($clientId);
        $usr = $OauthTable->Users->checkLogin($data);

        $token = $OauthTable->createBearerToken($usr->id, $clientId, $this->_secsToExpire($data));

        $cookie = $CookieHelper
            ->writeApi2Remember($token['access_token'], $token['expires_in']);
        $response = $response->withCookie($cookie);
        $authorizationCode = $this->getAuthorizationCode(
            $data, $CookieHelper, $OauthTable, $usr->id);
        return [$response, array_merge($token, $authorizationCode)];
    }

    protected function _secsToExpire($data)
    {
        $hasRemember = $data['remember_me'] ?? false;
        $hours = 60 * 60;
        if ($hasRemember) {
            return 48 * $hours + 6;//172806
        } else {
            return 2 * $hours + 6;//7206
        }
    }

    protected function getAuthorizationCode(
        array $data,
        CookieHelper $CookieHelper,
        OauthAccessTokensTable $OauthTable,
        $uid
    ): array {
        $clientId = $data['client_id'];
        $this->_validateClientId($clientId);
        $redirectUri = '';
        $codeChallenge = null;
        $state = null;
        if ($data['login_challenge'] ?? null) {
            $challenge = $CookieHelper->decryptLoginChallenge(urldecode($data['login_challenge']));
            $redirectUri = $challenge['redirect'];
            $state = $challenge['state'] ?? null;
            $codeChallenge = $challenge['challenge'];
        }
        $challengeMethod = AuthorizationCodeGrantPkceFlow::codeChallengeMethod();
        $AuthorizationCode = new AuthorizationCode($OauthTable);
        $code = $AuthorizationCode->createAuthorizationCode(
            $clientId, $uid, $redirectUri, $data['scope'] ?? null, $codeChallenge, $challengeMethod);
        $toRet = [
            'code' => $code,
            'redirect_uri' => $redirectUri,
        ];
        if ($state) {
            $toRet['state'] = $state;
        }
        return $toRet;
    }

    public function authorizationCodePkceFlow(
        array $data,
        OauthAccessTokensTable $OauthTable
    ): array {
        $codeVerifier = $data['code_verifier'] ?? null;
        $clientId = $data['client_id'] ?? '';
        $this->_validateClientId($clientId);
        if (!isset($data['code']) || !$codeVerifier) {
            throw new BadRequestException('Mandatory param is missing');
        }
        $authCode = $OauthTable->getAuthorizationCode($data['code']);
        if (!$authCode) {
            throw new BadRequestException('Invalid authorization code ' . $authCode);
        }
        $hash = hash('sha256', $codeVerifier);
        $codeChallenge = $authCode['code_challenge'] ?? null;
        if ($codeChallenge !== $hash) {
            throw new BadRequestException('Code challenge and verifier do not match '
                . $codeChallenge . ' -> ' . $hash);
        }
        $redirectUri = $data['redirect_uri'] ?? '';
        if ($redirectUri !== ($authCode['redirect_uri'] ?? '')) {
            throw new BadRequestException('Redirect uri must be the same');
        }
        if ($clientId !== $authCode['client_id']) {
            throw new BadRequestException('Client ID must be the same');
        }

        $token = $OauthTable->createBearerToken($authCode['user_id'], $clientId, $this->_secsToExpire($data));
        $OauthTable->expireAuthorizationCode($data['code']);
        if (str_contains($authCode['scope'] ?? null, 'offline_access')) {
            $token['refresh_token'] = null;
        }
        return $token;
    }

    private function _validateClientId($clientId): void
    {
        if (!$clientId) {
            throw new BadRequestException('Client id is mandatory');
        }
    }

    private function _getRedirectUri($redirect_uri)
    {
        $url = $redirect_uri;
        if (!$url) {
            $url = env('HTTP_REFERER');
        }
        return $url;
    }
}
