<?php

declare(strict_types = 1);

namespace RestOauth\Lib;

use Cake\Core\Configure;
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
    private OauthAccessTokensTable $OauthTable;

    public function __construct(OauthAccessTokensTable $OauthTable)
    {
        $this->OauthTable = $OauthTable;
    }

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
        $loginChallenge = new LoginChallenge($codeChallenge, $redirectUri, $state);
        return $loginChallenge->computeLoginChallenge();
    }

    public function loginWithPasswordToRedirect(array $data, CookieHelper $CookieHelper, Response $response): array
    {
        if (!($data['login_challenge'] ?? null)) {
            throw new DetailedException('Missing required parameter "login_challenge"');
        }
        try {
            /** @var Response $response */
            list($response, $return) = $this->loginWithPasswordToArray($data, $CookieHelper, $response);
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
        $challenge = LoginChallenge::decrypt($data['login_challenge'], $CookieHelper);
        return [$response, $this->buildUrl($this->_getRedirectUri($challenge['redirect']), '', $params)];
    }

    public function loginWithPasswordToArray(array $data, CookieHelper $CookieHelper, Response $response): array
    {
        $clientId = $data['client_id'] ?? false;
        $this->_validateClientId($clientId, $data['grant_type'] ?? null);
        $usr = $this->OauthTable->Users->checkLogin($data);

        $token = $this->OauthTable->createBearerToken($usr->id, $clientId, $this->_secsToExpire($data));

        $cookie = $CookieHelper
            ->writeApi2Remember($token['access_token'], $token['expires_in']);
        $response = $response->withCookie($cookie);
        $authorizationCode = $this->getAuthorizationCode($data, $CookieHelper, $usr->id);
        if (Configure::read('RestOauthPlugin.tokenDirectlyFromPasswordGrant') && !isset($data['login_challenge'])) {
            // it is insecure to return the auth $token directly here (only the $authorizationCode)
            $toRet = array_merge($token, $authorizationCode);
        } else {
            $toRet = $authorizationCode;
        }
        return [$response, $toRet];
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

    public function getAuthorizationCode(array $data, CookieHelper $CookieHelper, $uid): array
    {
        $clientId = $data['client_id'];
        $this->_validateClientId($clientId, 'authorization_code');
        $redirectUri = '';
        $codeChallenge = null;
        $state = null;
        if ($data['login_challenge'] ?? null) {
            $challenge = LoginChallenge::decrypt($data['login_challenge'], $CookieHelper);
            $redirectUri = $challenge['redirect'];
            $state = $challenge['state'] ?? null;
            $codeChallenge = $challenge['challenge'];
        }
        $challengeMethod = AuthorizationCodeGrantPkceFlow::codeChallengeMethod();
        $AuthorizationCode = new AuthorizationCode($this->OauthTable);
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

    public function verifyChallenge(string $codeVerifier): string
    {
        return strtr(rtrim(base64_encode(hash('sha256', $codeVerifier, true)), '='), '+/', '-_');
    }

    public function authorizationCodePkceFlow(array $data): array
    {
        $codeVerifier = $data['code_verifier'] ?? null;
        $clientId = $data['client_id'] ?? '';
        $this->_validateClientId($clientId, $data['grant_type'] ?? null);
        if (!isset($data['code']) || !$codeVerifier) {
            throw new BadRequestException('Mandatory param is missing');
        }
        $authCode = $this->OauthTable->getAuthorizationCode($data['code']);
        $this->OauthTable->expireAuthorizationCode($data['code']);
        if (!$authCode) {
            throw new BadRequestException('Invalid authorization code ' . $data['code'] . ' -> ' . $authCode);
        }
        $storedCodeChallenge = $authCode['code_challenge'] ?? null;
        $hash = $this->verifyChallenge($codeVerifier);
        if ($storedCodeChallenge !== $hash) {
            throw new BadRequestException('Code challenge and verifier do not match '
                . $storedCodeChallenge . ' -> ' . $hash);
        }
        $redirectUri = $data['redirect_uri'] ?? '';
        if ($redirectUri !== ($authCode['redirect_uri'] ?? '')) {
            throw new BadRequestException('Redirect uri must be the same');
        }
        if ($clientId != $authCode['client_id']) {
            throw new BadRequestException('Client ID must be the same ' . $authCode['client_id'] . ' - ' . $clientId);
        }

        $token = $this->OauthTable->createBearerToken($authCode['user_id'], $clientId, $this->_secsToExpire($data));
        $this->OauthTable->expireAuthorizationCode($data['code']);
        if (str_contains($authCode['scope'] ?? null, 'offline_access')) {
            $token['refresh_token'] = null;
        }
        return $token;
    }

    private function _validateClientId($clientId, string $grantType = null): void
    {
        if (!$clientId) {
            throw new BadRequestException('Client id is mandatory');
        }
        $client = $this->OauthTable->getClientDetails($clientId);
        if (!$client) {
            throw new BadRequestException('Invalid client_id ' . $clientId);
        }
        $grantTypes = $client['grant_types'] ?? null;
        if ($grantTypes !== null && $grantType !== null) {
            if (!str_contains($grantTypes, $grantType)) {
                throw new BadRequestException('The client_id does not allow this grant_type');
            }
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
