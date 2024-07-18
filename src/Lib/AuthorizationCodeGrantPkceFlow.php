<?php

declare(strict_types = 1);

namespace RestOauth\Lib;

use Cake\Http\Exception\BadRequestException;
use Cake\Http\Response;
use Cake\Http\ServerRequest;
use OAuth2\ResponseType\AuthorizationCode;
use RestApi\Lib\Helpers\CookieHelper;
use RestApi\Model\Table\OauthAccessTokensTable;

class AuthorizationCodeGrantPkceFlow
{
    public static function codeChallengeMethod(): string
    {
        return 'S256';
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
        if (!$clientId || !$codeChallenge) {
            throw new BadRequestException('Required parameter missing client_id or code_challenge');
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

    public function loginWithPassword(
        array $data,
        CookieHelper $CookieHelper,
        Response $response,
        OauthAccessTokensTable $OauthTable
    ): array {
        $clientId = $data['client_id'] ?? false;
        if (!$clientId) {
            throw new BadRequestException('Client id is mandatory');
        }
        $usr = $OauthTable->Users->checkLogin($data);

        $token = $OauthTable->createBearerToken($usr->id, $clientId, $this->_secsToExpire($data));

        $cookie = $CookieHelper
            ->writeApi2Remember($token['access_token'], $token['expires_in']);
        $response = $response->withCookie($cookie);
        list($response, $authorizationCode) = $this->getAuthorizationCode(
            $data, $CookieHelper, $response, $OauthTable, $usr->id);
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
        Response $response,
        OauthAccessTokensTable $OauthTable,
        $uid
    ): array {
        $clientId = $data['client_id'];
        $redirectUri = '';
        $state = null;
        if ($data['login_challenge'] ?? null) {
            $challenge = $CookieHelper->decryptLoginChallenge($data['login_challenge']);
            $redirectUri = $challenge['redirect'];
            $state = $challenge['state'] ?? null;
            $newCookie = ['challenge' => $challenge['challenge']];
            $cookieChallenge = $CookieHelper->writeLoginChallenge($newCookie);
            $response = $response->withCookie($cookieChallenge);
        }
        $challengeMethod = AuthorizationCodeGrantPkceFlow::codeChallengeMethod();
        $AuthorizationCode = new AuthorizationCode($OauthTable);
        $code = $AuthorizationCode->createAuthorizationCode(
            $clientId, $uid, $redirectUri, $data['scope'] ?? null, $challengeMethod);
        $toRet = [
            'code' => $code,
            'redirect_uri' => $redirectUri,
        ];
        if ($state) {
            $toRet['state'] = $state;
        }
        return [$response, $toRet];
    }

    public function authorizationCodePkceFlow(
        array $data,
        CookieHelper $Cookie,
        ServerRequest $request,
        OauthAccessTokensTable $OauthTable
    ): array {
        $challengeCookie = $Cookie->popLoginChallenge($request);
        $codeChallenge = $challengeCookie['challenge'];
        $codeVerifier = $data['code_verifier'] ?? null;
        $clientId = $data['client_id'] ?? '';
        if (!$clientId || !isset($data['code']) || !$codeVerifier) {
            throw new BadRequestException('Mandatory param is missing');
        }
        $authCode = $OauthTable->getAuthorizationCode($data['code']);
        if (!$authCode) {
            throw new BadRequestException('Invalid authorization code ' . $authCode);
        }
        $hash = hash('sha256', $codeVerifier);
        if ($codeChallenge !== $hash) {
            throw new BadRequestException('Code challenge and verifier do not match '
                . $codeChallenge . ' ' . $hash);
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
}
