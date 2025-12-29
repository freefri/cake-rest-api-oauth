<?php

declare(strict_types = 1);

namespace RestOauth\Controller;

use App\Controller\ApiController;
use Cake\Controller\ComponentRegistry;
use Cake\Core\Configure;
use Cake\Event\EventManagerInterface;
use Cake\Http\Exception\BadRequestException;
use Cake\Http\Exception\NotImplementedException;
use Cake\Http\Response;
use Cake\Http\ServerRequest;
use RestApi\Lib\Helpers\CookieHelper;
use RestApi\Model\Table\OauthAccessTokensTable;
use RestOauth\Lib\AuthorizationCodeGrantPkceFlow;

class AuthorizeController extends ApiController
{
    public CookieHelper $CookieHelper;
    private AuthorizationCodeGrantPkceFlow $AuthFlow;

    public function isPublicController(): bool
    {
        return true;
    }

    public function __construct(
        $cookieHelper,
        ?ServerRequest $request = null,
        ?Response $response = null,
        ?string $name = null,
        ?EventManagerInterface $eventManager = null,
        ?ComponentRegistry $components = null
    ) {
        $this->CookieHelper = $cookieHelper;
        parent::__construct($request, $response, $name, $eventManager, $components);
    }

    public function initialize(): void
    {
        parent::initialize();
        $this->AuthFlow = new AuthorizationCodeGrantPkceFlow(OauthAccessTokensTable::load());
    }

    protected function getList()
    {
        $redirectUrl = $this->_getExternalRedirect($this->getRequest()->getQueryParams());
        if ($redirectUrl) {
            return $this->redirect($redirectUrl);
        }

        $loginChallenge = $this->AuthFlow->getLoginChallenge($this->getRequest());
        $queryParams = [
            'login_challenge' => $loginChallenge,
        ];
        $accessTokenFromCookie = $this->CookieHelper->readApi2Remember($this->getRequest());
        if ($accessTokenFromCookie) {
            $queryParams = $this->_getAuthorizationCodeIfLoggedIn($accessTokenFromCookie, $loginChallenge);
            $redirectUri = $queryParams['redirect_uri'] ?? '';
            unset($queryParams['redirect_uri']);
            if ($redirectUri) {
                return $this->redirect($this->AuthFlow->buildUrl($redirectUri, '', $queryParams));
            } else {
                throw new NotImplementedException('Login without redirect_uri is not implemented');
            }
        }

        $path = Configure::read('RestOauthPlugin.idpLoginFormPath', '/idp/login');
        $redirect = $this->AuthFlow->buildUrl($this->_getIdpDomain(), $path, $queryParams);
        return $this->redirect($redirect);
    }

    private function _getExternalRedirect(array $queryParams): ?string
    {
        $cognitoClientId = Configure::read('RestOauthPlugin.externalOauth.clientId');
        $redirectUrl = null;
        if (($queryParams['client_id'] ?? null) === $cognitoClientId) {
            foreach ($queryParams as $param => $value) {
                if (!$value) {
                    unset($queryParams[$param]);
                }
            }
            $redirectUrl = Configure::read('RestOauthPlugin.externalOauth.loginUrl');
            $redirectUrl .= '?' . http_build_query($queryParams);
        }
        return $redirectUrl;
    }

    private function _getIdpDomain(): string
    {
        $domain = Configure::read('RestOauthPlugin.idpDomain');
        if (!$domain) {
            $domain = substr(env('HTTP_REFERER', '/'), 0, -1);
            $allowedCors = Configure::read('App.Cors.AllowOrigin', []);
            if (!in_array($domain, $allowedCors)) {
                throw new BadRequestException('Domain not allowed in Cors, better use RestOauthPlugin.idpDomain');
            }
        }
        return $domain;
    }

    private function _getAuthorizationCodeIfLoggedIn(string $accessTokenFromCookie, string $loginChallenge): array
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $accessTokenFromCookie;
        $userId = $this->getLocalOauth()->verifyAuthorizationAndGetToken()->getUserId();

        $req = $this->getRequest();
        $data = [
            'client_id' => $req->getQuery('client_id'),
            'login_challenge' => $loginChallenge,
            'scope' => $req->getQuery('scope'),
        ];
        return $this->AuthFlow->getAuthorizationCode($data, new CookieHelper(), $userId);
    }
}
