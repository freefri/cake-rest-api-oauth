<?php

declare(strict_types = 1);

namespace RestOauth\Controller;

use App\Controller\ApiController;
use Cake\Core\Configure;
use Cake\Http\Exception\BadRequestException;
use RestOauth\Lib\AuthorizationCodeGrantPkceFlow;

class AuthorizeController extends ApiController
{
    public function isPublicController(): bool
    {
        return true;
    }

    protected function getList()
    {
        $AuthorizationFlow = new AuthorizationCodeGrantPkceFlow();
        $queryParams = [
            'login_challenge' => $AuthorizationFlow->getLoginChallenge($this->getRequest()),
        ];
        $path = Configure::read('RestOauthPlugin.idpLoginFormPath', '/idp/login');
        $redirect = $AuthorizationFlow->buildUrl($this->_getIdpDomain(), $path, $queryParams);
        $this->redirect($redirect);
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
}
