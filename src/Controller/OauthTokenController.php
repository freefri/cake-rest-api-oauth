<?php

declare(strict_types = 1);

namespace RestOauth\Controller;

use App\Controller\ApiController;
use App\Model\Table\UsersTable;
use Cake\Controller\ComponentRegistry;
use Cake\Core\Configure;
use Cake\Event\EventManagerInterface;
use Cake\Http\Exception\BadRequestException;
use Cake\Http\Response;
use Cake\Http\ServerRequest;
use RestApi\Lib\Helpers\CookieHelper;
use RestApi\Model\Table\OauthAccessTokensTable;
use RestOauth\Lib\AuthorizationCodeGrantPkceFlow;
use RestOauth\Lib\AuthorizationCodeGrantPkceFlowExternal;

/**
 * @property OauthAccessTokensTable $OauthAccessTokens
 */
class OauthTokenController extends ApiController
{
    public CookieHelper $CookieHelper;

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
        $this->OauthAccessTokens = OauthAccessTokensTable::load();
    }

    public function isPublicController(): bool
    {
        return true;
    }

    protected function addNew($data)
    {
        $externalClientId = Configure::read('RestOauthPlugin.externalOauth.clientId');
        if ($externalClientId && ($data['client_id'] ?? '') == $externalClientId) {
            /** @var UsersTable $usersTable */
            $usersTable = UsersTable::load();
            $AuthorizationFlow = new AuthorizationCodeGrantPkceFlowExternal($this->OauthAccessTokens, $usersTable);
        } else {
            $skipInternalLogin = Configure::read('RestOauthPlugin.skipInternalLogin');
            if ($skipInternalLogin) {
                throw new BadRequestException('Internal login is not enabled');
            }
            $AuthorizationFlow = new AuthorizationCodeGrantPkceFlow($this->OauthAccessTokens);
        }
        switch ($data['grant_type'] ?? null) {
            case 'password':
                $this->_logoutCookie();
                $acceptHeader = $this->getRequest()->getHeader('Accept')[0] ?? '';
                if ($acceptHeader === 'application/json') {
                    list($this->response, $this->return) = $AuthorizationFlow->loginWithPasswordToArray(
                        $data, $this->CookieHelper, $this->response);
                } else {
                    list($this->response, $redirect) = $AuthorizationFlow->loginWithPasswordToRedirect(
                        $data, $this->CookieHelper, $this->response);
                    $this->redirect($redirect);
                }
                break;
            case 'authorization_code':
                $this->return = $AuthorizationFlow->authorizationCodePkceFlow($data);
                break;
            default:
                throw new BadRequestException('Invalid grant_type');
        }
    }

    protected function delete($id)
    {
        $accessToken = $this->_logoutCookie();
        if ($id !== 'current') {
            $accessToken = $id;
        }
        if ($accessToken) {
            $this->OauthAccessTokens->expireAccessToken($accessToken);
        }
        $this->return = false;
    }

    private function _logoutCookie()
    {
        $res = $this->CookieHelper->popApi2Remember($this->getRequest());
        $this->response = $this->response->withCookie($this->CookieHelper->cookie);
        return $res;
    }
}
