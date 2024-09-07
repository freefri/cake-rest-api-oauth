<?php

declare(strict_types = 1);

namespace RestOauth\Test\TestCase\Controller;

use App\Model\Table\UsersTable;
use App\Test\Fixture\UsersFixture;
use Cake\Core\Configure;
use RestApi\Lib\Helpers\CookieHelper;
use RestApi\Model\Table\OauthAccessTokensTable;
use RestApi\TestSuite\ApiCommonErrorsTest;
use RestOauth\Lib\AuthorizationCodeGrantPkceFlow;
use RestOauth\Lib\LoginChallenge;
use RestOauth\RestOauthPlugin;
use RestOauth\Test\Fixture\OauthClientsFixture;

class OauthTokenControllerTest extends ApiCommonErrorsTest
{
    protected $fixtures = [
        UsersFixture::LOAD,
        OauthClientsFixture::LOAD,
    ];

    private const REDIRECT_URL = 'https://domain.com/optional/URL/to/which/Auth0/will/redirect/the/browser/after/authorization/has/been/granted';

    protected function _getEndpoint(): string
    {
        return RestOauthPlugin::getRoutePath() . '/oauth/token/';
    }

    public function setUp(): void
    {
        parent::setUp();
        UsersTable::load();
    }

    public function testAddNew_login()
    {
        $uri = 'https://domain.com/optional/URL/to/which/Auth0/will/redirect/the/browser/after/authorization/has/been/granted';
        $challenge = new LoginChallenge('the_code_challenge', $uri, 'recommended_param_to_avoid_csrf');
        $data = [
            'username' => UsersFixture::USER_ADMIN_EMAIL,
            'password' => 'passpass',
            'client_id' => OauthClientsFixture::DASHBOARD_CLI,
            'grant_type' => 'password',
            'login_challenge' => $challenge->computeLoginChallenge(),
        ];

        $this->configRequest(['headers' => ['Accept' => 'application/json']]);
        $this->post($this->_getEndpoint(), $data);

        $return = $this->assertJsonResponseOK()['data'];

        $this->assertEquals(['code', 'redirect_uri', 'state'], array_keys($return));
        $this->assertEquals(self::REDIRECT_URL, $return['redirect_uri']);
        $this->assertEquals('recommended_param_to_avoid_csrf', $return['state']);
    }

    public function testAddNew_loginShouldRememberMe()
    {
        $data = [
            'username' => UsersFixture::USER_ADMIN_EMAIL,
            'password' => 'passpass',
            'client_id' => OauthClientsFixture::DASHBOARD_CLI,
            'grant_type' => 'password',
            'remember_me' => true,
        ];

        Configure::write('RestOauthPlugin.tokenDirectlyFromPasswordGrant', true);
        $this->configRequest(['headers' => ['Accept' => 'application/json']]);
        $this->post($this->_getEndpoint(), $data);
        Configure::write('RestOauthPlugin.tokenDirectlyFromPasswordGrant', false);

        $this->assertJsonResponseOK();
        $return = json_decode($this->_getBodyAsString(), true)['data'];

        $this->assertEquals(['access_token', 'expires_in', 'token_type', 'scope', 'code', 'redirect_uri'], array_keys($return));
        $this->assertEquals('172806', $return['expires_in'], 'expires in seconds');
        $this->assertEquals('Bearer', $return['token_type']);
    }

    public function testAddNew_loginShouldExceptionWithInvalidPayload()
    {
        $data = [
            'username' => UsersFixture::USER_ADMIN_EMAIL,
            'password' => 'passpass',
            'client_id' => OauthClientsFixture::DASHBOARD_CLI,
        ];

        $this->post($this->_getEndpoint(), $data);

        $this->assertResponseError();
        $return = json_decode($this->_getBodyAsString(), true);

        $this->assertEquals('Invalid grant_type', $return['message']);
    }

    public function testAddNew_authorizationCodePkceFlow()
    {
        $data = [
            'grant_type' => 'authorization_code',
            'client_id' => OauthClientsFixture::DASHBOARD_CLI,
            'code' => 'fake_test_authorization_code',
            'code_verifier' => 'test_verifier_code',
            'redirect_uri' => self::REDIRECT_URL,
            'scope' => 'offline_access'
        ];
        $OauthAccessTokensTable = OauthAccessTokensTable::load();
        $flow = new AuthorizationCodeGrantPkceFlow($OauthAccessTokensTable);
        $codeChallenge = $flow->verifyChallenge($data['code_verifier']);
        $OauthAccessTokensTable
            ->setAuthorizationCode(
                $data['code'], $data['client_id'], 50, $data['redirect_uri'],
                time() + 30, 'something offline_access', null, $codeChallenge);
        $mock = $this->createMock(CookieHelper::class);
        $this->mockService(CookieHelper::class, function () use ($mock) {
            return $mock;
        });

        $this->post($this->_getEndpoint(), $data);

        $return = $this->assertJsonResponseOK()['data'];
        $this->assertArrayHasKey('access_token', $return);
        $this->assertEquals('7206', $return['expires_in'], 'expires in seconds');
        $this->assertEquals('Bearer', $return['token_type']);
        $this->assertEquals(null, $return['refresh_token']);

        $db = OauthAccessTokensTable::load()->getAuthorizationCode($data['code']);
        $this->assertFalse($db);
    }

    public function testDelete_shouldLogoutWhenSendingCurrentAsEntityId()
    {
        $this->delete($this->_getEndpoint() . 'current');
        $this->assertResponseCode(204);
    }
}
