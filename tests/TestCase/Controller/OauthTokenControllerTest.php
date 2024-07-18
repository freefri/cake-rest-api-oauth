<?php

declare(strict_types = 1);

namespace RestOauth\Test\TestCase\Controller;

use App\Model\Table\UsersTable;
use App\Test\Fixture\UsersFixture;
use RestApi\Lib\Helpers\CookieHelper;
use RestApi\Model\Table\OauthAccessTokensTable;
use RestApi\TestSuite\ApiCommonErrorsTest;
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
        $data = [
            'username' => UsersFixture::USER_ADMIN_EMAIL,
            'password' => 'passpass',
            'client_id' => OauthClientsFixture::DASHBOARD_CLI,
            'grant_type' => 'password',
            'login_challenge' => AuthorizeControllerTest::LOGIN_CHALLENGE,
        ];

        $this->post($this->_getEndpoint(), $data);

        $return = $this->assertJsonResponseOK()['data'];

        $this->assertArrayHasKey('code', $return);
        $this->assertEquals(self::REDIRECT_URL, $return['redirect_uri']);
        $this->assertEquals('recommended_param_to_avoid_csrf', $return['state']);
        $this->assertArrayHasKey('access_token', $return);
        $this->assertEquals('7206', $return['expires_in'], 'expires in seconds');
        $this->assertEquals('Bearer', $return['token_type']);
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

        $this->configRequest(['headers' => ['Accept' => 'application/json']]);
        $this->post($this->_getEndpoint(), $data);

        $this->assertJsonResponseOK();
        $return = json_decode($this->_getBodyAsString(), true)['data'];

        $this->assertArrayHasKey('access_token', $return);
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
        $codeChallenge = hash('sha256', $data['code_verifier']);
        OauthAccessTokensTable::load()
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
