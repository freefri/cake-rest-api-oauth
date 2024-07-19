<?php

declare(strict_types = 1);

namespace RestOauth\Test\TestCase\Lib;

use App\Model\Table\UsersTable;
use Cake\Core\Configure;
use Cake\Http\Response;
use Cake\I18n\FrozenTime;
use Cake\TestSuite\TestCase;
use RestApi\Lib\Helpers\CookieHelper;
use RestApi\Model\Table\OauthAccessTokensTable;
use RestOauth\Lib\AuthorizationCodeGrantPkceFlow;
use RestOauth\Test\Fixture\OauthClientsFixture;

class AuthorizationCodeGrantPkceFlowTest extends TestCase
{
    protected $fixtures = [
        OauthClientsFixture::LOAD,
    ];

    private function _loginWithPasswordToArray()
    {
        $data = [
            'username' => 'UsersFixture::EMAIL',
            'password' => 'passpass',
            'client_id' => OauthClientsFixture::DASHBOARD_CLI,
            'grant_type' => 'password',
            'login_challenge' => 'mocked_OauthTokenControllerTest::LOGIN_CHALLENGE',
            'scope' => 'custom_test_scope',
        ];

        $mockCookieHelper = $this->createMock(CookieHelper::class);
        $mockCookieHelper->expects($this->once())->method('decryptLoginChallenge')
            ->willReturn([
                'challenge' => hash('sha256', 'mocked_code_verifier'),
                'redirect' => 'mocked_redirect',
                'state' => 'mocked_state',
                'expires' => new FrozenTime('+2minutes'),
            ]);
        $mockUsersTable = $this->getMockBuilder(UsersTable::class)
            ->getMock();

        $uid = 658954;
        $mockUsersTable->expects($this->once())
            ->method('checkLogin')
            ->willReturn((object)['id' => $uid]);
        $mockOauthTable = $this->getMockBuilder(OauthAccessTokensTable::class)
            ->onlyMethods(['createBearerToken'])
            ->getMock();
        $mockOauthTable->expects($this->once())->method('createBearerToken')
            ->willReturn([
                'access_token' => 'mocked_access_token',
                'expires_in' => '7200',
            ]);
        $mockOauthTable->Users = $mockUsersTable;
        $response = new Response();

        $AuthorizationFlow = new AuthorizationCodeGrantPkceFlow($mockOauthTable);
        list($response, $token) = $AuthorizationFlow->loginWithPasswordToArray($data, $mockCookieHelper, $response);
        return $token;
    }

    public function testLoginWithPassword()
    {
        $token = $this->_loginWithPasswordToArray();

        $this->assertEquals(['code', 'redirect_uri', 'state'], array_keys($token));
        $this->assertEquals('mocked_redirect', $token['redirect_uri']);
        $this->assertEquals('mocked_state', $token['state']);
        $this->assertArrayHasKey('code', $token);
    }

    public function testLoginWithPassword_notAllowedForClient()
    {

        $token = $this->_loginWithPasswordToArray();

        $this->assertEquals(['code', 'redirect_uri', 'state'], array_keys($token));
        $this->assertEquals('mocked_redirect', $token['redirect_uri']);
        $this->assertEquals('mocked_state', $token['state']);
        $this->assertArrayHasKey('code', $token);
    }

    public function testLoginWithPassword_andReturningAccessToken()
    {
        Configure::write('RestOauthPlugin.tokenDirectlyFromPasswordGrant', true);
        $token = $this->_loginWithPasswordToArray();
        Configure::write('RestOauthPlugin.tokenDirectlyFromPasswordGrant', false);

        $this->assertEquals(['access_token', 'expires_in', 'code', 'redirect_uri', 'state'], array_keys($token));
        $this->assertEquals('mocked_access_token', $token['access_token']);
        $this->assertEquals('7200', $token['expires_in'], 'expires in seconds');
        $this->assertEquals('mocked_redirect', $token['redirect_uri']);
        $this->assertEquals('mocked_state', $token['state']);
        $this->assertArrayHasKey('code', $token);
    }

    public function testAuthorizationCodePkceFlow()
    {
        $data = [
            'grant_type' => 'authorization_code',
            'client_id' => OauthClientsFixture::DASHBOARD_CLI,
            'code' => 'fake_test_authorization_code',
            'code_verifier' => 'test_verifier_code',
            'redirect_uri' => 'self::REDIRECT_URL',
            'scope' => 'offline_access'
        ];

        $uid = 556888;
        $mockOauthTable = $this->getMockBuilder(OauthAccessTokensTable::class)
            ->onlyMethods(['createBearerToken', 'getAuthorizationCode', 'expireAuthorizationCode'])
            ->getMock();
        $mockOauthTable->expects($this->once())->method('createBearerToken')
            ->willReturn([
                'access_token' => 'mocked_access_token',
            ]);
        $mockOauthTable->expects($this->once())->method('getAuthorizationCode')
            ->willReturn([
                'user_id' => $uid,
                'redirect_uri' => $data['redirect_uri'],
                'client_id' => $data['client_id'],
                'code_challenge' => 'b0e18bba920958598927dd997476f346e0e19d0b50aa1c420b99624c57aa176b',
                'scope' => 'something offline_access else'
            ]);

        $AuthorizationFlow = new AuthorizationCodeGrantPkceFlow($mockOauthTable);
        $token = $AuthorizationFlow->authorizationCodePkceFlow($data);

        $expected = [
            'access_token' => 'mocked_access_token',
            'refresh_token' => null,
        ];
        $this->assertEquals($expected, $token);
    }
}
