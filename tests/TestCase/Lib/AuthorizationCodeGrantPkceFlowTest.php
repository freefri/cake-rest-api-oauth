<?php

declare(strict_types = 1);

namespace RestOauth\Test\TestCase\Lib;

use App\Model\Table\UsersTable;
use Cake\Http\Response;
use Cake\Http\ServerRequest;
use Cake\TestSuite\TestCase;
use RestApi\Lib\Helpers\CookieHelper;
use RestApi\Model\Table\OauthAccessTokensTable;
use RestOauth\Lib\AuthorizationCodeGrantPkceFlow;

class AuthorizationCodeGrantPkceFlowTest extends TestCase
{
    public function testLoginWithPassword()
    {
        $data = [
            'username' => 'UsersFixture::EMAIL',
            'password' => 'passpass',
            'client_id' => 'OauthClientsFixture::DASHBOARD_CLI',
            'grant_type' => 'password',
            'login_challenge' => 'AuthorizeControllerTest::LOGIN_CHALLENGE',
            'scope' => 'custom_test_scope',
        ];

        $mockCookieHelper = $this->createMock(CookieHelper::class);
        $mockCookieHelper->expects($this->once())->method('decryptLoginChallenge')
            ->willReturn([
                'challenge' => hash('sha256', 'mocked_code_verifier'),
                'redirect' => 'mocked_redirect',
                'state' => 'mocked_state',
            ]);
        $mockUsersTable = $this->getMockBuilder(UsersTable::class)
            ->getMock();

        $uid = 658954;
        $mockUsersTable->expects($this->once())
            ->method('checkLogin')
            ->willReturn((object)['id' => $uid]);
        $mockOauthTable = $this->createMock(OauthAccessTokensTable::class);
        $mockOauthTable->expects($this->once())->method('createBearerToken')
            ->willReturn([
                'access_token' => 'mocked_access_token',
                'expires_in' => '7200',
            ]);
        $mockOauthTable->Users = $mockUsersTable;
        $response = new Response();

        $AuthorizationFlow = new AuthorizationCodeGrantPkceFlow();
        list($response, $token) = $AuthorizationFlow->loginWithPassword($data, $mockCookieHelper, $response, $mockOauthTable);

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
            'client_id' => 'OauthClientsFixture::DASHBOARD_CLI',
            'code' => 'fake_test_authorization_code',
            'code_verifier' => 'test_verifier_code',
            'redirect_uri' => 'self::REDIRECT_URL',
            'scope' => 'offline_access'
        ];

        $mockCookieHelper = $this->createMock(CookieHelper::class);
        $mockCookieHelper->expects($this->once())->method('popLoginChallenge')
            ->willReturn([
                'challenge' => hash('sha256', $data['code_verifier']),
                'redirect' => 'mocked_redirect',
                'state' => 'mocked_state',
            ]);
        $uid = 556888;
        $mockOauthTable = $this->createMock(OauthAccessTokensTable::class);
        $mockOauthTable->expects($this->once())->method('createBearerToken')
            ->willReturn([
                'access_token' => 'mocked_access_token',
            ]);
        $mockOauthTable->expects($this->once())->method('getAuthorizationCode')
            ->willReturn([
                'user_id' => $uid,
                'redirect_uri' => $data['redirect_uri'],
                'client_id' => $data['client_id'],
                'scope' => 'something offline_access else'
            ]);
        $request = new ServerRequest();

        $AuthorizationFlow = new AuthorizationCodeGrantPkceFlow();
        $token = $AuthorizationFlow->authorizationCodePkceFlow($data, $mockCookieHelper, $request, $mockOauthTable);

        $expected = [
            'access_token' => 'mocked_access_token',
            'refresh_token' => null,
        ];
        $this->assertEquals($expected, $token);
    }
}
