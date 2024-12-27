<?php

declare(strict_types = 1);

namespace RestOauth\Test\TestCase\Lib;

use App\Model\Table\UsersTable;
use Cake\TestSuite\TestCase;
use RestApi\Model\Table\OauthAccessTokensTable;
use RestOauth\Lib\AuthorizationCodeGrantPkceFlowExternal;
use RestOauth\Test\Fixture\OauthClientsFixture;

class AuthorizationCodeGrantPkceFlowExternalTest extends TestCase
{
    protected $fixtures = [
        OauthClientsFixture::LOAD,
    ];

    public function testAuthorizationCodePkceFlow_withExternalOauth()
    {
        $data = [
            'grant_type' => 'authorization_code',
            'client_id' => 'cognito_client_id',
            'code' => 'b108adf6-ceba-4776-9e4b-c5627de1b520',
            'code_verifier' => 'LuOWoeDfPc6R7~aA0c~6eCkcR_-NgDnOieA7GVDogyC',
            'redirect_uri' => 'self::REDIRECT_URL',
        ];

        $uid = 556888;
        $mockOauthTable = $this->getMockBuilder(OauthAccessTokensTable::class)
            ->onlyMethods(['createBearerToken', 'getAuthorizationCode', 'expireAuthorizationCode'])
            ->getMock();
        $mockOauthTable->expects($this->any())->method('createBearerToken')
            ->willReturn([
                'access_token' => 'mocked_access_token',
            ]);
        $mockOauthTable->expects($this->any())->method('getAuthorizationCode')
            ->willReturn([
                'user_id' => $uid,
                'redirect_uri' => $data['redirect_uri'],
                'client_id' => $data['client_id'],
                'code_challenge' => 'sOGLupIJWFmJJ92ZdHbzRuDhnQtQqhxCC5liTFeqF2s',
                'scope' => 'something offline_access else'
            ]);

        $AuthorizationFlow = new AuthorizationCodeGrantPkceFlowExternal($mockOauthTable, UsersTable::load());
        $this->expectExceptionMessage('Error with external oauth: {"error":"invalid_client"} {"grant_type":"authorization_code"');
        $token = $AuthorizationFlow->authorizationCodePkceFlow($data);

        $expected = [
            'access_token' => 'mocked_access_token',
            'refresh_token' => null,
        ];
        $this->assertEquals($expected, $token);
    }

    public function testDecodeAndVerifyJWT()
    {
        $idToken = 'eyJraWQiOiJva3FjNFU2Y21HTk4wNDRNN0tKeDdNOFo1aFNpVWxtbkMxbWtxd3RjWlBFPSIsImFsZyI6IlJTMjU2In0.eyJhdF9oYXNoIjoidEdCU19VTThzS1JFS1VaWno1U010ZyIsInN1YiI6IjczNjQ5ODcyLWUwYTEtNzAyNy1kZDJjLTBjYmYwY2MxNTUyNSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuZXUtY2VudHJhbC0xLmFtYXpvbmF3cy5jb21cL2V1LWNlbnRyYWwtMV9xbEdHd3B1ZFkiLCJjb2duaXRvOnVzZXJuYW1lIjoiNzM2NDk4NzItZTBhMS03MDI3LWRkMmMtMGNiZjBjYzE1NTI1Iiwib3JpZ2luX2p0aSI6ImE4ZjNkYjQ4LTM0YWItNGE4YS05YjkxLWEzYTYwNTZjMGQ5MSIsImF1ZCI6ImcyYmI3Y2NsaTF0MTk0OWJpbzRwMm5lbHAiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTczNTMwMzI3OSwiZXhwIjoxNzM1MzA2ODc5LCJpYXQiOjE3MzUzMDMyNzksImp0aSI6ImJmMWUyNzI4LTc3YmMtNDNjZi1iMDkzLTIxMzg3Njg4ODc5YyIsImVtYWlsIjoiYWRyaW9yZXBsYXlAZnJlZWZyaS5lcyJ9.gcnWxlp1R0-XbF69PVn-nL3iYVHVG_jW2z24zrL0QXiNzldRUFIULcMPCWMmAldjrZGccenNbrlthiPFU93330QSRPlt2yrrx7xabsxNvs6267xvMEkCJEamRFjJQ-nxXmiUBHUBdEC3iHsxZwbdBZnDY0vGSNWTb6Qo1R3KaoGYXtNcFKejbMs0RBalYlbd2KOsnWwi8majLsVe46uemOxXRvOptdlMb81nqizMhOZiMjOG8fKDSvQmGKQyDpqWEAqF6gelsVRvX9HY9NIhFBl7ZK9rI00syKFWmbSFd9RiQEPBr51cBs3dlmDRIfif1hjlj5Kf4RUiZrNCyvwpMA';
        $AuthorizationFlow = new AuthorizationCodeGrantPkceFlowExternal(OauthAccessTokensTable::load(), UsersTable::load());
        $this->expectExceptionMessage('Expired token');
        $jwt = $AuthorizationFlow->decodeAndVerifyJWT($idToken);

        $this->assertEquals('73649872-e0a1-7027-dd2c-0cbf0cc15525', $jwt['sub']);
        $this->assertStringStartsWith('adrioreplay@', $jwt['email']);
    }
}
