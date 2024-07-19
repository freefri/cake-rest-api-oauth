<?php

declare(strict_types = 1);

namespace RestOauth\Test\TestCase\Controller;

use App\Model\Table\UsersTable;
use App\Test\Fixture\UsersFixture;
use RestApi\TestSuite\ApiCommonErrorsTest;
use RestOauth\RestOauthPlugin;
use RestOauth\Test\Fixture\OauthClientsFixture;

class AuthorizeControllerTest extends ApiCommonErrorsTest
{
    protected $fixtures = [
        UsersFixture::LOAD,
        OauthClientsFixture::LOAD,
    ];


    protected function _getEndpoint(): string
    {
        return RestOauthPlugin::getRoutePath() . '/authorize/';
    }

    public function setUp(): void
    {
        parent::setUp();
        UsersTable::load();
    }

    public function testGetList_initializesTheAuthorizationCodeFlowWithPkce()
    {
        $params = [
            'response_type' => 'code',
            'client_id' => OauthClientsFixture::DASHBOARD_CLI,
            //'login_hint' => 'prefilled_email@example.com',
            //'screen_hint' => 'login_type_screen',
            'state' => 'recommended_param_to_avoid_csrf',
            'redirect_uri' => 'https://domain.com/optional/URL/to/which/Auth0/will/redirect/the/browser/after/authorization/has/been/granted',
            'code_challenge_method' => 'S256',
            'code_challenge' => 'the_code_challenge',
        ];
        $params = http_build_query($params);
        $this->get($this->_getEndpoint() . '?' . $params);

        $url = 'https://idp.example.com/path/login?login_challenge=akxUSHRqTEdJcm5oNllRVEI4TUMrSTFPaUNodGh4ajZLbnEydGJQSEVsYUk3eDcxY2NlT2xyVzZhMkxlNX';
        $this->assertRedirectContains($url);
    }
}
