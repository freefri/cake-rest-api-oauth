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

    public function testGetList_initializesTheAuthorizationCodeFlowWithPkceUsingCognito()
    {
        $params = [
            '/api/v1/authorize' => '',
            'response_type' => 'code',
            'client_id' => 'cognito_client_id',
            'state' => 'recommended_param_to_avoid_csrf',
            'redirect_uri' => 'https://domain.com/optional/URL/to/which/Auth0/will/redirect/the/browser/after/authorization/has/been/granted',
            'code_challenge_method' => 'S256',
            'code_challenge' => 'the_code_challenge',
        ];
        $params = http_build_query($params);
        $this->get($this->_getEndpoint() . '?' . $params);

        $url = 'https://eu-central-1qlggwpudy.auth.eu-central-1.amazoncognito.com/login?response_type=code&client_id=cognito_client_id&state=recommended_param_to_avoid_csrf&redirect_uri=https%3A%2F%2Fdomain.com%2Foptional%2FURL%2Fto%2Fwhich%2FAuth0%2Fwill%2Fredirect%2Fthe%2Fbrowser%2Fafter%2Fauthorization%2Fhas%2Fbeen%2Fgranted&code_challenge_method=S256&code_challenge=the_code_challenge';
        $this->assertRedirectContains($url);
    }
}
