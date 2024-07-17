<?php

declare(strict_types = 1);

namespace RestOauth;

use Cake\Routing\RouteBuilder;
use RestApi\Lib\RestPlugin;

class RestOauthPlugin extends RestPlugin
{
    protected function routeConnectors(RouteBuilder $builder): void
    {
        $builder->connect('/oauth/token/*', \RestOauth\Controller\OauthTokenController::route());
        $builder->connect('/authorize/*', \RestOauth\Controller\AuthorizeController::route());
        //$builder->connect('/restOauth/openapi/*', \RestOauth\Controller\SwaggerJsonController::route());
    }

    public function services(\Cake\Core\ContainerInterface $container): void
    {
        $container->addShared(\RestApi\Lib\Helpers\CookieHelper::class);// addShared means singleton
        $container->add(\RestOauth\Controller\OauthTokenController::class)
            ->addArguments([\RestApi\Lib\Helpers\CookieHelper::class, \Cake\Http\ServerRequest::class]);
    }
}
