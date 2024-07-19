<?php

declare(strict_types = 1);

use Cake\Cache\Cache;
use Cake\Core\Configure;
use Cake\Core\Plugin;
use Cake\Datasource\ConnectionManager;
use Cake\Log\Log;
use Cake\TestSuite\Fixture\SchemaLoader;
use function Cake\Core\env;

// Path constants to a few helpful things.
if (!defined('DS')) {
    define('DS', DIRECTORY_SEPARATOR);
}
define('ROOT', dirname(__DIR__));
define('CAKE_CORE_INCLUDE_PATH', ROOT . DS . 'vendor' . DS . 'cakephp' . DS . 'cakephp');
define('CORE_PATH', ROOT . DS . 'vendor' . DS . 'cakephp' . DS . 'cakephp' . DS);
define('CAKE', CORE_PATH . 'src' . DS);
define('TESTS', ROOT . DS . 'tests');
define('APP', ROOT . DS . 'vendor' . DS . 'freefri' . DS . 'cake-rest-api-fake-app' . DS);
define('APP_DIR', 'test_app');
define('WEBROOT_DIR', 'webroot');
define('WWW_ROOT', APP . 'webroot' . DS);
define('TMP', sys_get_temp_dir() . DS);
define('CONFIG', APP . 'config' . DS);
define('CACHE', TMP);
define('LOGS', TMP);

require_once CORE_PATH . 'config/bootstrap.php';
require_once CAKE . 'functions.php';

date_default_timezone_set('UTC');
mb_internal_encoding('UTF-8');

Configure::write('debug', true);
Configure::write('App', [
    'namespace' => 'App',
    'encoding' => 'UTF-8',
    'base' => false,
    'baseUrl' => false,
    'dir' => 'src',
    'webroot' => 'webroot',
    'www_root' => APP . 'webroot',
    'fullBaseUrl' => 'http://localhost',
    'imageBaseUrl' => 'img/',
    'jsBaseUrl' => 'js/',
    'cssBaseUrl' => 'css/',
    'paths' => [
        'plugins' => [APP . 'Plugin' . DS],
        'templates' => [APP . 'templates' . DS],
    ],
]);
Configure::write('Session', [
    'defaults' => 'php',
]);
Configure::write('RestOauthPlugin', [
    'idpDomain' => 'https://idp.example.com',
    'idpLoginFormPath' => '/path/login',
    'tokenDirectlyFromPasswordGrant' => false,
]);
Configure::write('Error', [
    'errorLevel' => E_ALL,
    'exceptionRenderer' => \RestApi\Lib\Error\ExceptionRenderer::class,
    'skipLog' => [],
    'log' => true,
    'trace' => true,
    'ignoredDeprecationPaths' => [],
]);

Cache::setConfig([
    '_cake_core_' => [
        'engine' => 'File',
        'prefix' => 'cake_core_',
        'serialize' => true,
    ],
    '_cake_model_' => [
        'engine' => 'File',
        'prefix' => 'cake_model_',
        'serialize' => true,
    ],
    'default' => [
        'engine' => 'File',
        'prefix' => 'default_',
        'serialize' => true,
    ],
    \RestApi\Model\Table\OauthAccessTokensTable::CACHE_GROUP => [
        'engine' => 'File',
        'prefix' => 'acl_',
        'serialize' => true,
    ]
]);

// Ensure default test connection is defined
if (!getenv('DATABASE_URL')) {
    putenv('DATABASE_URL=mysql://root:password@mysql:3306/phputesting');
}
ConnectionManager::setConfig('test', [
    'url' => getenv('DATABASE_URL'),
    'timezone' => 'UTC',
]);

Log::setConfig([
    'debug' => [
        'engine' => \Cake\Log\Engine\FileLog::class,
        'path' => LOGS,
        'levels' => ['notice', 'info', 'debug'],
        'file' => 'debug',
    ],
    'error' => [
        'engine' => \Cake\Log\Engine\FileLog::class,
        'path' => LOGS,
        'levels' => ['warning', 'error', 'critical', 'alert', 'emergency'],
        'file' => 'error',
    ],
]);

Plugin::getCollection()->add(new \RestOauth\RestOauthPlugin());
\RestApi\Lib\RestMigrator::runAll([
    [],
    ['plugin' => (new \RestOauth\RestOauthPlugin)->getName()]
]);


// Create test database schema
if (env('FIXTURE_SCHEMA_METADATA')) {
    $loader = new SchemaLoader();
    $loader->loadInternalFile(env('FIXTURE_SCHEMA_METADATA'), 'test');
}
