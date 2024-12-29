<?php

declare(strict_types = 1);

namespace RestOauth\Lib;

use App\Model\Table\UsersTable;
use Cake\Core\Configure;
use Cake\Http\Client;
use Cake\Http\Exception\BadRequestException;
use Cake\Http\Exception\InternalErrorException;
use \Firebase\JWT;
use RestApi\Model\Table\OauthAccessTokensTable;

class AuthorizationCodeGrantPkceFlowExternal
{
    private OauthAccessTokensTable $OauthTable;
    private UsersTable $UsersTable;

    public function __construct(OauthAccessTokensTable $OauthTable, UsersTable $UsersTable)
    {
        $this->OauthTable = $OauthTable;
        $this->UsersTable = $UsersTable;
    }

    private function _authorizationCodePkceExternalFlow(array $data): array
    {
        $client = new Client();
        $url = Configure::read('RestOauthPlugin.externalOauth.tokenUrl');
        $res = $client->post($url, $data);
        if (!$res->isSuccess()) {
            throw new InternalErrorException('Error with external oauth: ' . $res->getStringBody()
                . ' ' . json_encode($data));
        }
        return $res->getJson();
    }

    private function _loginExternalUser(array $externalToken, array $queryParams): array
    {
        if (!isset($externalToken['id_token'])) {
            throw new InternalErrorException('Error from external oauth ' . json_encode($externalToken));
        }
        $jwt = $this->decodeAndVerifyJWT($externalToken['id_token']);

        $usr = $this->UsersTable->getUserByEmailOrNew($jwt);
        if ($usr->isNew()) {
            $usr = $this->UsersTable->saveOrFail($usr);
        }
        $queryClientId = $queryParams['client_id'];
        $externalClientId = Configure::read('RestOauthPlugin.externalOauth.clientId');
        if ($queryClientId == $externalClientId) {
            throw new InternalErrorException('Invalid oauth client ID');
        }

        try {
            return $this->OauthTable->createBearerToken($usr->id, $queryClientId, $externalToken['expires_in']);
        } catch (BadRequestException $e) {
            $entity = $this->OauthTable->OauthClients->newEmptyEntity();
            $entity->client_id = $queryClientId;
            $this->OauthTable->OauthClients->saveOrFail($entity);
            return $this->OauthTable->createBearerToken($usr->id, $queryClientId, $externalToken['expires_in']);
        }
    }

    public function authorizationCodePkceFlow(array $data): array
    {
        $externalToken = $this->_authorizationCodePkceExternalFlow($data);
        return $this->_loginExternalUser($externalToken, $data);
    }

    public function decodeAndVerifyJWT($jwt)
    {
        $jwks = $this->_fetchJWKS();
        $kid = $this->_decodeJwtHeaderToGetKid($jwt);
        $publicKey = $this->_findMatchingKeyInJwks($jwks, $kid);

        try {
            $decoded = JWT\JWT::decode($jwt, $publicKey, ['RS256']);
            return (array)$decoded; // Convert stdClass to array
        } catch (InternalErrorException $e) {
            throw new InternalErrorException('JWT verification failed: ' . $e->getMessage());
        }
    }

    private function _fetchJWKS()
    {
        $jwksUrl = Configure::read('RestOauthPlugin.externalOauth.tokenSigningKeyUrl');
        $jwksJson = file_get_contents($jwksUrl);
        if (!$jwksJson) {
            throw new InternalErrorException('Unable to fetch JWKS');
        }
        $jwks = json_decode($jwksJson, true);
        return $jwks;
    }

    private function _decodeJwtHeaderToGetKid($jwt)
    {
        $tokenParts = explode('.', $jwt);
        if (count($tokenParts) !== 3) {
            throw new InternalErrorException('Invalid JWT format');
        }
        $header = json_decode(base64_decode($tokenParts[0]), true);
        if (!isset($header['kid'])) {
            throw new InternalErrorException('No kid found in JWT header');
        }

        $kid = $header['kid'];
        return $kid;
    }

    private function _findMatchingKeyInJwks($jwks, $kid)
    {
        $keys = JWT\JWK::parseKeySet($jwks);
        if (!isset($keys[$kid])) {
            throw new InternalErrorException('No matching key found for kid: $kid');
        }

        $publicKey = $keys[$kid];
        return $publicKey;
    }
}
