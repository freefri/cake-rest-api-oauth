<?php

namespace RestOauth\Lib;

use Cake\I18n\FrozenTime;
use RestApi\Lib\Exception\DetailedException;
use RestApi\Lib\Helpers\CookieHelper;

class LoginChallenge
{
    private string $codeChallenge;
    private string $redirectUri;
    private ?string $state;
    private CookieHelper $encryptionHelper;

    public function __construct(string $codeChallenge, string $redirectUri, string $state = null)
    {
        $this->codeChallenge = $codeChallenge;
        $this->redirectUri = $redirectUri;
        $this->state = $state;
    }

    public function computeLoginChallenge(): string
    {
        $this->encryptionHelper = new CookieHelper();
        $payload = [
            'challenge' => $this->codeChallenge,
            'redirect' => $this->redirectUri,
            'state' => $this->state,
            'expires' => new FrozenTime('+2minutes')
        ];
        $encryptedChallenge = $this->encryptionHelper->writeLoginChallenge($payload, 1);
        return base64_encode($encryptedChallenge->read());
    }

    public static function decrypt(string $encrypted, CookieHelper $CookieHelper): array
    {
        $decoded = base64_decode($encrypted);
        $res = $CookieHelper->decryptLoginChallenge($decoded);
        $expires = new FrozenTime($res['expires']);
        unset($res['expires']);
        if ($expires->isPast()) {
            throw new DetailedException('Expired login_challenge');
        }
        return $res;
    }
}
