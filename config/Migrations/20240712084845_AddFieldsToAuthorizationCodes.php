<?php

declare(strict_types = 1);

use Migrations\AbstractMigration;

class AddFieldsToAuthorizationCodes extends AbstractMigration
{
    public function change(): void
    {
        $table = $this->table('oauth_authorization_codes');
        $table->addColumn('code_challenge', 'string', [
            'default' => null,
            'limit' => 255,
            'null' => true,
        ]);
        $table->addColumn('code_challenge_method', 'string', [
            'default' => null,
            'limit' => 10,
            'null' => true,
        ]);
        $table->update();
    }
}
