<?php

namespace Zycon42\Security\Authentication;

use Nette\Object;
use Nette\Security\IIdentity;

/**
 * Fake identity for guest user
 * @package Zycon42\Security\Authentication
 */
class GuestIdentity extends Object implements IIdentity {

    const ROLE = 'guest';

    public function getId() {
        return null;
    }

    public function getRoles() {
        return [
            self::ROLE
        ];
    }
}
