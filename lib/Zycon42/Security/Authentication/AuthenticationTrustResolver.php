<?php

namespace Zycon42\Security\Authentication;


use Nette;
use Nette\Security\IIdentity;

class AuthenticationTrustResolver extends Nette\Object implements IAuthenticationTrustResolver {

    /**
     * @var Nette\Security\User
     */
    private $user;

    public function __construct(Nette\Security\User $user) {
        $this->user = $user;
    }

    /**
     * {@inheritdoc}
     */
    public function isGuest(IIdentity $identity = null)
    {
        if (!$identity || $identity instanceof GuestIdentity)
            return true;
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function isAuthenticated(IIdentity $identity = null)
    {
        if (!$identity)
            return false;

        // if current user identity is different from passed identity that identity cannot be authenticated
        if ($this->user->id !== $identity->getId())
            return false;

        return $this->user->isLoggedIn();
    }
}
