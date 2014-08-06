<?php

namespace Zycon42\Security\Authentication;


use Nette\Security\IIdentity;

interface IAuthenticationTrustResolver {

    /**
     * Checks if identity is quest
     * @param IIdentity $identity
     * @return bool
     */
    public function isGuest(IIdentity $identity = null);

    /**
     * Checks if identity is authenticated
     * @param IIdentity $identity
     * @return bool
     */
    public function isAuthenticated(IIdentity $identity = null);
}
