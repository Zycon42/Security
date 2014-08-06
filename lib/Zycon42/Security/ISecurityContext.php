<?php

namespace Zycon42\Security;


use Nette\Security\IIdentity;

interface ISecurityContext {

    /**
     * Checks if attributes are granted to current identity and optionally supplied object.
     * @param $attributes
     * @param null $object
     * @return bool
     */
    public function isGranted($attributes, $object = null);

    /**
     * Sets identity for security context to work with
     * @param IIdentity $identity
     */
    public function setIdentity(IIdentity $identity = null);

    /**
     * Gets associated identity
     * @return IIdentity|null
     */
    public function getIdentity();
}
