<?php

namespace Zycon42\Security\Authorization;


use Nette\Security\IIdentity;

interface IAccessDecisionManager {

    /**
     * Decides if access is possible.
     * @param IIdentity $identity
     * @param array $attributes
     * @param $object
     * @return bool true when can access, false otherwise
     */
    public function decide(IIdentity $identity, array $attributes, $object);

    /**
     * Checks if decision manager supports given attribute.
     * @param $attribute
     * @return bool
     */
    public function supportsAttribute($attribute);

    /**
     * Checks if decision manager supports given class
     * @param string $class class name
     * @return bool
     */
    public function supportsClass($class);
} 