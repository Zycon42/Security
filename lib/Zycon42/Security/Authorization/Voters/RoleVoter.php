<?php

namespace Zycon42\Security\Authorization\Voters;


use Nette\Object;
use Nette\Security\IIdentity;
use Nette\Security\IRole;

/**
 * Voter that checks if identity has one of roles.
 */
class RoleVoter extends Object implements IVoter {

    private $prefix;

    public function __construct($prefix = 'ROLE_') {
        $this->prefix = $prefix;
    }

    /**
     * {@inheritdoc}
     */
    public function supportsAttribute($attribute) {
        if ($attribute instanceof IRole)
            return true;
        return strpos($attribute, $this->prefix) === 0;
    }

    /**
     * {@inheritdoc}
     */
    public function supportsClass($class) {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function vote(IIdentity $identity, array $attributes, $object) {
        $result = self::VOTE_ABSTAIN;
        $roles = $this->extractRoles($identity);
        foreach ($attributes as $attribute) {
            if (!$this->supportsAttribute($attribute))
                continue;

            $result = self::VOTE_DENIED;
            foreach ($roles as $role) {
                if (self::getRole($role) === $this->getRoleFromAttribute($attribute))
                    return self::VOTE_GRANTED;
            }
        }

        return $result;
    }

    protected function extractRoles(IIdentity $identity) {
        return $identity->getRoles();
    }

    private static function getRole($role) {
        if ($role instanceof IRole)
            return $role->getRoleId();
        return $role;
    }

    private function getRoleFromAttribute($role) {
        if ($role instanceof IRole)
            return $role->getRoleId();
        return str_replace($this->prefix, '', $role);
    }
} 