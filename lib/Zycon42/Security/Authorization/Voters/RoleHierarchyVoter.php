<?php

namespace Zycon42\Security\Authorization\Voters;

use Nette\Security\IIdentity;
use Zycon42\Security\Role\IRoleHierarchy;

class RoleHierarchyVoter extends RoleVoter {

    /** @var IRoleHierarchy */
    private $roleHierarchy;

    public function __construct(IRoleHierarchy $roleHierarchy, $prefix = 'ROLE_') {
        parent::__construct($prefix);
        $this->roleHierarchy = $roleHierarchy;
    }

    protected function extractRoles(IIdentity $identity) {
        return $this->roleHierarchy->getReachableRoles($identity->getRoles());
    }
} 