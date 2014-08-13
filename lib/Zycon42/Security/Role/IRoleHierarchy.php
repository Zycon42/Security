<?php

namespace Zycon42\Security\Role;

interface IRoleHierarchy {

    /**
     * Returns an array of all reachable roles.
     * Reachable roles are directly assigned roles and all roles that
     * are transitively reachable from them in the role hierarchy
     * @param array $roles directly assigned roles
     * @return array reachable roles given to assigned roles
     */
    public function getReachableRoles(array $roles);
}
