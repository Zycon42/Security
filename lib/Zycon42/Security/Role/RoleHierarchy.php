<?php

namespace Zycon42\Security\Role;

use Nette;
use Nette\Security\IRole;

class RoleHierarchy extends Nette\Object implements IRoleHierarchy {

    private $hierarchy;
    private $map;

    /**
     * Sets role hierarchy and pre-compute reachable roles so that
     * they can be accessed later in O(1) time.
     * @param array $hierarchy
     */
    public function setHierarchy(array $hierarchy) {
        $this->hierarchy = $hierarchy;
        $this->buildMap($hierarchy);
    }

    /**
     * @return array current hierarchy
     */
    public function getHierarchy() {
        return $this->hierarchy;
    }

    /**
     * {@inheritdoc}
     */
    public function getReachableRoles(array $roles) {
        $reachableRoles = $roles;
        foreach ($roles as $role) {
            if (!isset($this->map[$this->getRole($role)])) {
                continue;
            }

            foreach ($this->map[$this->getRole($role)] as $r) {
                $reachableRoles[] = $r;
            }
        }
        return $reachableRoles;
    }

    private function buildMap($hierarchy) {
        foreach ($hierarchy as $main => $roles) {
            $this->map[$main] = $roles;

            $visited = [];
            $additionalRoles = $roles;
            while ($role = array_shift($additionalRoles)) {
                if (!isset($hierarchy[$role]))
                    continue;

                $visited[] = $role;
                $this->map[$main] = array_unique(array_merge($this->map[$main], $hierarchy[$role]));
                $additionalRoles = array_merge($additionalRoles, array_diff($hierarchy[$role], $visited));
            }
        }
    }

    private function getRole($role) {
        return $role instanceof IRole ? $role->getRoleId() : $role;
    }
}