<?php

namespace Zycon42\Security\Tests\Role;

use Zycon42\Security\Role\RoleHierarchy;

class RoleHierarchyTest extends \PHPUnit_Framework_TestCase {

    /** @var RoleHierarchy */
    private $roleHierarchy;

    protected function setUp() {
        $this->roleHierarchy = new RoleHierarchy();
    }

    public function testGetReachableRoles_simpleHierarchy_valid() {
        $this->roleHierarchy->setHierarchy([
            'admin' => ['user']
        ]);

        $this->assertEquals(['admin', 'user'], $this->roleHierarchy->getReachableRoles(['admin']));
    }

    public function testGetReachableRoles_complicatedHierarchy_valid() {
        $this->roleHierarchy->setHierarchy([
            'admin' => ['user', 'manager'],
            'manager' => ['user', 'client'],
            'user' => ['guest']
        ]);

        $this->assertEquals(['admin', 'user', 'manager', 'guest', 'client'],
            $this->roleHierarchy->getReachableRoles(['admin']));
    }
}
