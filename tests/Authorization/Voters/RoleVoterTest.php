<?php

namespace Zycon42\Security\Tests\Authorization\Voters;

use Nette\Security\IIdentity;
use Nette\Security\IRole;
use Zycon42\Security\Authorization\Voters\IVoter;
use Zycon42\Security\Authorization\Voters\RoleVoter;

class RoleVoterTest extends \PHPUnit_Framework_TestCase {

    /**
     * @var RoleVoter
     */
    private $voter;

    protected function setUp() {
        $this->voter = new RoleVoter();
    }

    protected function tearDown() {
        \Mockery::close();
    }

    public function testSupportsClass_always_returnTrue() {
        $this->assertTrue($this->voter->supportsClass('foo'));
    }

    public function testSupportsAttribute_stringWithoutPrefix_returnFalse() {
        $this->assertFalse($this->voter->supportsAttribute('ADMIN'));
    }

    public function testSupportsAttribute_stringWithPrefix_returnTrue() {
        $this->assertTrue($this->voter->supportsAttribute('ROLE_ADMIN'));
    }

    public function testSupportsAttribute_instanceOfIRoleGiven_returnTrue() {
        $role = \Mockery::mock(IRole::class);
        $this->assertTrue($this->voter->supportsAttribute($role));
    }

    public function testVote_badAttributesGiven_abstain() {
        $identity = \Mockery::mock(IIdentity::class)
            ->shouldReceive('getRoles')->andReturn(['ADMIN', 'CLIENT'])
            ->getMock();

        $vote = $this->voter->vote($identity, ['admin', null], null);

        $this->assertEquals(IVoter::VOTE_ABSTAIN, $vote);
    }

    public function testVote_identityHasSuitableRole_grant() {
        $identity = \Mockery::mock(IIdentity::class)
            ->shouldReceive('getRoles')->andReturn(['ADMIN', 'CLIENT'])
            ->getMock();

        $vote = $this->voter->vote($identity, ['ROLE_ADMIN'], null);

        $this->assertEquals(IVoter::VOTE_GRANTED, $vote);
    }

    public function testVote_identityNoSuitableRole_deny() {
        $identity = \Mockery::mock(IIdentity::class)
            ->shouldReceive('getRoles')->andReturn(['CLIENT'])
            ->getMock();

        $vote = $this->voter->vote($identity, ['ROLE_ADMIN', 'ROLE_MANAGER'], null);

        $this->assertEquals(IVoter::VOTE_DENIED, $vote);
    }

    public function testVote_usingIRole_noThrow() {
        $identity = \Mockery::mock(IIdentity::class)
            ->shouldReceive('getRoles')->andReturn([$this->createRole('CLIENT')])
            ->getMock();

        $vote = $this->voter->vote($identity, [
            $this->createRole('ADMIN'), $this->createRole('MANAGER')
        ], null);

        $this->assertEquals(IVoter::VOTE_DENIED, $vote);
    }

    private function createRole($role) {
        return \Mockery::mock(IRole::class)
            ->shouldReceive('getRoleId')->andReturn($role)
            ->getMock();
    }
}
