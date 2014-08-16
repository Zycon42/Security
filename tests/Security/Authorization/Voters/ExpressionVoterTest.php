<?php

namespace Zycon42\Security\Tests\Authorization\Voters;

use Nette\Security\IIdentity;
use Nette\Security\User;
use Symfony\Component\ExpressionLanguage\Expression;
use Zycon42\Security\Authorization\ExpressionLanguage;
use Zycon42\Security\Authorization\Voters\ExpressionVoter;
use Zycon42\Security\Authorization\Voters\IVoter;
use Zycon42\Security\Role\RoleHierarchy;

class ExpressionVoterTest extends \PHPUnit_Framework_TestCase {

    /** @var ExpressionVoter */
    private $voter;

    /** @var \Mockery\MockInterface */
    private $expressionLanguage;

    /** @var \Mockery\MockInterface */
    private $user;

    /** @var \Mockery\MockInterface */
    private $identity;

    protected function setUp() {
        $this->expressionLanguage = \Mockery::mock(ExpressionLanguage::class);
        $this->user = \Mockery::mock(User::class);

        $this->voter = new ExpressionVoter($this->expressionLanguage, $this->user);

        $this->identity = \Mockery::mock(IIdentity::class)->shouldReceive('getRoles')
            ->andReturn(['test'])->byDefault()->getMock();
    }

    protected function tearDown() {
        \Mockery::close();
    }

    public function testSupportsClass_always_returnsTrue() {
        $this->assertTrue($this->voter->supportsClass('foo'));
    }

    public function testSupportsAttribute_expressionGiven_returnsTrue() {
        $expr = \Mockery::mock(Expression::class);
        $this->assertTrue($this->voter->supportsAttribute($expr));
    }

    public function testSupportsAttribute_notExpressionGiven_returnsFalse() {
        $this->assertFalse($this->voter->supportsAttribute('foo'));
    }

    public function testVote_badAttribute_abstain() {
        $vote = $this->voter->vote($this->identity, ['ROLE_ADMIN'], null);

        $this->assertEquals(IVoter::VOTE_ABSTAIN, $vote);
    }

    public function testVote_expressionAsAttribute_languageEvaluateCalled() {
        $expr = \Mockery::mock(Expression::class);

        $object = new \stdClass();
        $this->expressionLanguage->shouldReceive('evaluate')
            ->with($expr, [
                'identity' => $this->identity,
                'user' => $this->user,
                'object' => $object,
                'roles' => ['test']
            ])->once();

        $this->voter->vote($this->identity, [$expr], $object);
    }

    public function testVote_roleHierarchyInvolved_languageVariablesContainsProperRoles() {
        $roleHierarchy = \Mockery::mock(RoleHierarchy::class)
            ->shouldReceive('getReachableRoles')->with(['ADMIN'])
            ->andReturn(['ADMIN', 'MANAGER', 'USER'])->getMock();

        $voter = new ExpressionVoter($this->expressionLanguage, $this->user, $roleHierarchy);

        $this->identity->shouldReceive('getRoles')->andReturn(['ADMIN'])->getMock();

        $expr = \Mockery::mock(Expression::class);

        $object = new \stdClass();
        $this->expressionLanguage->shouldReceive('evaluate')
            ->with($expr, [
                'identity' => $this->identity,
                'user' => $this->user,
                'object' => $object,
                'roles' => ['ADMIN', 'MANAGER', 'USER']
            ])->once();

        $voter->vote($this->identity, [$expr], $object);
    }

    public function testVote_expressionReturnsTrue_grant() {
        $expr = \Mockery::mock(Expression::class);

        $this->expressionLanguage->shouldReceive('evaluate')->andReturn(true);

        $vote = $this->voter->vote($this->identity, [$expr], null);

        $this->assertEquals(IVoter::VOTE_GRANTED, $vote);
    }

    public function testVote_expressionReturnsFalse_deny() {
        $expr = \Mockery::mock(Expression::class);

        $this->expressionLanguage->shouldReceive('evaluate')->andReturn(false);

        $vote = $this->voter->vote($this->identity, [$expr], null);

        $this->assertEquals(IVoter::VOTE_DENIED, $vote);
    }
}
