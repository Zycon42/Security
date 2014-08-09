<?php

namespace Zycon42\Security\Tests\Authorization\Voters;

use Nette\Security\User;
use Symfony\Component\ExpressionLanguage\Expression;
use Zycon42\Security\Authentication\IAuthenticationTrustResolver;
use Zycon42\Security\Authorization\ExpressionLanguage;
use Zycon42\Security\Authorization\Voters\ExpressionVoter;

class ExpressionVoterTest extends \PHPUnit_Framework_TestCase {

    /** @var ExpressionVoter */
    private $voter;

    /** @var \Mockery\MockInterface */
    private $expressionLanguage;

    /** @var \Mockery\MockInterface */
    private $trustResolver;

    /** @var \Mockery\MockInterface */
    private $user;

    protected function setUp() {
        $this->expressionLanguage = \Mockery::mock(ExpressionLanguage::class);
        $this->trustResolver = \Mockery::mock(IAuthenticationTrustResolver::class);
        $this->user = \Mockery::mock(User::class);

        $this->voter = new ExpressionVoter($this->expressionLanguage, $this->trustResolver, $this->user);
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
}
