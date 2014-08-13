<?php

namespace Zycon42\Security\Tests\Authorization\Voters;

use Nette\Security\IIdentity;
use Nette\Security\User;
use Zycon42\Security\Authorization\Voters\AuthenticatedVoter;
use Zycon42\Security\Authorization\Voters\IVoter;

class AuthenticatedVoterTest extends \PHPUnit_Framework_TestCase {

    /** @var AuthenticatedVoter */
    private $voter;

    /** @var \Mockery\MockInterface */
    private $user;

    protected function setUp() {
        $this->user = \Mockery::mock(User::class);
        $this->voter = new AuthenticatedVoter($this->user);
    }

    protected function tearDown() {
        \Mockery::close();
    }

    public function testSupportsClass_always_returnsTrue() {
        $this->assertTrue($this->voter->supportsClass('foo'));
    }

    public function supportedAttributes() {
        return [
            [ AuthenticatedVoter::IS_ANONYMOUS ],
            [ AuthenticatedVoter::IS_AUTHENTICATED ]
        ];
    }

    /**
     * @dataProvider supportedAttributes
     */
    public function testSupportsAttribute_supported_returnsTrue($attribute) {
        $this->assertTrue($this->voter->supportsAttribute($attribute));
    }

    public function testSupportsAttribute_unsupported_returnsFalse() {
        $this->assertFalse($this->voter->supportsAttribute('foo'));
    }

    public function testVote_invalidAttributes_abstain() {
        $identity = \Mockery::mock(IIdentity::class);

        $result = $this->voter->vote($identity, [null, 'foo'], null);

        $this->assertEquals(IVoter::VOTE_ABSTAIN, $result);
    }

    public function testVote_isAnonymous_userCalled() {
        $identity = \Mockery::mock(IIdentity::class);
        $this->user->shouldReceive('isLoggedIn')->andReturn(false)->once();

        $this->voter->vote($identity, [ AuthenticatedVoter::IS_ANONYMOUS ], null);
    }

    public function testVote_isAnonymousAndUserNotLoggedIn_granted() {
        $identity = \Mockery::mock(IIdentity::class);
        $this->user->shouldReceive('isLoggedIn')->andReturn(false);

        $result = $this->voter->vote($identity, [ AuthenticatedVoter::IS_ANONYMOUS ], null);

        $this->assertEquals(IVoter::VOTE_GRANTED, $result);
    }

    public function testVote_isAnonymousAndUserIsLoggedIn_denied() {
        $identity = \Mockery::mock(IIdentity::class);
        $this->user->shouldReceive('isLoggedIn')->andReturn(true);

        $result = $this->voter->vote($identity, [ AuthenticatedVoter::IS_ANONYMOUS ], null);

        $this->assertEquals(IVoter::VOTE_DENIED, $result);
    }

    public function testVote_isAuthenticated_userCalled() {
        $identity = \Mockery::mock(IIdentity::class);
        $this->user->shouldReceive('isLoggedIn')->andReturn(true)->once();

        $this->voter->vote($identity, [ AuthenticatedVoter::IS_AUTHENTICATED ], null);
    }

    public function testVote_isAuthenticatedAndUserIsLoggedIn_granted() {
        $identity = \Mockery::mock(IIdentity::class);
        $this->user->shouldReceive('isLoggedIn')->andReturn(true);

        $result = $this->voter->vote($identity, [ AuthenticatedVoter::IS_AUTHENTICATED ], null);

        $this->assertEquals(IVoter::VOTE_GRANTED, $result);
    }

    public function testVote_isAuthenticatedAndUserNotLoggedIn_denied() {
        $identity = \Mockery::mock(IIdentity::class);
        $this->user->shouldReceive('isLoggedIn')->andReturn(false);

        $result = $this->voter->vote($identity, [ AuthenticatedVoter::IS_AUTHENTICATED ], null);

        $this->assertEquals(IVoter::VOTE_DENIED, $result);
    }
}
