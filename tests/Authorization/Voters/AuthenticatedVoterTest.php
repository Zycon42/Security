<?php

namespace Zycon42\Security\Tests\Authorization\Voters;

use Nette\Security\IIdentity;
use Zycon42\Security\Authentication\IAuthenticationTrustResolver;
use Zycon42\Security\Authorization\Voters\AuthenticatedVoter;
use Zycon42\Security\Authorization\Voters\IVoter;

class AuthenticatedVoterTest extends \PHPUnit_Framework_TestCase {

    /** @var AuthenticatedVoter */
    private $voter;

    /** @var \Mockery\MockInterface */
    private $trustResolver;

    protected function setUp() {
        $this->trustResolver = \Mockery::mock(IAuthenticationTrustResolver::class);
        $this->voter = new AuthenticatedVoter($this->trustResolver);
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

    public function testVote_isAnonymous_trustResolverCalled() {
        $identity = \Mockery::mock(IIdentity::class);
        $this->trustResolver->shouldReceive('isGuest')->with($identity)
            ->andReturn(true)->once();

        $this->voter->vote($identity, [ AuthenticatedVoter::IS_ANONYMOUS ], null);
    }

    public function testVote_isAnonymousAndTrustResolverReturnsTrue_granted() {
        $identity = \Mockery::mock(IIdentity::class);
        $this->trustResolver->shouldReceive('isGuest')->andReturn(true);

        $result = $this->voter->vote($identity, [ AuthenticatedVoter::IS_ANONYMOUS ], null);

        $this->assertEquals(IVoter::VOTE_GRANTED, $result);
    }

    public function testVote_isAnonymousAndTrustResolverReturnsFalse_denied() {
        $identity = \Mockery::mock(IIdentity::class);
        $this->trustResolver->shouldReceive('isGuest')->andReturn(false);

        $result = $this->voter->vote($identity, [ AuthenticatedVoter::IS_ANONYMOUS ], null);

        $this->assertEquals(IVoter::VOTE_DENIED, $result);
    }

    public function testVote_isAuthenticated_trustResolverCalled() {
        $identity = \Mockery::mock(IIdentity::class);
        $this->trustResolver->shouldReceive('isAuthenticated')->with($identity)
            ->andReturn(true)->once();

        $this->voter->vote($identity, [ AuthenticatedVoter::IS_AUTHENTICATED ], null);
    }

    public function testVote_isAuthenticatedAndTrustResolverReturnsTrue_granted() {
        $identity = \Mockery::mock(IIdentity::class);
        $this->trustResolver->shouldReceive('isAuthenticated')->andReturn(true);

        $result = $this->voter->vote($identity, [ AuthenticatedVoter::IS_AUTHENTICATED ], null);

        $this->assertEquals(IVoter::VOTE_GRANTED, $result);
    }

    public function testVote_isAuthenticatedAndTrustResolverReturnsFalse_denied() {
        $identity = \Mockery::mock(IIdentity::class);
        $this->trustResolver->shouldReceive('isAuthenticated')->andReturn(false);

        $result = $this->voter->vote($identity, [ AuthenticatedVoter::IS_AUTHENTICATED ], null);

        $this->assertEquals(IVoter::VOTE_DENIED, $result);
    }
}
