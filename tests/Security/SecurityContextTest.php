<?php

namespace Zycon42\Security\Tests;

use Nette\Security\IIdentity;
use Nette\Security\User;
use Zycon42\Security\Authentication\GuestIdentity;
use Zycon42\Security\Authorization\IAccessDecisionManager;
use Zycon42\Security\SecurityContext;

class SecurityContextTest extends \PHPUnit_Framework_TestCase {

    /** @var SecurityContext */
    private $securityContext;

    /** @var \Mockery\MockInterface */
    private $accessDecisionManager;

    /** @var \Mockery\MockInterface */
    private $user;

    protected function setUp() {
        $this->accessDecisionManager = \Mockery::mock(IAccessDecisionManager::class);
        $this->user = \Mockery::mock(User::class);
        $this->securityContext = new SecurityContext($this->accessDecisionManager, $this->user);
    }

    protected function tearDown() {
        \Mockery::close();
    }

    public function testIsGranted_userHasNullIdentity_GuestIdentityPassedToAccessDecisionManager() {
        $this->user->shouldReceive('getIdentity')->andReturn(null);

        $this->accessDecisionManager->shouldReceive('decide')
            ->with(\Mockery::type(GuestIdentity::class), \Mockery::any(), \Mockery::any())
            ->once();

        $this->securityContext->isGranted('SHOW');
    }

    public function testIsGranted_attributesIsArray_paramsPassedToDecisionManager() {
        $identity = \Mockery::mock(IIdentity::class);
        $this->user->shouldReceive('getIdentity')->andReturn($identity);

        $attributes = ['SHOW', 'EDIT'];
        $object = new \stdClass();

        $this->accessDecisionManager->shouldReceive('decide')
            ->with($identity, $attributes, $object)->once();

        $this->securityContext->isGranted($attributes, $object);
    }

    public function testIsGranted_attributesIsNotArray_attributesConvertedToArray() {
        $identity = \Mockery::mock(IIdentity::class);
        $this->user->shouldReceive('getIdentity')->andReturn($identity);

        $this->accessDecisionManager->shouldReceive('decide')
            ->with($identity, ['SHOW'], null)->once();

        $this->securityContext->isGranted('SHOW');
    }

    public function testIsGranted_accessDecisionResult_returned() {
        $identity = \Mockery::mock(IIdentity::class);
        $this->user->shouldReceive('getIdentity')->andReturn($identity);

        $this->accessDecisionManager->shouldReceive('decide')
            ->withAnyArgs()->andReturn(true)->once();

        $result = $this->securityContext->isGranted(null);

        $this->assertEquals(true, $result);
    }
}
