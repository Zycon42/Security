<?php

namespace Zycon42\Security\Tests;

use Nette\Security\IIdentity;
use Zycon42\Security\Authentication\GuestIdentity;
use Zycon42\Security\Authorization\IAccessDecisionManager;
use Zycon42\Security\SecurityContext;

class SecurityContextTest extends \PHPUnit_Framework_TestCase {

    /**
     * @var SecurityContext
     */
    private $securityContext;

    /**
     * @var \Mockery\MockInterface
     */
    private $accessDecisionManager;

    protected function setUp() {
        $this->accessDecisionManager = \Mockery::mock(IAccessDecisionManager::class);
        $this->securityContext = new SecurityContext($this->accessDecisionManager);
    }

    protected function tearDown() {
        \Mockery::close();
    }

    public function testGetIdentity_identityNotSet_returnsNull() {
        $this->assertEquals(null, $this->securityContext->getIdentity());
    }

    public function testGetIdentity_identitySetToNull_returnsGuestIdentity() {
        $this->securityContext->setIdentity(null);

        $this->assertInstanceOf(GuestIdentity::class,
            $this->securityContext->getIdentity());
    }

    public function testGetIdentity_identitySet_returnsSameIdentity() {
        $identity = \Mockery::mock(IIdentity::class);
        $this->securityContext->setIdentity($identity);

        $this->assertSame($identity, $this->securityContext->getIdentity());
    }

    public function testIsGranted_attributesIsArray_paramsPassedToDecisionManager() {
        $identity = \Mockery::mock(IIdentity::class);
        $this->securityContext->setIdentity($identity);

        $attributes = ['SHOW', 'EDIT'];
        $object = new \stdClass();

        $this->accessDecisionManager->shouldReceive('decide')
            ->with($identity, $attributes, $object)->once();

        $this->securityContext->isGranted($attributes, $object);
    }

    public function testIsGranted_attributesIsNotArray_attributesConvertedToArray() {
        $identity = \Mockery::mock(IIdentity::class);
        $this->securityContext->setIdentity($identity);

        $this->accessDecisionManager->shouldReceive('decide')
            ->with($identity, ['SHOW'], null)->once();

        $this->securityContext->isGranted('SHOW');
    }

    public function testIsGranted_accessDecisionResult_returned() {
        $identity = \Mockery::mock(IIdentity::class);
        $this->securityContext->setIdentity($identity);

        $this->accessDecisionManager->shouldReceive('decide')
            ->withAnyArgs()->andReturn(true)->once();

        $result = $this->securityContext->isGranted(null);

        $this->assertEquals(true, $result);
    }
}
