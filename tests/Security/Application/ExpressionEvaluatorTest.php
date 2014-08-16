<?php

namespace Zycon42\Security\Tests\Application;

use Nette\Application\Request;
use Nette\Security\IIdentity;
use Nette\Security\User;
use Symfony\Component\ExpressionLanguage\Expression;
use Zycon42\Security\Application\ExpressionEvaluator;
use Zycon42\Security\Authorization\ExpressionLanguage;
use Zycon42\Security\ISecurityContext;
use Zycon42\Security\Role\RoleHierarchy;

class ExpressionEvaluatorTest extends \PHPUnit_Framework_TestCase {

    /** @var ExpressionEvaluator */
    private $evaluator;

    /** @var \Mockery\MockInterface */
    private $securityContext;

    /** @var \Mockery\MockInterface */
    private $user;

    /** @var \Mockery\MockInterface */
    private $language;

    protected function setUp() {
        $this->securityContext = \Mockery::mock(ISecurityContext::class);
        $this->user = \Mockery::mock(User::class);
        $this->language = \Mockery::mock(ExpressionLanguage::class);

        $this->evaluator = new ExpressionEvaluator($this->securityContext, $this->user, $this->language);
    }

    protected function tearDown() {
        \Mockery::close();
    }

    public function testEvaluate_noRequestParams_onlyDefaultParamsInLanguage() {
        $this->user->shouldReceive('getRoles')->andReturn(['test']);
        $identity = \Mockery::mock(IIdentity::class);
        $this->user->shouldReceive('getIdentity')->andReturn($identity);

        $request = \Mockery::mock(Request::class)->shouldReceive('getParameters')
            ->andReturn([])->getMock();

        $expr = \Mockery::mock(Expression::class);

        $this->language->shouldReceive('evaluate')
            ->with($expr, [
                'user' => $this->user,
                'identity' => $identity,
                'object' => $request,
                'roles' => ['test'],
                'securityContext' => $this->securityContext
            ])->once();

        $this->evaluator->evaluate($expr, $request);
    }

    public function testEvaluate_roleHierarchyInvolved_variablesContainsProperRoles() {
        $roleHierarchy = \Mockery::mock(RoleHierarchy::class)
            ->shouldReceive('getReachableRoles')->with(['ADMIN'])
            ->andReturn(['ADMIN', 'MANAGER', 'USER'])->getMock();

        $this->evaluator = new ExpressionEvaluator($this->securityContext, $this->user, $this->language, $roleHierarchy);

        $this->user->shouldReceive('getRoles')->andReturn(['ADMIN']);
        $identity = \Mockery::mock(IIdentity::class);
        $this->user->shouldReceive('getIdentity')->andReturn($identity);

        $request = \Mockery::mock(Request::class)->shouldReceive('getParameters')
            ->andReturn([])->getMock();

        $expr = \Mockery::mock(Expression::class);

        $this->language->shouldReceive('evaluate')
            ->with($expr, \Mockery::on(function ($variables) {
                return $variables['roles'] === ['ADMIN', 'MANAGER', 'USER'];
            }))->once();

        $this->evaluator->evaluate($expr, $request);
    }
}
 