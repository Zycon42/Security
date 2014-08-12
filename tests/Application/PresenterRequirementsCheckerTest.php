<?php

namespace Zycon42\Security\Tests\Application;


use Nette\Application\Request;
use Nette\Reflection\ClassType;
use Nette\Reflection\Method;
use Zycon42\Security\Application\ExpressionEvaluator;
use Zycon42\Security\Application\PresenterRequirementsChecker;

class PresenterRequirementsCheckerTest extends \PHPUnit_Framework_TestCase {

    /** @var PresenterRequirementsChecker */
    private $checker;

    /** @var \Mockery\MockInterface */
    private $evaluator;

    protected function setUp() {
        $this->evaluator = \Mockery::mock(ExpressionEvaluator::class);
        $this->checker = new PresenterRequirementsChecker($this->evaluator);
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testCheckRequirement_forbiddenTypePassedAsElement_Throws() {
        $request = \Mockery::mock(Request::class);
        $this->checker->checkRequirement('foo', $request);
    }

    public function testCheckRequirement_methodWithoutAnnotation_evaluatorNotCalled() {
        $request = \Mockery::mock(Request::class);

        $this->evaluator->shouldReceive('evaluate')->never();

        $methodReflection = Method::from(TestDerivedClass::class, 'testMethodWithoutAnnotation');
        $this->checker->checkRequirement($methodReflection, $request);
    }

    public function testCheckRequirement_methodWithAnnotation_evaluatorCalled() {
        $request = \Mockery::mock(Request::class);

        $this->evaluator->shouldReceive('evaluate')
            ->with(\Mockery::on(function($expr) { return $expr == 'method'; }), $request)
            ->once();

        $methodReflection = Method::from(TestDerivedClass::class, 'testMethod');
        $this->checker->checkRequirement($methodReflection, $request);
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testCheckRequirement_methodWithBadAnnotation_throws() {
        $request = \Mockery::mock(Request::class);

        $methodReflection = Method::from(TestDerivedClass::class, 'testMethodBadAnnotation');
        $this->checker->checkRequirement($methodReflection, $request);
    }

    public function testCheckRequirement_classWithoutAnnotation_evaluatorNotCalled() {
        $request = \Mockery::mock(Request::class);

        $this->evaluator->shouldReceive('evaluate')->never();

        $classReflection = ClassType::from(TestClassWithoutAnnotation::class);
        $this->checker->checkRequirement($classReflection, $request);
    }

    public function testCheckRequirement_baseClassWithAnnotation_evaluatorCalled() {
        $request = \Mockery::mock(Request::class);

        $this->evaluator->shouldReceive('evaluate')
            ->with(\Mockery::on(function($expr) { return $expr == 'base'; }), $request)
            ->once();

        $classReflection = ClassType::from(TestBaseClass::class);
        $this->checker->checkRequirement($classReflection, $request);
    }

    public function testCheckRequirement_derivedClassWithAnnotation_evaluatorCalledForBaseAndDerived() {
        $request = \Mockery::mock(Request::class);

        $this->evaluator->shouldReceive('evaluate')
            ->with(\Mockery::on(function($expr) { return $expr == 'base'; }), $request)
            ->once()->ordered();

        $this->evaluator->shouldReceive('evaluate')
            ->with(\Mockery::on(function($expr) { return $expr == 'derived'; }), $request)
            ->once()->ordered();

        $classReflection = ClassType::from(TestDerivedClass::class);
        $this->checker->checkRequirement($classReflection, $request);
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testCheckRequirement_classWithBadAnnotation_throws() {
        $request = \Mockery::mock(Request::class);

        $classReflection = ClassType::from(TestClassWithBadAnnotation::class);
        $this->checker->checkRequirement($classReflection, $request);
    }

    public function testGetFailedExpression_evaluatorReturnsFalse_returnsExpressionThatFailed() {
        $request = \Mockery::mock(Request::class);

        $this->evaluator->shouldReceive('evaluate')->andReturn(false);

        $methodReflection = Method::from(TestDerivedClass::class, 'testMethod');
        $result = $this->checker->checkRequirement($methodReflection, $request);

        $this->assertFalse($result);
        $this->assertEquals('method', (string)$this->checker->getFailedExpression());
    }
}

/**
 * @Security('base')
 */
class TestBaseClass
{ }

/**
 * @Security('derived')
 */
class TestDerivedClass
{
    /**
     * @Security('method')
     */
    public function testMethod() {}

    /**
     * @Security(expr = 'bad')
     */
    public function testMethodBadAnnotation() {}

    public function testMethodWithoutAnnotation() { }
}

/**
 * @Security(expr = 'bad')
 */
class TestClassWithBadAnnotation
{ }

class TestClassWithoutAnnotation
{}