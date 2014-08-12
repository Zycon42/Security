<?php

namespace Zycon42\Security\Tests\Authorization;

use Zycon42\Security\Authorization\ExpressionLanguage;

class ExpressionLanguageTest extends \PHPUnit_Framework_TestCase {

    protected function tearDown() {
        \Mockery::close();
    }

    public function testCompile_isAnonymous_correctResult() {
        $language = new ExpressionLanguage();
        $compiled = $language->compile('isAnonymous()');

        $this->assertEquals('!$user->isLoggedIn()', $compiled);
    }

    public function testEvaluate_isAnonymous_correctResult() {
        $identity = new \stdClass();
        $user = \Mockery::mock()
            ->shouldReceive('isLoggedIn')->andReturn(false)->once()
            ->getMock();

        $language = new ExpressionLanguage();
        $evaluated = $language->evaluate('isAnonymous()', [
            'identity' => $identity,
            'user' => $user
        ]);

        $this->assertTrue($evaluated);
    }

    public function testCompile_isAuthenticated_correctResult() {
        $language = new ExpressionLanguage();
        $compiled = $language->compile('isAuthenticated()');

        $this->assertEquals('$user->isLoggedIn()', $compiled);
    }

    public function testEvaluate_isAuthenticated_correctResult() {
        $identity = new \stdClass();
        $user = \Mockery::mock()
            ->shouldReceive('isLoggedIn')->andReturn(true)->once()
            ->getMock();

        $language = new ExpressionLanguage();
        $evaluated = $language->evaluate('isAuthenticated()', [
            'identity' => $identity,
            'user' => $user
        ]);

        $this->assertTrue($evaluated);
    }

    public function testCompile_hasRole_correctResult() {
        $language = new ExpressionLanguage();
        $compiled = $language->compile("hasRole('admin')");

        $this->assertEquals('in_array("admin", $roles)', $compiled);
    }

    public function testEvaluate_hasRole_correctResult() {
        $language = new ExpressionLanguage();
        $evaluated = $language->evaluate("hasRole('admin')", [
            'roles' => ['admin', 'client']
        ]);

        $this->assertTrue($evaluated);
    }

    public function testCompile_hasPermission_correctResult() {
        $language = new ExpressionLanguage();
        $compiled = $language->compile("hasPermission(object, 'read')", ['object']);

        $this->assertEquals('$securityContext && $securityContext->isGranted("read", $object)', $compiled);
    }

    public function testEvaluate_hasPermission_correctResult() {
        $object = new \stdClass();
        $securityContext = \Mockery::mock()
            ->shouldReceive('isGranted')->with('read', $object)->andReturn(true)->once()
            ->getMock();

        $language = new ExpressionLanguage();
        $evaluated = $language->evaluate("hasPermission(object, 'read')", [
            'object' => $object,
            'securityContext' => $securityContext
        ]);

        $this->assertTrue($evaluated);
    }
}
