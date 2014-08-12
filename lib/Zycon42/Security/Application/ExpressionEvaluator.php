<?php

namespace Zycon42\Security\Application;

use Nette\Application\Request;
use Nette\Security\IRole;
use Nette;
use Symfony\Component\ExpressionLanguage\Expression;
use Zycon42\Security\Authorization\ExpressionLanguage;
use Zycon42\Security\ISecurityContext;

class ExpressionEvaluator extends Nette\Object {

    /**
     * @var ISecurityContext
     */
    private $securityContext;

    /**
     * @var ExpressionLanguage
     */
    private $language;

    /**
     * @var Nette\Security\User
     */
    private $user;

    public function __construct(ISecurityContext $securityContext, Nette\Security\User $user,
                                ExpressionLanguage $language) {

        $this->securityContext = $securityContext;
        $this->user = $user;
        $this->language = $language;
    }

    public function evaluateExpression(Expression $expression, Request $request) {
        return $this->language->evaluate($expression, $this->getVariables($request));
    }

    private function getVariables(Request $request) {
        $variables = [
            'user' => $this->user,
            'identity' => $this->user->identity,
            'object' => $request,
            'roles' => array_map(function ($role) { return $role instanceof IRole ? $role->getRoleId() : $role; },
                $this->user->getRoles()),
            'securityContext' => $this->securityContext
        ];

        return array_merge($variables, $request->parameters);
    }
}
