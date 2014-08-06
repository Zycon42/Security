<?php

namespace Zycon42\Security\Application;

use Zycon42\Security\Authentication\IAuthenticationTrustResolver;
use Zycon42\Security\Authorization\ExpressionLanguage;
use Zycon42\Security\ISecurityContext;
use Nette;
use Nette\Application\Request;
use Nette\Security\IRole;
use Symfony\Component\ExpressionLanguage\Expression;

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

    /**
     * @var IAuthenticationTrustResolver
     */
    private $trustResolver;

    public function __construct(ISecurityContext $securityContext, IAuthenticationTrustResolver $trustResolver,
                                Nette\Security\User $user, ExpressionLanguage $language) {

        $this->securityContext = $securityContext;
        $this->trustResolver = $trustResolver;
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
            'trustResolver' => $this->trustResolver,
            'securityContext' => $this->securityContext
        ];

        return array_merge($variables, $request->parameters);
    }
}
