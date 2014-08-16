<?php

namespace Zycon42\Security\Application;

use Nette;
use Nette\Application\Request;
use Nette\Security\IRole;
use Symfony\Component\ExpressionLanguage\Expression;
use Zycon42\Security\Authorization\ExpressionLanguage;
use Zycon42\Security\ISecurityContext;
use Zycon42\Security\Role\RoleHierarchy;

class ExpressionEvaluator extends Nette\Object {

    /** @var ISecurityContext */
    private $securityContext;

    /** @var ExpressionLanguage */
    private $language;

    /** @var Nette\Security\User */
    private $user;

    /** @var RoleHierarchy */
    private  $roleHierarchy;

    public function __construct(ISecurityContext $securityContext, Nette\Security\User $user,
                                ExpressionLanguage $language, RoleHierarchy $roleHierarchy = null) {

        $this->securityContext = $securityContext;
        $this->user = $user;
        $this->language = $language;
        $this->roleHierarchy = $roleHierarchy;
    }

    public function evaluate(Expression $expression, Request $request) {
        return $this->language->evaluate($expression, $this->getVariables($request));
    }

    private function getVariables(Request $request) {
        $variables = [
            'user' => $this->user,
            'identity' => $this->user->identity,
            'object' => $request,
            'roles' => array_map(function ($role) { return $role instanceof IRole ? $role->getRoleId() : $role; },
                $this->extractRoles()),
            'securityContext' => $this->securityContext
        ];

        return array_merge($variables, $request->parameters);
    }

    private function extractRoles() {
        $userRoles = $this->user->getRoles();
        if ($this->roleHierarchy) {
            return $this->roleHierarchy->getReachableRoles($userRoles);
        }
        return $userRoles;
    }
}
