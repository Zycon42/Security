<?php

namespace Zycon42\Security\Authorization;

use Symfony\Component\ExpressionLanguage\ExpressionLanguage as BaseExpressionLanguage;

class ExpressionLanguage extends BaseExpressionLanguage {

    protected function registerFunctions() {
        parent::registerFunctions();

        $this->register('isAnonymous', function () {
            return '$trustResolver->isGuest($identity)';
        }, function (array $variables) {
            return $variables['trustResolver']->isGuest($variables['identity']);
        });

        $this->register('isAuthenticated', function () {
            return '$trustResolver->isAuthenticated($identity)';
        }, function (array $variables) {
            return $variables['trustResolver']->isAuthenticated($variables['identity']);
        });

        $this->register('hasRole', function ($role) {
            return sprintf('in_array(%s, $roles)', $role);
        }, function (array $variables, $role) {
            return in_array($role, $variables['roles']);
        });

        $this->register('hasPermission', function ($object, $attributes) {
            return sprintf('$securityContext && $securityContext->isGranted(%s, %s)', $attributes, $object);
        }, function (array $variables, $object, $attributes) {
            return $variables['securityContext'] && $variables['securityContext']->isGranted($attributes, $object);
        });
    }
}
