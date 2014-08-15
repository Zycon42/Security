Security
========

[![Build Status](https://travis-ci.org/Zycon42/Security.svg?branch=master)](https://travis-ci.org/Zycon42/Security)

Overview
--------

Because I wasn't satisfied with current state of nette authorization mechanism I decided to port `Symfony/Security` into Nette.

It is largely based on `Symfony/Security-Core`. Sadly Nette authentication mechanism and `Nette\Security\User` class are incompatible with pure `Symfony/Security-Core`, so it was necessary to rewrite it.

Currently this project handles only Authorization for Authentication you have to use Nette classes. Also ACL isn't currently supported.

For more info how it works internally please refer to symfony security documentation.

Requirements
--------

This project requires php 5.4

- [Nette Framework](https://github.com/nette/nette)
- [Symfony Expression Language](https://github.com/symfony/expression-language)

Installation
------------

The best way to install Zycon42/Security is using the [Composer](http://getcomposer.org/):

```sh
$ composer require zycon42/security:~0.1
```

and then you have to enable it in your config.neon

```yml
extensions:
	security: Zycon42\Security\DI\SecurityExtension
```

Basic Usage
-----------

Main entry point for authorizations is `SecurityContext` class. Sample usage:

```php
if (!$securityContext->isGranted('ROLE_ADMIN'))
    throw new ForbiddenRequestException('You need to be admin');
```

Code above will deny access if current user doesn't have role named `ADMIN`. Instead of roles you can use `IS_AUTHENTICATED` or `IS_ANONYMOUS` that grant access only to authenticated users or anonymous users respectively.

Also you can utilize optional secondary parameter `object` of `isGranted` method and ask if current user can perform given action on given resource like this:

```php
if (!$securityContext->isGranted('EDIT', $post))
    throw new ForbiddenRequestException("You are not able to edit this $post");
```

Voters
------

Symfony security uses idea of voters that vote if user will be granted or denied. Access decision manager collects these votes and decides based on them. Project ships with three voters. One for roles, second for `IS_AUTHENTICATED, IS_ANONYMOUS` tokens and last one for expressions which we will discuss later.

Using voters you can easily extend range of supported attributes and objects. You can for example implement typical use-case of user only allowed to edit own posts.

Create new voter implementing `Zycon42\Security\Authorization\Voters\IVoter` interface and then register it in DIC with specific tag

```yml
services:
    foo:
        class: YourVoter
        tags: [security.voter]
```

When you tag service with `security.voter` tag it will be added into `AccessDecisionManager` as voter.

For more information about voters and how to implement new one please refer to [symfony documentation](http://symfony.com/doc/current/cookbook/security/voters_data_permission.html) only remember that instead of `TokenInterface` we use `IIdentity` from nette.

Expressions
---------

To be able to write more complex access rules you can use expressions. For parsing it we use `symfony/expression-language`.

There are several functions you can use in them:

- `isAnonymous()` returns true if current user isn't authenticated
- `isAuthenticated()` returns true if current user is authenticated
- `hasRole(string $role)` checks if user is in given role
- `hasPermission($object, $action)` checks if user has permission to perform action on object

Also you can access several variables:

- `identity` current user identity
- `user` nette user object `Nette\Security\User`
- `object` object that was passed as second parameter into `isGranted` method.
- `roles` array of identity roles

Example usage:
```php
$securityContext->isGranted(new Expression("isAuthenticated() && !hasRole('CLIENT')"));
```

Presenter annotations
---------

To be able to use presenter annotations for granting/denying access use this in your secured presenter, which all your presenters that needs to use this, derive:

```php

class SecuredPresenter extends BasePresenter
{
    // ... some code

    /**
     * @var PresenterRequirementsChecker
     * @inject
     */
    public $requirementsChecker;

    /**
     * {@inheritdoc}
     */
    public function checkRequirements($element) {
        if (!$this->requirementsChecker->checkRequirement($element, $this->request)) {
            // logged users get 403 and anonymous users get redirect to sign in
            if ($this->user->isLoggedIn()) {
                $expr = $this->requirementsChecker->getFailedExpression();
                throw new ForbiddenRequestException("Request didn't passed security expression \"$expr\"");
            } else {
                $this->redirect('Sign:in', ['backLink' => $this->storeRequest()]);
            }
        }
    }

    // ... some code
}
```

Remember not to override `checkRequirements` method in your derived presenters.

Now you can annotate your presenters and its `action/render/handle` methods with `@Security` annotations. Small example:

```php
/**
 * @Security("hasRole('ADMIN')")
 */
class UsersPresenter extends SecuredPresenter
{
    // ... some code
}
```

or on `action` method

```php
class UsersPresenter extends SecuredPresenter
{
    // ... some code

    /**
     * @Security("hasRole('ADMIN')")
     */
    public function actionEdit($id) {
        // ... implementation
    }
}
```

When using annotations on presenters note that annotations are inherited and are checked in order from base class to derived classes.

Expressions in annotations are same as these on `isGranted` but additionally you have access to all current request parameters as variables and object variable contains current request. So if you use something that converts presenter methods parameters from `id` to actual objects by adding additional request variables like `zycon42/param-converters` you will be able to write:

```php
class PostPresenter extends SecuredPresenter
{
    // ... some code

        /**
         * @Security("hasPermission(post, 'EDIT')")
         */
        public function actionEdit(Post $post) {
            // ... implementation
        }
}
```

Configuration
----------

Here you can find possible configuration options and its default values

```yml
security:
    decisionManager:
        strategy: affirmative
        allowIfAllAbstain: false
        allowIfEqualGrantedDenied: true
    voters:
        role: on
        authenticated: on
        expression: on
    roleHierarchy: false
```

In `roleHierarchy` section you can define how roles inherit from each other

```yml
security:
    roleHierarchy:
        ADMIN: { USER, MANAGER }
        MANAGER: { USER, CLIENT }
        CLIENT: GUEST
```

Note that ADMIN inheriting from USER is redundant because ADMIN inherits from USER through MANAGER. But here is list of each role effective list:

- ADMIN: ADMIN, USER, MANAGER, CLIENT, GUEST
- MANAGER: MANAGER, USER, CLIENT, GUEST
- CLIENT: CLIENT, GUEST
