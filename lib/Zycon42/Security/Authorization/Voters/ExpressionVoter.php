<?php

namespace Zycon42\Security\Authorization\Voters;


use Nette\Object;
use Nette\Security\IIdentity;
use Nette\Security\IRole;
use Nette\Security\User;
use Symfony\Component\ExpressionLanguage\Expression;
use Zycon42\Security\Authorization\ExpressionLanguage;
use Zycon42\Security\Role\RoleHierarchy;

class ExpressionVoter extends Object implements IVoter {

    /** @var ExpressionLanguage */
    private $language;

    /** @var User */
    private $user;

    /** @var RoleHierarchy */
    private $roleHierarchy;

    public function __construct(ExpressionLanguage $language, User $user, RoleHierarchy $roleHierarchy = null) {
        $this->language = $language;
        $this->user = $user;
        $this->roleHierarchy = $roleHierarchy;
    }

    /**
     * {@inheritdoc}
     */
    public function supportsAttribute($attribute)
    {
        return $attribute instanceof Expression;
    }

    /**
     * {@inheritdoc}
     */
    public function supportsClass($class)
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function vote(IIdentity $identity, array $attributes, $object)
    {
        $result = self::VOTE_ABSTAIN;
        $variables = null;
        foreach ($attributes as $attribute) {
            if (!$this->supportsAttribute($attribute))
                continue;

            if ($variables === null)
                $variables = $this->getVariables($identity, $object);

            $result = self::VOTE_DENIED;
            if ($this->language->evaluate($attribute, $variables))
                return self::VOTE_GRANTED;
        }

        return $result;
    }

    public function getVariables(IIdentity $identity, $object) {
        return [
            'identity' => $identity,
            'user' => $this->user,
            'object' => $object,
            'roles' => array_map(function ($role) { return $role instanceof IRole ? $role->getRoleId() : $role; },
                $this->extractRoles($identity))
        ];
    }

    private function extractRoles(IIdentity $identity) {
        if ($this->roleHierarchy)
            return $this->roleHierarchy->getReachableRoles($identity->getRoles());
        return $identity->getRoles();
    }
}
