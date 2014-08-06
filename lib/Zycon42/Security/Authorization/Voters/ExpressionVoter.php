<?php

namespace Zycon42\Security\Authorization\Voters;


use Zycon42\Security\Authentication\IAuthenticationTrustResolver;
use Zycon42\Security\Authorization\ExpressionLanguage;
use Nette\Object;
use Nette\Security\IIdentity;
use Nette\Security\IRole;
use Nette\Security\User;
use Symfony\Component\ExpressionLanguage\Expression;

class ExpressionVoter extends Object implements IVoter {

    /**
     * @var ExpressionLanguage
     */
    private $language;

    /**
     * @var IAuthenticationTrustResolver
     */
    private $trustResolver;

    /**
     * @var User
     */
    private $user;

    public function __construct(ExpressionLanguage $language, IAuthenticationTrustResolver $trustResolver, User $user) {
        $this->language = $language;
        $this->trustResolver = $trustResolver;
        $this->user = $user;
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
                $identity->getRoles()),
            'trustResolver' => $this->trustResolver
        ];
    }
}