<?php

namespace Zycon42\Security\Authorization\Voters;


use Nette\Object;
use Nette\Security\IIdentity;
use Nette\Security\User;

/**
 * Voter that checks if identity is authenticated or anonymous.
 */
class AuthenticatedVoter extends Object implements IVoter {

    const IS_AUTHENTICATED = 'IS_AUTHENTICATED';
    const IS_ANONYMOUS = 'IS_ANONYMOUS';

    /**
     * @var User
     */
    private $user;

    public function __construct(User $user) {
        $this->user = $user;
    }

    /**
     * {@inheritdoc}
     */
    public function supportsAttribute($attribute)
    {
        return $attribute === self::IS_ANONYMOUS || $attribute === self::IS_AUTHENTICATED;
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
        foreach ($attributes as $attribute) {
            if (!$this->supportsAttribute($attribute))
                continue;

            $result = self::VOTE_DENIED;
            if ($attribute === self::IS_ANONYMOUS && !$this->user->isLoggedIn())
                return self::VOTE_GRANTED;
            if ($attribute === self::IS_AUTHENTICATED && $this->user->isLoggedIn())
                return self::VOTE_GRANTED;
        }

        return $result;
    }
}
