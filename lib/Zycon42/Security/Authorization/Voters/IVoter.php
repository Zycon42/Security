<?php

namespace Zycon42\Security\Authorization\Voters;


use Nette\Security\IIdentity;

interface IVoter {

    const VOTE_GRANTED = 1;
    const VOTE_ABSTAIN = 0;
    const VOTE_DENIED = -1;

    /**
     * Checks if voter supports attribute
     * @param $attribute
     * @return bool
     */
    public function supportsAttribute($attribute);

    /**
     * Checks if voter supports given class
     * @param string $class
     * @return bool
     */
    public function supportsClass($class);

    /**
     * Returns vote for given attributes
     * @param IIdentity $identity
     * @param array $attributes
     * @param $object
     * @return integer one of VOTE_GRANTED, VOTE_ABSTAIN, VOTE_DENIED
     */
    public function vote(IIdentity $identity, array $attributes, $object);
}
