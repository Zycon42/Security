<?php

namespace Zycon42\Security;

use Nette\Object;
use Nette\Security\User;
use Zycon42\Security\Authentication\GuestIdentity;
use Zycon42\Security\Authorization\IAccessDecisionManager;

class SecurityContext extends Object implements ISecurityContext {

    /**
     * @var IAccessDecisionManager
     */
    private $decisionManager;

    /**
     * @var User
     */
    private $user;

    public function __construct(IAccessDecisionManager $decisionManager, User $user) {
        $this->decisionManager = $decisionManager;
        $this->user = $user;
    }

    /**
     * {@inheritdoc}
     */
    public function isGranted($attributes, $object = null) {
        if (!is_array($attributes))
            $attributes = array($attributes);

        $identity = $this->user->getIdentity();
        if ($identity === null) {
            $identity = new GuestIdentity();
        }

        return $this->decisionManager->decide($identity, $attributes, $object);
    }
}
