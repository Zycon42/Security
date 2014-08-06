<?php

namespace Zycon42\Security;

use Zycon42\Security\Authentication\GuestIdentity;
use Zycon42\Security\Authorization\IAccessDecisionManager;
use Nette\Object;
use Nette\Security\IIdentity;

class SecurityContext extends Object implements ISecurityContext {

    /**
     * @var IAccessDecisionManager
     */
    private $decisionManager;

    /**
     * @var IIdentity
     */
    private $identity;

    public function __construct(IAccessDecisionManager $decisionManager) {
        $this->decisionManager = $decisionManager;
    }

    /**
     * {@inheritdoc}
     */
    public function isGranted($attributes, $object = null) {
        if (!is_array($attributes))
            $attributes = array($attributes);

        return $this->decisionManager->decide($this->identity, $attributes, $object);
    }

    /**
     * {@inheritdoc}
     */
    public function setIdentity(IIdentity $identity = null) {
        if ($identity === null) {
            $identity = new GuestIdentity();
        }
        $this->identity = $identity;
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentity() {
        return $this->identity;
    }
}
