<?php

namespace Zycon42\Security\Authorization;

use Nette\Object;
use Nette\Security\IIdentity;
use Zycon42\Security\Authorization\Voters\IVoter;

class AccessDecisionManager extends Object implements IAccessDecisionManager {

    const STRATEGY_AFFIRMATIVE = 'affirmative';
    const STRATEGY_CONSENSUS = 'consensus';
    const STRATEGY_UNANIMOUS = 'unanimous';

    private $allowIfAllAbstain;
    private $allowIfEqualGrantedDenied;
    private $strategy;

    /**
     * @var IVoter[]
     */
    private $voters;

    public function __construct($strategy = self::STRATEGY_AFFIRMATIVE, $allowIfAllAbstain = false, $allowIfEqualGrantedDenied = true) {
        $this->allowIfAllAbstain = (bool)$allowIfAllAbstain;
        $this->allowIfEqualGrantedDenied = (bool)$allowIfEqualGrantedDenied;

        $strategyMethod = 'decide'.ucfirst($strategy);
        if (!method_exists($this, $strategyMethod))
            throw new \InvalidArgumentException(sprintf('Strategy "%s" is not supported.', $strategy));

        $this->strategy = $strategyMethod;
    }

    public function addVoter(IVoter $voter) {
        $this->voters[] = $voter;
    }

    /**
     * {@inheritdoc}
     */
    public function decide(IIdentity $identity, array $attributes, $object)
    {
        if (!$this->voters) {
            throw new \InvalidArgumentException("No voters added.");
        }

        return $this->{$this->strategy}($identity, $attributes, $object);
    }

    /**
     * {@inheritdoc}
     */
    public function supportsAttribute($attribute) {
        if (!$this->voters) {
            throw new \InvalidArgumentException("No voters added.");
        }

        foreach ($this->voters as $voter) {
            if ($voter->supportsAttribute($attribute))
                return true;
        }
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function supportsClass($class) {
        if (!$this->voters) {
            throw new \InvalidArgumentException("No voters added.");
        }

        foreach ($this->voters as $voter) {
            if ($voter->supportsClass($class))
                return true;
        }
        return false;
    }

    /**
     * Grants access if any voter grants.
     *
     * If any denies it denies and if all abstain it's decided according to allowIfAllAbstain attribute
     */
    private function decideAffirmative(IIdentity $identity, array $attributes, $object) {
        $deny = 0;
        foreach ($this->voters as $voter) {
            $vote = $voter->vote($identity, $attributes, $object);
            if ($vote === IVoter::VOTE_GRANTED)
                return true;
            if ($vote === IVoter::VOTE_DENIED)
                $deny++;
        }

        if ($deny > 0)
            return false;

        return $this->allowIfAllAbstain;
    }

    /**
     * Grants access if there's is consensus among voters.
     *
     * Consensus means majority rule, so more grants wins ignoring abstains.
     * In case of tie result is decided according to allowIfEqualGrantedDenied property.
     *
     * If all abstains then result is decided according to allowIfAllAbstain property.
     */
    private function decideConsensus(IIdentity $identity, array $attributes, $object) {
        $pros = 0;
        $cons = 0;
        foreach ($this->voters as $voter) {
            $vote = $voter->vote($identity, $attributes, $object);
            if ($vote === IVoter::VOTE_GRANTED)
                $pros++;
            if ($vote === IVoter::VOTE_DENIED)
                $cons++;
        }

        if ($pros > $cons)
            return true;
        if ($cons > $pros)
            return false;
        if ($pros == $cons && $pros != 0)
            return $this->allowIfEqualGrantedDenied;
        return $this->allowIfAllAbstain;
    }

    /**
     * Grants only if all votes were grant or abstain.
     *
     * If all abstains then result is decided according to allowIfAllAbstain property.
     */
    private function decideUnanimous(IIdentity $identity, array $attributes, $object) {
        $grant = 0;
        foreach ($this->voters as $voter) {
            $vote = $voter->vote($identity, $attributes, $object);
            if ($vote === IVoter::VOTE_GRANTED)
                $grant++;
            if ($vote === IVoter::VOTE_DENIED)
                return false;
        }

        if ($grant > 0)
            return true;

        return $this->allowIfAllAbstain;
    }
}
