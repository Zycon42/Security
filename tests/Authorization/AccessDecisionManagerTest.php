<?php

namespace Zycon42\Security\Tests\Authorization;


use Zycon42\Security\Authorization\AccessDecisionManager;
use Zycon42\Security\Authorization\Voters\IVoter;

class AccessDecisionManagerTest extends \PHPUnit_Framework_TestCase {

    protected function tearDown() {
        \Mockery::close();
    }

    private function getMockIdentity() {
        return \Mockery::mock('Nette\Security\IIdentity');
    }

    private function getMockVoter() {
        return \Mockery::mock('Zycon42\Security\Authorization\Voters\IVoter');
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testConstruct_invalidStrategy_throws() {
        $manager = new AccessDecisionManager('foo');
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testSupportsAttribute_noVoters_throws() {
        $manager = new AccessDecisionManager();

        $result = $manager->supportsAttribute('foo');
    }

    public function testSupportsAttribute_allVotersDoesNotSupport_returnsFalse() {
        $voter1 = $this->getMockVoter();
        $voter1->shouldReceive('supportsAttribute')->with('foo')->andReturn(false);

        $voter2 = $this->getMockVoter();
        $voter2->shouldReceive('supportsAttribute')->with('foo')->andReturn(false);

        $manager = new AccessDecisionManager();
        $manager->addVoter($voter1);
        $manager->addVoter($voter2);

        $result = $manager->supportsAttribute('foo');

        $this->assertFalse($result);
    }

    public function testSupportsAttribute_oneVoterDoesSupport_returnsTrue() {
        $voter1 = $this->getMockVoter();
        $voter1->shouldReceive('supportsAttribute')->with('foo')->andReturn(false);

        $voter2 = $this->getMockVoter();
        $voter2->shouldReceive('supportsAttribute')->with('foo')->andReturn(true);

        $manager = new AccessDecisionManager();
        $manager->addVoter($voter1);
        $manager->addVoter($voter2);

        $result = $manager->supportsAttribute('foo');

        $this->assertTrue($result);
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testSupportsClass_noVoters_throws() {
        $manager = new AccessDecisionManager();

        $result = $manager->supportsClass('foo');
    }

    public function testSupportsClass_allVotersDoesNotSupport_returnsFalse() {
        $voter1 = $this->getMockVoter();
        $voter1->shouldReceive('supportsClass')->with('foo')->andReturn(false);

        $voter2 = $this->getMockVoter();
        $voter2->shouldReceive('supportsClass')->with('foo')->andReturn(false);

        $manager = new AccessDecisionManager();
        $manager->addVoter($voter1);
        $manager->addVoter($voter2);

        $result = $manager->supportsClass('foo');

        $this->assertFalse($result);
    }

    public function testSupportsClass_oneVoterDoesSupport_returnsTrue() {
        $voter1 = $this->getMockVoter();
        $voter1->shouldReceive('supportsClass')->with('foo')->andReturn(false);

        $voter2 = $this->getMockVoter();
        $voter2->shouldReceive('supportsClass')->with('foo')->andReturn(true);

        $manager = new AccessDecisionManager();
        $manager->addVoter($voter1);
        $manager->addVoter($voter2);

        $result = $manager->supportsClass('foo');

        $this->assertTrue($result);
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testDecide_noVoters_throws() {
        $manager = new AccessDecisionManager();

        $manager->decide($this->getMockIdentity(), [], null);
    }

    private function addMockVoters(AccessDecisionManager $manager, array $votes) {
        foreach ($votes as $vote) {
            $voter = $this->getMockVoter();
            $voter->shouldReceive('vote')->andReturn($vote);

            $manager->addVoter($voter);
        }
    }

    public function testDecideAffirmative_oneGrants_returnsTrue() {
        $manager = new AccessDecisionManager();
        $this->addMockVoters($manager, [
            IVoter::VOTE_ABSTAIN,
            IVoter::VOTE_GRANTED,
            IVoter::VOTE_ABSTAIN
        ]);

        $result = $manager->decide($this->getMockIdentity(), ['foo'], null);

        $this->assertTrue($result);
    }

    public function testDecideAffirmative_oneGrantsAndOneDenies_returnsTrue() {
        $manager = new AccessDecisionManager();
        $this->addMockVoters($manager, [
            IVoter::VOTE_ABSTAIN,
            IVoter::VOTE_GRANTED,
            IVoter::VOTE_DENIED
        ]);

        $result = $manager->decide($this->getMockIdentity(), ['foo'], null);

        $this->assertTrue($result);
    }

    public function testDecideAffirmative_oneDenies_returnsFalse() {
        $manager = new AccessDecisionManager();
        $this->addMockVoters($manager, [
            IVoter::VOTE_ABSTAIN,
            IVoter::VOTE_ABSTAIN,
            IVoter::VOTE_DENIED
        ]);

        $result = $manager->decide($this->getMockIdentity(), ['foo'], null);

        $this->assertFalse($result);
    }

    public function testDecideAffirmative_allAbstainsAndAllowIfAllAbstainIsTrue_returnsTrue() {
        $manager = new AccessDecisionManager(AccessDecisionManager::STRATEGY_AFFIRMATIVE, true);
        $this->addMockVoters($manager, [
            IVoter::VOTE_ABSTAIN,
            IVoter::VOTE_ABSTAIN,
            IVoter::VOTE_ABSTAIN
        ]);

        $result = $manager->decide($this->getMockIdentity(), ['foo'], null);

        $this->assertTrue($result);
    }

    public function testDecideAffirmative_allAbstainsAndAllowIfAllAbstainIsFalse_returnsFalse() {
        $manager = new AccessDecisionManager();
        $this->addMockVoters($manager, [
            IVoter::VOTE_ABSTAIN,
            IVoter::VOTE_ABSTAIN,
            IVoter::VOTE_ABSTAIN
        ]);

        $result = $manager->decide($this->getMockIdentity(), ['foo'], null);

        $this->assertFalse($result);
    }

    public function testDecideUnanimous_oneGrants_returnsTrue() {
        $manager = new AccessDecisionManager(AccessDecisionManager::STRATEGY_UNANIMOUS);
        $this->addMockVoters($manager, [
            IVoter::VOTE_GRANTED,
            IVoter::VOTE_ABSTAIN,
            IVoter::VOTE_ABSTAIN
        ]);

        $result = $manager->decide($this->getMockIdentity(), ['foo'], null);

        $this->assertTrue($result);
    }

    public function testDecideUnanimous_twoGrantsButOneDeny_returnsFalse() {
        $manager = new AccessDecisionManager(AccessDecisionManager::STRATEGY_UNANIMOUS);
        $this->addMockVoters($manager, [
            IVoter::VOTE_GRANTED,
            IVoter::VOTE_GRANTED,
            IVoter::VOTE_DENIED
        ]);

        $result = $manager->decide($this->getMockIdentity(), ['foo'], null);

        $this->assertFalse($result);
    }

    public function testDecideUnanimous_allAbstainAndAllowIfAllAbstainIsFalse_returnsFalse() {
        $manager = new AccessDecisionManager(AccessDecisionManager::STRATEGY_UNANIMOUS);
        $this->addMockVoters($manager, [
            IVoter::VOTE_ABSTAIN,
            IVoter::VOTE_ABSTAIN,
            IVoter::VOTE_ABSTAIN
        ]);

        $result = $manager->decide($this->getMockIdentity(), ['foo'], null);

        $this->assertFalse($result);
    }

    public function testDecideUnanimous_allAbstainAndAllowIfAllAbstainIsTrue_returnsTrue() {
        $manager = new AccessDecisionManager(AccessDecisionManager::STRATEGY_UNANIMOUS, true);
        $this->addMockVoters($manager, [
            IVoter::VOTE_ABSTAIN,
            IVoter::VOTE_ABSTAIN,
            IVoter::VOTE_ABSTAIN
        ]);

        $result = $manager->decide($this->getMockIdentity(), ['foo'], null);

        $this->assertTrue($result);
    }

    public function testDecideConsensus_oneGrantsRestAbstains_returnTrue() {
        $manager = new AccessDecisionManager(AccessDecisionManager::STRATEGY_CONSENSUS);
        $this->addMockVoters($manager, [
            IVoter::VOTE_GRANTED,
            IVoter::VOTE_ABSTAIN,
            IVoter::VOTE_ABSTAIN
        ]);

        $result = $manager->decide($this->getMockIdentity(), ['foo'], null);

        $this->assertTrue($result);
    }

    public function testDecideConsensus_moreGrantsThanDenies_returnTrue() {
        $manager = new AccessDecisionManager(AccessDecisionManager::STRATEGY_CONSENSUS);
        $this->addMockVoters($manager, [
            IVoter::VOTE_GRANTED,
            IVoter::VOTE_GRANTED,
            IVoter::VOTE_DENIED
        ]);

        $result = $manager->decide($this->getMockIdentity(), ['foo'], null);

        $this->assertTrue($result);
    }

    public function testDecideConsensus_moreDeniesThanGrants_returnFalse() {
        $manager = new AccessDecisionManager(AccessDecisionManager::STRATEGY_CONSENSUS);
        $this->addMockVoters($manager, [
            IVoter::VOTE_GRANTED,
            IVoter::VOTE_DENIED,
            IVoter::VOTE_DENIED
        ]);

        $result = $manager->decide($this->getMockIdentity(), ['foo'], null);

        $this->assertFalse($result);
    }

    public function testDecideConsensus_tieWhenAllowIfEqualGrantedDeniedIsTrue_returnsTrue() {
        $manager = new AccessDecisionManager(AccessDecisionManager::STRATEGY_CONSENSUS);
        $this->addMockVoters($manager, [
            IVoter::VOTE_GRANTED,
            IVoter::VOTE_GRANTED,
            IVoter::VOTE_DENIED,
            IVoter::VOTE_DENIED
        ]);

        $result = $manager->decide($this->getMockIdentity(), ['foo'], null);

        $this->assertTrue($result);
    }

    public function testDecideConsensus_tieWhenAllowIfEqualGrantedDeniedIsFalse_returnsFalse() {
        $manager = new AccessDecisionManager(AccessDecisionManager::STRATEGY_CONSENSUS, false, false);
        $this->addMockVoters($manager, [
            IVoter::VOTE_GRANTED,
            IVoter::VOTE_GRANTED,
            IVoter::VOTE_DENIED,
            IVoter::VOTE_DENIED
        ]);

        $result = $manager->decide($this->getMockIdentity(), ['foo'], null);

        $this->assertFalse($result);
    }
}
