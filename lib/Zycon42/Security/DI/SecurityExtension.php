<?php
namespace Zycon42\Security\DI;

use Zycon42\Security\Authorization\AccessDecisionManager;
use Nette\DI\CompilerExtension;

class SecurityExtension extends CompilerExtension {

    const VOTER_ROLE = 'role';
    const VOTER_EXPRESSION = 'expression';
    const VOTER_AUTHENTICATED = 'authenticated';

    const TAG_VOTER = 'mevris.voter';

    public $defaults = [
        'decisionManager' => [
            'strategy' => AccessDecisionManager::STRATEGY_AFFIRMATIVE,
            'allowIfAllAbstain' => FALSE,
            'allowIfEqualGrantedDenied' => TRUE
        ],
        'voters' => [
            self::VOTER_ROLE => TRUE,
            self::VOTER_EXPRESSION => TRUE,
            self::VOTER_AUTHENTICATED => TRUE
        ]
    ];

    public function loadConfiguration() {
        $builder = $this->getContainerBuilder();
        $config = $this->getConfig($this->defaults);

        $builder->addDefinition($this->prefix('expressionLanguage'))
            ->setClass('Zycon42\Security\Authorization\ExpressionLanguage')
            ->setInject(FALSE);

        $builder->addDefinition($this->prefix('trustResolver'))
            ->setImplementType('Zycon42\Security\Authentication\IAuthenticationTrustResolver')
            ->setClass('Zycon42\Security\Authentication\AuthenticationTrustResolver')
            ->setInject(FALSE);

        $builder->addDefinition($this->prefix('decisionManager'))
            ->setImplementType('Zycon42\Security\Authorization\IAccessDecisionManager')
            ->setClass('Zycon42\Security\Authorization\AccessDecisionManager', $config['decisionManager'])
            ->setInject(FALSE);

        $builder->addDefinition($this->prefix('securityContext'))
            ->setImplementType('Zycon42\Security\ISecurityContext')
            ->setClass('Zycon42\Security\SecurityContext')
            ->addSetup('$service->setIdentity(?->identity)', ['@user'])
            ->setInject(FALSE);

        $builder->addDefinition($this->prefix('expressionEvaluator'))
            ->setClass('Zycon42\Security\Application\ExpressionEvaluator')
            ->setInject(FALSE);

        $builder->addDefinition($this->prefix('presenterRequirementsChecker'))
            ->setClass('Zycon42\Security\Application\PresenterRequirementsChecker')
            ->setInject(FALSE);

        if ($config['voters'][self::VOTER_ROLE]) {
            $builder->addDefinition($this->prefix('voters.' . self::VOTER_ROLE))
                ->setClass('Zycon42\Security\Authorization\Voters\RoleVoter')
                ->addTag(self::TAG_VOTER)
                ->setInject(FALSE);
        }

        if ($config['voters'][self::VOTER_EXPRESSION]) {
            $builder->addDefinition($this->prefix('voters.' . self::VOTER_EXPRESSION))
                ->setClass('Zycon42\Security\Authorization\Voters\ExpressionVoter')
                ->addTag(self::TAG_VOTER)
                ->setInject(FALSE);
        }

        if ($config['voters'][self::VOTER_AUTHENTICATED]) {
            $builder->addDefinition($this->prefix('voters.' . self::VOTER_AUTHENTICATED))
                ->setClass('Zycon42\Security\Authorization\Voters\AuthenticatedVoter')
                ->addTag(self::TAG_VOTER)
                ->setInject(FALSE);
        }
    }

    public function beforeCompile() {
        $builder = $this->getContainerBuilder();

        $decisionManger = $builder->getDefinition($this->prefix('decisionManager'));
        foreach (array_keys($builder->findByTag(self::TAG_VOTER)) as $serviceName) {
            $decisionManger->addSetup('addVoter', ['@'. $serviceName]);
        }
    }
}
