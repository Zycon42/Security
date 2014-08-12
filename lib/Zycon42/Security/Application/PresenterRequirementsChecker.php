<?php

namespace Zycon42\Security\Application;

use Nette;
use Nette\Application\Request;
use Nette\Reflection\ClassType;
use Nette\Reflection\Method;
use Symfony\Component\ExpressionLanguage\Expression;

class PresenterRequirementsChecker extends Nette\Object {

    /**
     * @var ExpressionEvaluator
     */
    private $expressionEvaluator;

    private $failedExpression;

    public function __construct(ExpressionEvaluator $expressionEvaluator) {
        $this->expressionEvaluator = $expressionEvaluator;
    }

    /**
     * @param ClassType|Method $element
     * @param Request $request
     * @return bool
     * @throws \InvalidArgumentException
     */
    public function checkRequirement($element, Request $request) {
        if ($element instanceof ClassType) {
            $expressions = $this->getClassExpressionsToEvaluate($element);
        } else if ($element instanceof Method) {
            $expressions = $this->getMethodExpressionsToEvaluate($element);
        } else
            throw new \InvalidArgumentException("Argument 'element' must be instanceof Nette\\Reflection\\ClassType or Nette\\Reflection\\Method");

        if (!empty($expressions)) {
            foreach ($expressions as $expression) {
                $result = $this->expressionEvaluator->evaluate($expression, $request);
                if (!$result) {
                    $this->failedExpression = $expression;
                    return false;
                }
            }
        }
        return true;
    }

    public function getFailedExpression() {
        return $this->failedExpression;
    }

    private function getClassExpressionsToEvaluate(ClassType $classType) {
        $expressions = [];
        $this->walkClassHierarchy($classType, $expressions);
        return $expressions;
    }

    private function walkClassHierarchy(ClassType $classType, &$expressions) {
        $parentClass = $classType->getParentClass();
        if ($parentClass)
            $this->walkClassHierarchy($parentClass, $expressions);

        $annotation = $classType->getAnnotation('Security');
        if ($annotation) {
            if (!is_string($annotation)) {
                throw new \InvalidArgumentException('Security annotation must be simple string with expression.');
            }

            $expressions[] = new Expression($annotation);
        }
    }

    private function getMethodExpressionsToEvaluate(Method $method) {
        $annotation = $method->getAnnotation('Security');
        if ($annotation) {
            if (!is_string($annotation)) {
                throw new \InvalidArgumentException('Security annotation must be simple string with expression.');
            }
            return [new Expression($annotation)];
        }
        return [];
    }
}
