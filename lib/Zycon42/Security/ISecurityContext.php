<?php

namespace Zycon42\Security;

interface ISecurityContext {

    /**
     * Checks if attributes are granted to current identity and optionally supplied object.
     * @param $attributes
     * @param null $object
     * @return bool
     */
    public function isGranted($attributes, $object = null);
}
