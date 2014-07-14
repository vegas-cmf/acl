<?php
/**
 * This file is part of Vegas package
 *
 * @author Slawomir Zytko <slawomir.zytko@gmail.com>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @homepage http://vegas-cmf.github.io
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Vegas\Security\Acl;

use \Phalcon\Acl\Resource as PhalconResource;

/**
 *
 * @package Vegas\Security\Acl
 */
class Resource extends PhalconResource
{
    /**
     * Reserved name of 'catch-all' access/name for specific resource
     */
    const WILDCARD = '*';

    /**
     * @var array
     */
    protected $accesses = array();

    /**
     * Name of scope - used for controllers splitted on Frontend and Backend
     *
     * @var string
     */
    protected $scope = '';

    /**
     * @param $accesses
     */
    public function setAccesses($accesses)
    {
        foreach ($accesses as $access) {
            $this->accesses[$access['access_name']] = $access['access_description'];
        }
    }

    /**
     * @param $accessName
     * @return bool
     */
    public function hasAccess($accessName)
    {
        return in_array($accessName, $this->accesses);
    }

    /**
     * @return mixed
     */
    public function getAccesses()
    {
        return $this->accesses;
    }

    /**
     * @param $scope
     */
    public function setScope($scope)
    {
        $this->scope = $scope;
    }

    /**
     * @return string
     */
    public function getScope()
    {
        return $this->scope;
    }
}
 