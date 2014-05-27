<?php
/**
 * This file is part of Vegas package
 *
 * @author Slawomir Zytko <slawomir.zytko@gmail.com>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @homepage https://bitbucket.org/amsdard/vegas-phalcon
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Vegas\Security\Acl;

use \Phalcon\Acl\Role as PhalconRole;
use Phalcon\Acl;

/**
 *
 * @package Vegas\Security\Acl
 */
class Role extends PhalconRole
{
    const DEFAULT_ROLE_GUEST = "Guest";

    /**
     * List of role accesses
     *
     * @var array
     */
    protected $accessList = [];

    /**
     * Determines if role is built-in
     * Built-in roles cannot be removed
     *
     * @var bool
     */
    protected $isRemovable = true;

    /**
     * @var \MongoId|integer
     */
    protected $id;
    
    /**
     * @param $access
     */
    public function addAccess($access)
    {
        $resourceName = $access['resources_name'];
        if (!isset($this->accessList[$resourceName])) {
            $this->accessList[$resourceName] = [];
        }
        $this->accessList[$resourceName][] = $access['access_name'];
    }

    /**
     * @param $accessList
     */
    public function setAccessList($accessList)
    {
        $this->accessList = [];
        foreach ($accessList as $access) {
            $this->addAccess($access);
        }
    }

    /**
     * @return array
     */
    public function getAccessList()
    {
        return $this->accessList;
    }

    /**
     * @param $accessName
     * @return bool
     */
    private function findAccessByName($accessName)
    {
        $result = false;
        array_walk($this->accessList, function($item, $key) use ($accessName, &$result) {
            if ($item['name'] == $accessName) {
                $result = $item;
            }
        });

        return $result;
    }

    /**
     * @param $accessName
     * @return bool
     */
    public function hasAccess($accessName)
    {
        return (bool)$this->findAccessByName($accessName);
    }

    /**
     * @param $accessName
     * @return bool
     */
    public function isAccessAllowed($accessName)
    {
        $access = $this->findAccessByName($accessName);
        return $access['allowed'] == Acl::ALLOW;
    }
    
    /**
     * @param \MongoId|integer $id
     */
    public function setId($id)
    {
        $this->id = $id;
    }

    /**
     * @return \MongoId|integer
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @param $flag
     */
    public function setRemovable($flag)
    {
        $this->isRemovable = $flag;
    }

    /**
     * Determines if role is built-in
     * Built-in roles cannot be removed
     *
     * @return bool
     */
    public function isRemovable()
    {
        return $this->isRemovable;
    }
}
 