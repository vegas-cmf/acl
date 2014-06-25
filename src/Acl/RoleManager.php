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

use Vegas\Security\Acl\ManagerAbstract;
use Vegas\Security\Acl\Role;
use Vegas\Security\Acl\Exception\InvalidRoleNameException;

/**
 *
 * @package Vegas\Security\Acl
 */
class RoleManager extends ManagerAbstract
{

    /**
     * @param string $name
     * @return \Phalcon\Acl\RoleInterface[]
     */
    public function getRole($name)
    {
        $role = $this->adapter->getRole($name);

        return $role;
    }

    /**
     * @return \Phalcon\Acl\RoleInterface[]
     */
    public function getRoles()
    {
        $roles = $this->adapter->getRoles();

        return $roles;
    }

    /**
     * @param $name
     * @param $description
     * @param bool $isRemovable
     * @throws Exception\InvalidRoleNameException
     * @return bool
     */
    public function add($name, $description, $isRemovable = true)
    {
        if (!$name) {
            throw new InvalidRoleNameException();
        }
        $role = new Role($name, $description);
        $role->setRemovable($isRemovable);
        
        $result = $this->adapter->addRole($role);

        return $result;
    }

    /**
     * @param $name
     * @return bool
     */
    public function isRole($name)
    {
        $result = $this->adapter->isRole($name);

        return $result;
    }

    /**
     * @param $name
     * @return mixed
     */
    public function dropRole($name)
    {
        $result = $this->adapter->dropRole($name);

        return $result;
    }
}